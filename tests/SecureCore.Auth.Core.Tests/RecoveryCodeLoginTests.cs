using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests de <c>IdentityOrchestrator.CompleteMfaLoginWithRecoveryCodeAsync</c> (A1, auditoría F5):
/// cierra el flujo A-20 — redimir el recovery code, completar el login y (por política del host)
/// rotar el SecurityStamp revocando las sesiones previas.
/// </summary>
/// <remarks>
/// DIDÁCTICA: <c>CompleteMfaLoginAsync</c> exige un <c>mfaCode</c> que pase
/// <c>mfaService.VerifyAsync</c> (TOTP/email); un recovery code NO pasa esa verificación. Este
/// flujo consume el recovery code (single-use vía S2) y emite los tokens con la marca
/// <c>mfa_method=recovery</c>, sin dejar al host la responsabilidad de reimplementar la emisión.
/// </remarks>
public class RecoveryCodeLoginTests
{
    private const string UserId = "u1";
    private const string MfaToken = "mfa-token";

    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly ISessionStore _sessionStore = Substitute.For<ISessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IMfaSessionStore _mfaSessionStore = Substitute.For<IMfaSessionStore>();
    private readonly IMfaService _mfaService = Substitute.For<IMfaService>();
    private readonly IRecoveryCodeStore _recoveryStore = Substitute.For<IRecoveryCodeStore>();
    private readonly ITotpService _totpService = Substitute.For<ITotpService>();
    private readonly IAccountProtectionService _protection = Substitute.For<IAccountProtectionService>();

    public RecoveryCodeLoginTests()
    {
        _recoveryStore.RedeemAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(false));
        _recoveryStore.GetStatusAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Invalid));
        _eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1))));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");
        _mfaSessionStore.ValidateMfaSessionTokenAsync(MfaToken, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>(UserId));
    }

    private IdentityOrchestrator CreateOrchestrator(bool withRecovery = true, bool protectionEnabled = false)
    {
        var authOptions = Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) });
        var mfaOptions = Options.Create(new MfaOptions { Enabled = true, EnableRecoveryCodes = true });
        var lockoutManager = new LockoutManager(_userStore, authOptions, NullLogger<LockoutManager>.Instance);

        RecoveryCodeOrchestrator? recovery = null;
        if (withRecovery)
        {
            recovery = new RecoveryCodeOrchestrator(
                _recoveryStore,
                _totpService,
                _eventDispatcher,
                new InMemoryOperationLock(TimeSpan.FromSeconds(5)),
                mfaOptions,
                NullLogger<RecoveryCodeOrchestrator>.Instance,
                protectionEnabled ? _protection : null,
                protectionEnabled ? Options.Create(new AccountProtectionOptions { Enabled = true }) : null);
        }

        return new IdentityOrchestrator(
            _userStore,
            _passwordHasher,
            _tokenService,
            _sessionStore,
            lockoutManager,
            _eventDispatcher,
            authOptions,
            mfaOptions,
            _mfaSessionStore,
            _mfaService,
            NullLogger<IdentityOrchestrator>.Instance,
            recoveryCodeOrchestrator: recovery);
    }

    private UserIdentity CreateTestUser() => new()
    {
        Id = UserId,
        Email = "test@example.com",
        PasswordHash = "hashed-password",
        SecurityStamp = "stamp-1"
    };

    [Fact]
    public async Task WithoutOrchestrator_ReturnsFailed()
    {
        var orchestrator = CreateOrchestrator(withRecovery: false);

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "code", rotateSecurityStamp: true);

        Assert.False(result.Succeeded);
        Assert.Null(tokens);
        await _recoveryStore.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvalidMfaSessionToken_ReturnsFailed_WithoutRedeeming()
    {
        _mfaSessionStore.ValidateMfaSessionTokenAsync(MfaToken, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>(null));
        var orchestrator = CreateOrchestrator();

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "code", rotateSecurityStamp: false);

        Assert.False(result.Succeeded);
        Assert.Null(tokens);
        await _recoveryStore.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvalidRecoveryCode_ReturnsFailed()
    {
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(CreateTestUser()));
        var orchestrator = CreateOrchestrator();

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "bad", rotateSecurityStamp: false);

        Assert.False(result.Succeeded);
        Assert.Null(tokens);
        await _mfaSessionStore.DidNotReceive().ConsumeMfaSessionTokenAsync(MfaToken, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LockedOutByProtection_ReturnsFailed_Generic()
    {
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(CreateTestUser()));
        _protection.CheckAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(false, 0, DateTimeOffset.UtcNow.AddMinutes(10), 1)));
        var orchestrator = CreateOrchestrator(protectionEnabled: true);

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "code", rotateSecurityStamp: false);

        // DIDÁCTICA: el bloqueo S1 se traduce a fallo genérico de login (no se revela la causa).
        Assert.False(result.Succeeded);
        Assert.Null(tokens);
    }

    [Fact]
    public async Task Success_IssuesTokens_WithRecoveryFactor_WithoutRotatingStamp()
    {
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(CreateTestUser()));
        _recoveryStore.RedeemAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(true));
        var orchestrator = CreateOrchestrator();

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "code", rotateSecurityStamp: false);

        Assert.True(result.Succeeded);
        Assert.NotNull(tokens);

        await _mfaSessionStore.Received(1).ConsumeMfaSessionTokenAsync(MfaToken, Arg.Any<CancellationToken>());
        await _userStore.Received(1).ResetFailedAccessCountAsync(UserId, Arg.Any<CancellationToken>());

        // Sin rotación: el stamp y las sesiones previas quedan intactos.
        await _userStore.DidNotReceiveWithAnyArgs().UpdateSecurityStampAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _sessionStore.DidNotReceiveWithAnyArgs().RevokeAllByUserAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());

        // El factor verificado se refleja en los claims del token.
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.Claims != null &&
                u.Claims.GetValueOrDefault("amr") == "mfa" &&
                u.Claims.GetValueOrDefault("mfa_method") == "recovery"),
            Arg.Any<CancellationToken>());

        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e =>
                e.EventType == AuthEventType.LoginSuccess &&
                e.Metadata != null && e.Metadata.GetValueOrDefault("factor") == "recovery"),
            Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceive().DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.SecurityStampChanged),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Success_WithRotateStamp_RotatesStamp_AndRevokesAllSessions()
    {
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(CreateTestUser()));
        _recoveryStore.RedeemAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(true));
        var orchestrator = CreateOrchestrator();

        var (result, tokens) = await orchestrator.CompleteMfaLoginWithRecoveryCodeAsync(
            MfaToken, "code", rotateSecurityStamp: true);

        Assert.True(result.Succeeded);
        Assert.NotNull(tokens);

        await _userStore.Received(1).UpdateSecurityStampAsync(
            UserId, Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).RevokeAllByUserAsync(UserId, Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
                    Arg.Is<AuthEvent>(e =>
                        e.EventType == AuthEventType.SecurityStampChanged &&
                        e.Metadata != null && e.Metadata.GetValueOrDefault("reason") == "recovery_code_used"),
                    Arg.Any<CancellationToken>());

        // Los tokens se emiten con el SecurityStamp NUEVO (si no, el cliente quedaría sin sesión:
        // el par emitido debe llevar el stamp ya persistido, no el anterior).
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.SecurityStamp != null && u.SecurityStamp != "stamp-1"),
            Arg.Any<CancellationToken>());
    }

    private static string ComputeHash(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
