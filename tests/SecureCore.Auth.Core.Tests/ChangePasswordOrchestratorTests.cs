using Microsoft.Extensions.Caching.Distributed;
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
/// Tests de ChangePasswordOrchestrator — creación/cambio de contraseña con re-emisión de tokens (S3, A-22).
/// </summary>
public class ChangePasswordOrchestratorTests
{
    private const string UserId = "u1";
    private const string OldStamp = "old-stamp";
    private const string LockedMessage = "Demasiados intentos. Intente más tarde.";

    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly ISessionStore _sessionStore = Substitute.For<ISessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IMfaVerifiedSessionStore _mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();
    private readonly SecurityStampValidator _stampValidator;

    public ChangePasswordOrchestratorTests()
    {
        var options = Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) });
        _stampValidator = new SecurityStampValidator(
            _userStore,
            Substitute.For<IDistributedCache>(),
            options,
            NullLogger<SecurityStampValidator>.Instance);

        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("jwt", "refresh-new", DateTimeOffset.UtcNow.AddMinutes(15)));
        _tokenService.HashRefreshToken(Arg.Any<string>())
            .Returns("hashed-refresh");
        _passwordHasher.HashPasswordAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("new-hash");
    }

    private ChangePasswordOrchestrator CreateOrchestrator(
        IAccountProtectionService? protection = null,
        bool protectionEnabled = false,
        IMfaVerifiedSessionStore? verifiedStore = null)
    {
        return new ChangePasswordOrchestrator(
            _userStore,
            _passwordHasher,
            _tokenService,
            _sessionStore,
            _stampValidator,
            _eventDispatcher,
            Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) }),
            NullLogger<ChangePasswordOrchestrator>.Instance,
            verifiedStore ?? _mfaVerified,
            protection,
            protection is null ? null : Options.Create(new AccountProtectionOptions { Enabled = protectionEnabled }));
    }

    private static UserIdentity CreateTestUser(string? passwordHash = "hashed-password")
    {
        return new UserIdentity
        {
            Id = UserId,
            Email = "test@example.com",
            PasswordHash = passwordHash,
            SecurityStamp = OldStamp
        };
    }

    [Fact]
    public async Task CreateAsync_VerifiedWindowOpen_UpdatesPasswordRotatesStampAndReissuesTokens()
    {
        // Arrange: cuenta sin contraseña (flujo passwordless) y ventana verify-action ABIERTA.
        var user = CreateTestUser(passwordHash: null);
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _mfaVerified.IsVerifiedAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await CreateOrchestrator().CreateAsync(UserId, "NuevaClaveSegura1");

        // Assert: contraseña creada y stamp rotado (todas las sesiones previas mueren).
        Assert.True(result.Success);
        Assert.NotNull(result.Tokens);
        await _userStore.Received(1).UpdatePasswordHashAsync(UserId, "new-hash", Arg.Any<CancellationToken>());
        await _userStore.Received(1).UpdateSecurityStampAsync(UserId, Arg.Is<string>(s => s != OldStamp && !string.IsNullOrEmpty(s)), Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).RevokeAllByUserAsync(UserId, Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).CreateAsync(Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>());

        // S3: el usuario acaba de demostrar verify-action → ventana mfa_verified renovada.
        await _mfaVerified.Received(1).SetVerifiedAsync(UserId, "change_password", Arg.Any<CancellationToken>());

        // Auditoría: SecurityStampChanged por rotación.
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.SecurityStampChanged),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_WindowClosed_ReturnsVerifyActionRequired()
    {
        // Assert (M1, auditoría): sin ventana verify-action abierta, fail-closed. El código ya
        // se consumió en VerifyActionAsync; aquí solo se consulta la ventana, no se relee OTP.
        var user = CreateTestUser(passwordHash: null);
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _mfaVerified.IsVerifiedAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await CreateOrchestrator().CreateAsync(UserId, "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.VerifyActionRequired, result.ErrorCode);
        await _userStore.DidNotReceiveWithAnyArgs().UpdatePasswordHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.PasswordChangeFailed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_NoVerifiedStore_ReturnsVerifyActionRequired()
    {
        // Assert (M1): si el host no registró IMfaVerifiedSessionStore, fail-closed.
        var user = CreateTestUser(passwordHash: null);
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator(verifiedStore: null).CreateAsync(UserId, "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.VerifyActionRequired, result.ErrorCode);
    }

    [Fact]
    public async Task CreateAsync_AlreadyHasPassword_ReturnsPasswordAlreadyExists()
    {
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator().CreateAsync(UserId, "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.PasswordAlreadyExists, result.ErrorCode);
        await _userStore.DidNotReceiveWithAnyArgs().UpdatePasswordHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_WeakPassword_RejectedByPolicy()
    {
        // Arrange: política NIST — mínimo 8 caracteres.
        var user = CreateTestUser(passwordHash: null);
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator().CreateAsync(UserId, "corta1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.InvalidPasswordPolicy, result.ErrorCode);
        await _userStore.DidNotReceiveWithAnyArgs().UpdatePasswordHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChangeAsync_ValidCurrentPassword_ChangesAndReissuesTokens()
    {
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _passwordHasher.VerifyPasswordAsync("hashed-password", "ClaveActual1", Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.Success);

        var result = await CreateOrchestrator().ChangeAsync(UserId, "ClaveActual1", "NuevaClaveSegura1");

        Assert.True(result.Success);
        Assert.Equal("jwt", result.Tokens!.AccessToken);
        await _userStore.Received(1).UpdatePasswordHashAsync(UserId, "new-hash", Arg.Any<CancellationToken>());
        await _userStore.Received(1).UpdateSecurityStampAsync(UserId, Arg.Is<string>(s => s != OldStamp), Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).RevokeAllByUserAsync(UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChangeAsync_WrongCurrentPassword_ReturnsInvalidCurrentPassword()
    {
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _passwordHasher.VerifyPasswordAsync("hashed-password", "ClaveIncorrecta1", Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.Failed);

        var result = await CreateOrchestrator().ChangeAsync(UserId, "ClaveIncorrecta1", "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.InvalidCurrentPassword, result.ErrorCode);
        await _userStore.DidNotReceiveWithAnyArgs().UpdatePasswordHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChangeAsync_OversizedCurrentPassword_ReturnsInvalidCurrentPassword()
    {
        // Assert (H3, auditoría): la contraseña actual se acota antes de invocar Argon2.
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator().ChangeAsync(UserId, new string('x', 2048), "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.InvalidCurrentPassword, result.ErrorCode);
        await _passwordHasher.DidNotReceiveWithAnyArgs().VerifyPasswordAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChangeAsync_WithProtection_WrongCurrentPassword_RecordsFailure()
    {
        // Arrange (M4, auditoría): cada intento fallido consume el presupuesto PasswordChange.
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        var orchestrator = CreateOrchestrator(protection, protectionEnabled: true);
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _passwordHasher.VerifyPasswordAsync("hashed-password", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.Failed);

        for (var i = 0; i < 5; i++)
        {
            await orchestrator.ChangeAsync(UserId, "ClaveIncorrecta1", "NuevaClaveSegura1");
        }

        var sixth = await orchestrator.ChangeAsync(UserId, "ClaveIncorrecta1", "NuevaClaveSegura1");

        // Assert: el 6º intento queda bloqueado y NO se filtra la causa (genérico).
        Assert.False(sixth.Success);
        Assert.Equal(LockedMessage, sixth.ErrorMessage);
        var check = await protection.CheckAsync(AccountProtectionScope.PasswordChange, UserId);
        Assert.False(check.Allowed);
        Assert.Equal(1, check.EscalationLevel);
    }

    [Fact]
    public async Task ChangeAsync_WithProtection_Success_ResetsBudget()
    {
        // Arrange (M4): un cambio correcto renueva el presupuesto PasswordChange (paridad S1).
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        var orchestrator = CreateOrchestrator(protection, protectionEnabled: true);
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _passwordHasher.VerifyPasswordAsync("hashed-password", "ClaveActual1", Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.Success);

        var result = await orchestrator.ChangeAsync(UserId, "ClaveActual1", "NuevaClaveSegura1");

        Assert.True(result.Success);
        var check = await protection.CheckAsync(AccountProtectionScope.PasswordChange, UserId);
        Assert.True(check.Allowed);
        Assert.Equal(5, check.RemainingAttempts);
    }

    [Fact]
    public async Task ChangeAsync_NoPasswordExists_ReturnsNoPasswordCreated()
    {
        var user = CreateTestUser(passwordHash: null);
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator().ChangeAsync(UserId, "Cualquiera1", "NuevaClaveSegura1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.NoPasswordCreated, result.ErrorCode);
    }

    [Fact]
    public async Task ChangeAsync_WeakPassword_RejectedByPolicy()
    {
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);

        var result = await CreateOrchestrator().ChangeAsync(UserId, "ClaveActual1", "corta1");

        Assert.False(result.Success);
        Assert.Equal(ChangePasswordError.InvalidPasswordPolicy, result.ErrorCode);
        await _userStore.DidNotReceiveWithAnyArgs().UpdatePasswordHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ChangeAsync_SuccessRehashNeeded_UpdatesHash()
    {
        // DIDÁCTICA (consistencia): SuccessRehashNeeded también procede; el nuevo hash
        // re-hashea con los parámetros vigentes (mantenimiento continuo del resguardo).
        var user = CreateTestUser();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(user);
        _passwordHasher.VerifyPasswordAsync("hashed-password", "ClaveActual1", Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.SuccessRehashNeeded);

        var result = await CreateOrchestrator().ChangeAsync(UserId, "ClaveActual1", "NuevaClaveSegura1");

        Assert.True(result.Success);
        await _userStore.Received(1).UpdatePasswordHashAsync(UserId, "new-hash", Arg.Any<CancellationToken>());
    }
}
