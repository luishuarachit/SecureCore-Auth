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
/// Tests para IdentityOrchestrator — flujo completo de autenticación con contraseña.
/// </summary>
public class IdentityOrchestratorTests
{
    private readonly IdentityOrchestrator _orchestrator;
    private readonly IUserStore _userStore;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ITokenService _tokenService;
    private readonly ISessionStore _sessionStore;
    private readonly IAuthEventDispatcher _eventDispatcher;
    private readonly LockoutManager _lockoutManager;
    private readonly IMfaSessionStore _mfaSessionStore;
    private readonly IMfaService _mfaService;

    public IdentityOrchestratorTests()
    {
        _userStore = Substitute.For<IUserStore>();
        _passwordHasher = Substitute.For<IPasswordHasher>();
        _tokenService = Substitute.For<ITokenService>();
        _sessionStore = Substitute.For<ISessionStore>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        _mfaSessionStore = Substitute.For<IMfaSessionStore>();
        _mfaService = Substitute.For<IMfaService>();

        var authOptions = Options.Create(new SecureAuthOptions
        {
            MaxFailedAttempts = 5,
            RefreshTokenLifetime = TimeSpan.FromDays(7)
        });

        var mfaOptions = Options.Create(new MfaOptions
        {
            Enabled = true,
            AllowedMethods = new List<string> { "totp", "email" }
        });

        _mfaSessionStore.CreateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<int>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult("mfa-session-token"));

        _lockoutManager = new LockoutManager(
            _userStore, authOptions, NullLogger<LockoutManager>.Instance);

        _orchestrator = new IdentityOrchestrator(
            _userStore,
            _passwordHasher,
            _tokenService,
            _sessionStore,
            _lockoutManager,
            _eventDispatcher,
            authOptions,
            mfaOptions,
            _mfaSessionStore,
            _mfaService,
            NullLogger<IdentityOrchestrator>.Instance);
    }

    private UserIdentity CreateTestUser(
        string id = "u1",
        string email = "test@example.com",
        bool twoFactor = false,
        DateTimeOffset? lockoutEnd = null)
    {
        return new UserIdentity
        {
            Id = id,
            Email = email,
            PasswordHash = "hashed-password",
            SecurityStamp = Guid.NewGuid().ToString(),
            TwoFactorEnabled = twoFactor,
            LockoutEnd = lockoutEnd
        };
    }

    [Fact]
    public async Task SignInWithPasswordAsync_UserNotFound_CallsVerifyDummyPassword()
    {
        // Arrange
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(null));
        var password = "some_password";

        // Act
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("noone@example.com", password);

        // Assert — debe llamar a la verificación ficticia para evitar timing attacks
        Assert.False(result.Succeeded);
        Assert.Null(tokens);
        _passwordHasher.Received(1).VerifyDummyPassword(password);
    }

    [Fact]
    public async Task SignInWithPasswordAsync_AccountLocked_ReturnsLockedOut()
    {
        // Arrange
        var user = CreateTestUser(lockoutEnd: DateTimeOffset.UtcNow.AddMinutes(10));
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));

        // Act
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "pass");

        // Assert
        Assert.True(result.IsLockedOut);
        Assert.Null(tokens);
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.AccountLockedOut),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_WrongPassword_ReturnsFailedAndIncrementsCounter()
    {
        // Arrange
        var user = CreateTestUser();
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Failed);
        _userStore.IncrementFailedAccessCountAsync(Arg.Any<string>())
            .Returns(Task.FromResult(1));

        // Act
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "wrong");

        // Assert
        Assert.False(result.Succeeded);
        Assert.Null(tokens);
        await _userStore.Received(1).IncrementFailedAccessCountAsync("u1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginFailed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_TwoFactorEnabled_ReturnsTwoFactorRequired()
    {
        // Arrange
        var user = CreateTestUser(twoFactor: true) with { MfaEnrollmentStatus = MfaEnrollmentStatus.Enrolled };
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);

        // Act
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        // Assert
        Assert.True(result.RequiresTwoFactor);
        Assert.Null(tokens);
    }

    [Fact]
    public async Task SignInWithPasswordAsync_ValidCredentials_ReturnsSuccessWithTokens()
    {
        // Arrange
        var user = CreateTestUser();
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>())
            .Returns(Task.FromResult(new TokenResponse("jwt", "refresh", DateTimeOffset.UtcNow.AddMinutes(15))));
        _tokenService.HashRefreshToken(Arg.Any<string>())
            .Returns("hashed-refresh");

        // Act
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        // Assert
        Assert.True(result.Succeeded);
        Assert.NotNull(tokens);
        Assert.Equal("jwt", tokens.AccessToken);

        // Verificar que se reseteó el contador y se almacenó el refresh token
        await _userStore.Received(1).ResetFailedAccessCountAsync("u1", Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).CreateAsync(
            Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginSuccess),
            Arg.Any<CancellationToken>());
    }

    // ─────────────────────────────────────────────
    //  Passwordless (F6, A-25)
    // ─────────────────────────────────────────────

    [Fact]
    public async Task SignInWithPasswordAsync_PasswordNull_ReturnsPasswordlessRequiresCredential_WithoutStoreLookup()
    {
        // DIDÁCTICA (S6, A-25): password null es una señal de REQUEST uniforme: se devuelve ANTES
        // de consultar el store, por lo que NO es un oráculo de enumeración (mismo resultado para
        // emails existentes o no).
        var (result, tokens, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", null);

        Assert.True(result.RequiresPasswordlessCredential);
        Assert.Equal(nameof(SignInErrorCode.PasswordlessRequiresCredential), result.ErrorCode);
        Assert.Null(tokens);
        await _userStore.DidNotReceiveWithAnyArgs().FindByEmailAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_PasswordNull_DoesNotRunDummyVerify()
    {
        await _orchestrator.SignInWithPasswordAsync("test@example.com", null);

        _passwordHasher.DidNotReceiveWithAnyArgs().VerifyDummyPassword(Arg.Any<string>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_EmitAmrTrue_EmitsAmrPwdClaim()
    {
        var user = CreateTestUser();
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>())
            .Returns(Task.FromResult(new TokenResponse("jwt", "refresh", DateTimeOffset.UtcNow.AddMinutes(15))));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hashed-refresh");

        var orchestrator = CreateOrchestrator(new SecureAuthOptions { EmitAmr = true });

        var (result, _, _) = await orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        Assert.True(result.Succeeded);
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.Claims != null && u.Claims.GetValueOrDefault("amr") == "pwd"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_EmitAmrFalse_DoesNotMutateClaims()
    {
        var user = CreateTestUser() with { Claims = new Dictionary<string, string> { ["custom"] = "x" } };
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>())
            .Returns(Task.FromResult(new TokenResponse("jwt", "refresh", DateTimeOffset.UtcNow.AddMinutes(15))));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hashed-refresh");

        var (result, _, _) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        Assert.True(result.Succeeded);
        // DIDÁCTICA (D6-05): sin EmitAmr el token no cambia (no-breaking).
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.Claims != null &&
                !u.Claims.ContainsKey("amr") &&
                u.Claims.GetValueOrDefault("custom") == "x"),
            Arg.Any<CancellationToken>());
    }

    private IdentityOrchestrator CreateOrchestrator(SecureAuthOptions options)
    {
        var authOptions = Options.Create(options);
        var mfaOptions = Options.Create(new MfaOptions { Enabled = true, AllowedMethods = new List<string> { "totp", "email" } });
        var lockoutManager = new LockoutManager(_userStore, authOptions, NullLogger<LockoutManager>.Instance);

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
            NullLogger<IdentityOrchestrator>.Instance);
    }
}

/// <summary>
/// Tests de S3 en IdentityOrchestrator: CompleteMfaLoginAsync marca la ventana mfa_verified.
/// </summary>
public class IdentityOrchestratorMfaVerifiedTests
{
    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly ISessionStore _sessionStore = Substitute.For<ISessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IMfaSessionStore _mfaSessionStore = Substitute.For<IMfaSessionStore>();
    private readonly IMfaService _mfaService = Substitute.For<IMfaService>();
    private readonly IMfaVerifiedSessionStore _mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();

    private IdentityOrchestrator CreateOrchestrator()
    {
        var authOptions = Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) });
        var mfaOptions = Options.Create(new MfaOptions { Enabled = true, AllowedMethods = new List<string> { "totp", "email" } });
        var lockoutManager = new LockoutManager(_userStore, authOptions, NullLogger<LockoutManager>.Instance);

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
            accountProtectionService: null,
            accountProtectionOptions: null,
            mfaVerifiedSessionStore: _mfaVerified);
    }

    private UserIdentity CreateMfaUser() => new()
    {
        Id = "u1",
        Email = "test@example.com",
        PasswordHash = "hashed-password",
        SecurityStamp = Guid.NewGuid().ToString(),
        TwoFactorEnabled = true,
        MfaEnrollmentStatus = MfaEnrollmentStatus.Enrolled,
        PreferredMfaMethod = "totp"
    };

    [Fact]
    public async Task CompleteMfaLoginAsync_Success_MarksMfaVerifiedWindow()
    {
        // Arrange
        var orchestrator = CreateOrchestrator();
        _mfaSessionStore.ValidateMfaSessionTokenAsync("sess", Arg.Any<CancellationToken>())
            .Returns("u1");
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(CreateMfaUser());
        _mfaService.VerifyAsync("u1", "123456", Arg.Any<CancellationToken>())
            .Returns(new MfaVerificationResult(true, null, MfaMethod.Totp));
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("jwt", "refresh", DateTimeOffset.UtcNow.AddMinutes(15)));
        _tokenService.HashRefreshToken(Arg.Any<string>())
            .Returns("hash");

        // Act
        var (result, _) = await orchestrator.CompleteMfaLoginAsync("sess", "123456");

        // Assert
        Assert.Equal(SignInResult.Success, result);
        await _mfaVerified.Received(1).SetVerifiedAsync("u1", "totp", Arg.Any<CancellationToken>());

        // El par de tokens se emite con claims de método MFA (comportamiento previo intacto).
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.Claims!.ContainsKey("amr") && u.Claims["amr"] == "mfa" &&
                u.Claims.ContainsKey("mfa_method") && u.Claims["mfa_method"] == "totp"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteMfaLoginAsync_FailedMfa_DoesNotMarkVerified()
    {
        // Arrange
        var orchestrator = CreateOrchestrator();
        _mfaSessionStore.ValidateMfaSessionTokenAsync("sess", Arg.Any<CancellationToken>())
            .Returns("u1");
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(CreateMfaUser());
        _mfaService.VerifyAsync("u1", "000000", Arg.Any<CancellationToken>())
            .Returns(new MfaVerificationResult(false, "Código inválido", null));

        // Act
        var (result, _) = await orchestrator.CompleteMfaLoginAsync("sess", "000000");

        // Assert: sin verificación, sin ventana.
        Assert.Equal(SignInResult.Failed, result);
        await _mfaVerified.DidNotReceiveWithAnyArgs().SetVerifiedAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
