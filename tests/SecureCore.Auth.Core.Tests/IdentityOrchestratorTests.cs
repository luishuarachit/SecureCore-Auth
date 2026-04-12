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

    public IdentityOrchestratorTests()
    {
        _userStore = Substitute.For<IUserStore>();
        _passwordHasher = Substitute.For<IPasswordHasher>();
        _tokenService = Substitute.For<ITokenService>();
        _sessionStore = Substitute.For<ISessionStore>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

        var authOptions = Options.Create(new SecureAuthOptions
        {
            MaxFailedAttempts = 5,
            RefreshTokenLifetime = TimeSpan.FromDays(7)
        });

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
        var (result, tokens) = await _orchestrator.SignInWithPasswordAsync("noone@example.com", password);

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
        var (result, tokens) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "pass");

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
        var (result, tokens) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "wrong");

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
        var user = CreateTestUser(twoFactor: true);
        _userStore.FindByEmailAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);

        // Act
        var (result, tokens) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

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
        var (result, tokens) = await _orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

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
}
