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
/// Tests para SessionOrchestrator — rotación de tokens, grace period y revocación.
/// </summary>
public class SessionOrchestratorTests
{
    private readonly SessionOrchestrator _orchestrator;
    private readonly ISessionStore _sessionStore;
    private readonly IUserStore _userStore;
    private readonly ITokenService _tokenService;
    private readonly IAuthEventDispatcher _eventDispatcher;
    private readonly SecurityStampValidator _stampValidator;

    public SessionOrchestratorTests()
    {
        _sessionStore = Substitute.For<ISessionStore>();
        _userStore = Substitute.For<IUserStore>();
        _tokenService = Substitute.For<ITokenService>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

        var authOptions = Options.Create(new SecureAuthOptions
        {
            GracePeriodSeconds = 30,
            RefreshTokenLifetime = TimeSpan.FromDays(7),
            AccessTokenLifetime = TimeSpan.FromMinutes(15)
        });

        var cache = Substitute.For<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
        _stampValidator = new SecurityStampValidator(
            _userStore, cache, authOptions, NullLogger<SecurityStampValidator>.Instance);

        _orchestrator = new SessionOrchestrator(
            _sessionStore,
            _userStore,
            _tokenService,
            _stampValidator,
            _eventDispatcher,
            authOptions,
            NullLogger<SessionOrchestrator>.Instance);
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_TokenNotFound_ReturnsNull()
    {
        // Arrange
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");
        _sessionStore.FindByTokenHashAsync(Arg.Any<string>())
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(null));

        // Act
        var result = await _orchestrator.RotateRefreshTokenAsync("invalid-token");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_RevokedToken_RevokesEntireFamilyAndReturnsNull()
    {
        // Arrange
        var entry = new RefreshTokenEntry
        {
            TokenHash = "hash",
            FamilyId = "family-1",
            UserId = "u1",
            IsRevoked = true,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");
        _sessionStore.FindByTokenHashAsync("hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));

        // Act
        var result = await _orchestrator.RotateRefreshTokenAsync("stolen-token");

        // Assert — familia completa revocada + evento de seguridad
        Assert.Null(result);
        await _sessionStore.Received(1).RevokeByFamilyAsync("family-1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.SuspiciousActivityDetected),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_ExpiredToken_ReturnsNull()
    {
        // Arrange
        var entry = new RefreshTokenEntry
        {
            TokenHash = "hash",
            FamilyId = "family-1",
            UserId = "u1",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(-1) // expirado
        };

        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");
        _sessionStore.FindByTokenHashAsync("hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));

        // Act
        var result = await _orchestrator.RotateRefreshTokenAsync("expired-token");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_ValidToken_RotatesSuccessfully()
    {
        // Arrange
        var entry = new RefreshTokenEntry
        {
            TokenHash = "old-hash",
            FamilyId = "family-1",
            UserId = "u1",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        var user = new UserIdentity
        {
            Id = "u1", Email = "test@ex.com",
            SecurityStamp = "stamp", PasswordHash = "h"
        };

        _tokenService.HashRefreshToken("old-token").Returns("old-hash");
        _tokenService.HashRefreshToken("new-refresh").Returns("new-hash");
        _sessionStore.FindByTokenHashAsync("old-hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));
        _userStore.FindByIdAsync("u1")
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>())
            .Returns(Task.FromResult(new TokenResponse("new-jwt", "new-refresh", DateTimeOffset.UtcNow.AddMinutes(15))));

        // Act
        var result = await _orchestrator.RotateRefreshTokenAsync("old-token");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("new-jwt", result.AccessToken);
        Assert.Equal("new-refresh", result.RefreshToken);

        // Verificar que el token antiguo fue marcado como reemplazado
        await _sessionStore.Received(1).RevokeAsync("old-hash", "new-hash", Arg.Any<CancellationToken>());
        // Verificar que se creó el nuevo token
        await _sessionStore.Received(1).CreateAsync(
            Arg.Is<RefreshTokenEntry>(e => e.TokenHash == "new-hash" && e.FamilyId == "family-1"),
            Arg.Any<CancellationToken>());
        // Verificar evento de rotación
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.TokenRotated),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokeAllSessionsAsync_RevokesTokensAndChangesStamp()
    {
        // Act
        await _orchestrator.RevokeAllSessionsAsync("u1");

        // Assert
        await _userStore.Received(1).UpdateSecurityStampAsync(
            "u1", Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).RevokeAllByUserAsync("u1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.GlobalLogout),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoutAsync_RevokesSpecificToken()
    {
        // Arrange
        var entry = new RefreshTokenEntry
        {
            TokenHash = "hash", FamilyId = "f1", UserId = "u1",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        _tokenService.HashRefreshToken("token").Returns("hash");
        _sessionStore.FindByTokenHashAsync("hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));

        // Act
        await _orchestrator.LogoutAsync("token");

        // Assert
        await _sessionStore.Received(1).RevokeAsync("hash", cancellationToken: Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.Logout),
            Arg.Any<CancellationToken>());
    }
}
