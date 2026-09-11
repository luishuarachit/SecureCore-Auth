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
    private readonly IOperationLock _operationLock;

    public SessionOrchestratorTests()
    {
        _sessionStore = Substitute.For<ISessionStore>();
        _userStore = Substitute.For<IUserStore>();
        _tokenService = Substitute.For<ITokenService>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        _operationLock = Substitute.For<IOperationLock>();
        _operationLock.AcquireAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(new MockLock());

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
            _operationLock,
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
            Id = "u1",
            Email = "test@ex.com",
            SecurityStamp = "stamp",
            PasswordHash = "h"
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
    public async Task RotateRefreshTokenAsync_ReplacedWithinGracePeriod_ReturnsAccessToken_WithoutRevokingFamily()
    {
        // DIDÁCTICA (auditoría): el grace period DEBE ser alcanzable. Un token rotado (marcado
        // ReplacedBy + ReplacedAtUtc reciente) presentado de nuevo por una race condition del
        // cliente NO debe revocar la familia: devuelve un Access Token fresco e idempotente.
        var entry = new RefreshTokenEntry
        {
            TokenHash = "old-hash",
            FamilyId = "family-1",
            UserId = "u1",
            IsRevoked = true, // un store real marca el token rotado también como revocado
            ReplacedByTokenHash = "new-hash",
            ReplacedAtUtc = DateTime.UtcNow, // dentro del grace period (30 s)
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        _tokenService.HashRefreshToken("old-token").Returns("old-hash");
        _sessionStore.FindByTokenHashAsync("old-hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));
        _userStore.FindByIdAsync("u1")
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity { Id = "u1", Email = "t@e.com", SecurityStamp = "s" }));
        _tokenService.GenerateAccessToken(Arg.Any<UserIdentity>()).Returns("fresh-jwt");

        var result = await _orchestrator.RotateRefreshTokenAsync("old-token");

        Assert.NotNull(result);
        Assert.Equal("fresh-jwt", result.AccessToken);
        Assert.Equal("old-token", result.RefreshToken);
        await _sessionStore.DidNotReceiveWithAnyArgs().RevokeByFamilyAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _sessionStore.DidNotReceiveWithAnyArgs().CreateAsync(Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceiveWithAnyArgs().DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_ReplacedOutsideGracePeriod_RevokesFamily()
    {
        // Fuera del grace period, la re-presentación de un token rotado es REUSO → familia revocada.
        var entry = new RefreshTokenEntry
        {
            TokenHash = "old-hash",
            FamilyId = "family-1",
            UserId = "u1",
            ReplacedByTokenHash = "new-hash",
            ReplacedAtUtc = DateTime.UtcNow.AddSeconds(-60), // fuera del grace (30 s)
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        _tokenService.HashRefreshToken("old-token").Returns("old-hash");
        _sessionStore.FindByTokenHashAsync("old-hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));

        var result = await _orchestrator.RotateRefreshTokenAsync("old-token");

        Assert.Null(result);
        await _sessionStore.Received(1).RevokeByFamilyAsync("family-1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.SuspiciousActivityDetected),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RotateRefreshTokenAsync_ValidToken_PreservesAuthMethodInNewTokens()
    {
        // DIDÁCTICA (auditoría): el aseguramiento de la sesión (amr/mfa_method) debe sobrevivir
        // a la rotación; sin esto, una sesión MFA se re-emite sin amr (downgrade).
        var entry = new RefreshTokenEntry
        {
            TokenHash = "old-hash",
            FamilyId = "family-1",
            UserId = "u1",
            AuthMethod = "mfa",
            MfaMethod = "totp",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };

        var user = new UserIdentity { Id = "u1", Email = "t@e.com", SecurityStamp = "stamp" };

        _tokenService.HashRefreshToken("old-token").Returns("old-hash");
        _tokenService.HashRefreshToken("new-refresh").Returns("new-hash");
        _sessionStore.FindByTokenHashAsync("old-hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(entry));
        _userStore.FindByIdAsync("u1")
            .Returns(ValueTask.FromResult<UserIdentity?>(user));
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>())
            .Returns(Task.FromResult(new TokenResponse("new-jwt", "new-refresh", DateTimeOffset.UtcNow.AddMinutes(15))));

        var result = await _orchestrator.RotateRefreshTokenAsync("old-token");

        Assert.NotNull(result);
        await _tokenService.Received(1).GenerateTokenPairAsync(
            Arg.Is<UserIdentity>(u =>
                u.Claims != null &&
                u.Claims.GetValueOrDefault("amr") == "mfa" &&
                u.Claims.GetValueOrDefault("mfa_method") == "totp"),
            Arg.Any<CancellationToken>());
        await _sessionStore.Received(1).CreateAsync(
            Arg.Is<RefreshTokenEntry>(e =>
                e.AuthMethod == "mfa" && e.MfaMethod == "totp"),
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
            TokenHash = "hash",
            FamilyId = "f1",
            UserId = "u1",
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

    [Fact]
    public async Task RevokeAllSessionsAsync_WithVerifiedStore_ClearsMfaVerifiedWindow()
    {
        // Arrange (H2, auditoría): la revocación global también cae la ventana mfa_verified.
        var mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();
        var orchestrator = CreateOrchestratorWithWindow(mfaVerified);

        // Act
        await orchestrator.RevokeAllSessionsAsync("u1");

        // Assert: una sesión nueva (sin MFA) dentro de MfaVerifiedTtl no hereda el step-up.
        await mfaVerified.Received(1).ClearAsync("u1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogoutAsync_WithVerifiedStore_ClearsMfaVerifiedWindow()
    {
        // Arrange (H2, auditoría): el cierre de sesión invalida la ventana compartida.
        var mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();
        var orchestrator = CreateOrchestratorWithWindow(mfaVerified);
        _tokenService.HashRefreshToken("token").Returns("hash");
        _sessionStore.FindByTokenHashAsync("hash")
            .Returns(ValueTask.FromResult<RefreshTokenEntry?>(new RefreshTokenEntry
            {
                TokenHash = "hash",
                FamilyId = "f1",
                UserId = "u1",
                ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
            }));

        // Act
        await orchestrator.LogoutAsync("token");

        // Assert
        await mfaVerified.Received(1).ClearAsync("u1", Arg.Any<CancellationToken>());
    }

    private SessionOrchestrator CreateOrchestratorWithWindow(IMfaVerifiedSessionStore mfaVerified)
    {
        return new SessionOrchestrator(
            _sessionStore,
            _userStore,
            _tokenService,
            _stampValidator,
            _eventDispatcher,
            Options.Create(new SecureAuthOptions
            {
                GracePeriodSeconds = 30,
                RefreshTokenLifetime = TimeSpan.FromDays(7),
                AccessTokenLifetime = TimeSpan.FromMinutes(15)
            }),
            _operationLock,
            NullLogger<SessionOrchestrator>.Instance,
            mfaVerified);
    }

    private sealed class MockLock : IDisposable
    {
        public void Dispose() { }
    }
}
