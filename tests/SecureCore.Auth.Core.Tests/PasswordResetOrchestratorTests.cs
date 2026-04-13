using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

public class PasswordResetOrchestratorTests
{
    private readonly Mock<IUserStore> _userStoreMock = new();
    private readonly Mock<IPasswordResetStore> _passwordResetStoreMock = new();
    private readonly Mock<IResetTokenMailer> _resetTokenMailerMock = new();
    private readonly Mock<IPasswordHasher> _passwordHasherMock = new();
    private readonly Mock<ISessionStore> _sessionStoreMock = new();
    private readonly Mock<IAuthEventDispatcher> _eventDispatcherMock = new();
    
    // Para simplificar, obviaremos las inyecciones anidadas completas del SessionOrchestrator en favor de una configuración mockeada indirectamente si el diseño lo permitiera - sin embargo, ya que se le requiere inyectar su instancia cruda, inicializaremos la cadena de dependencias requerida.
    private readonly Mock<ITokenService> _tokenServiceMock = new();
    private readonly Mock<Microsoft.Extensions.Caching.Distributed.IDistributedCache> _cacheMock = new();
    
    private readonly IOptions<PasswordResetOptions> _options;
    private readonly IOptions<SecureAuthOptions> _secureAuthOptions;
    
    private readonly PasswordResetOrchestrator _sut;
    private readonly SessionOrchestrator _sessionOrchestrator;

    public PasswordResetOrchestratorTests()
    {
        _options = Options.Create(new PasswordResetOptions
        {
            TokenLifetimeMinutes = 15,
            TokenSizeBytes = 32,
            MaxRequestsPerHour = 3
        });

        _secureAuthOptions = Options.Create(new SecureAuthOptions());

        var stampValidator = new SecurityStampValidator(
            _userStoreMock.Object,
            _cacheMock.Object,
            _secureAuthOptions,
            NullLogger<SecurityStampValidator>.Instance
        );

        _sessionOrchestrator = new SessionOrchestrator(
            _sessionStoreMock.Object,
            _userStoreMock.Object,
            _tokenServiceMock.Object,
            stampValidator,
            _eventDispatcherMock.Object,
            _secureAuthOptions,
            NullLogger<SessionOrchestrator>.Instance
        );

        _sut = new PasswordResetOrchestrator(
            _userStoreMock.Object,
            _passwordResetStoreMock.Object,
            _resetTokenMailerMock.Object,
            _passwordHasherMock.Object,
            _sessionOrchestrator,
            _eventDispatcherMock.Object,
            _options,
            NullLogger<PasswordResetOrchestrator>.Instance
        );
    }

    [Fact]
    public async Task RequestReset_UserNotFound_ReturnsTrue_NoEmailSent()
    {
        // Arrange
        _userStoreMock.Setup(m => m.FindByEmailAsync("notfound@example.com", default))
            .ReturnsAsync((UserIdentity?)null);

        // Act
        var result = await _sut.RequestPasswordResetAsync("notfound@example.com");

        // Assert
        Assert.True(result);
        _resetTokenMailerMock.Verify(m => m.SendResetEmailAsync(It.IsAny<string>(), It.IsAny<string>(), default), Times.Never);
        _passwordResetStoreMock.Verify(m => m.StoreAsync(It.IsAny<PasswordResetEntry>(), default), Times.Never);
    }

    [Fact]
    public async Task RequestReset_ValidEmail_StoresHashedToken()
    {
        // Arrange
        var user = new UserIdentity { Id = "user-1", Email = "found@example.com", SecurityStamp = "stamp" };
        _userStoreMock.Setup(m => m.FindByEmailAsync("found@example.com", default))
            .ReturnsAsync(user);
        
        _passwordResetStoreMock.Setup(m => m.CountRecentRequestsAsync(user.Id, It.IsAny<DateTime>(), default))
            .ReturnsAsync(0);

        PasswordResetEntry? storedEntry = null;
        _passwordResetStoreMock.Setup(m => m.StoreAsync(It.IsAny<PasswordResetEntry>(), default))
            .Callback<PasswordResetEntry, CancellationToken>((entry, _) => storedEntry = entry)
            .Returns(Task.CompletedTask);

        string? rawTokenSent = null;
        _resetTokenMailerMock.Setup(m => m.SendResetEmailAsync("found@example.com", It.IsAny<string>(), default))
            .Callback<string, string, CancellationToken>((_, token, _) => rawTokenSent = token)
            .Returns(Task.CompletedTask);

        // Act
        var result = await _sut.RequestPasswordResetAsync("found@example.com");

        // Assert
        Assert.True(result);
        Assert.NotNull(storedEntry);
        Assert.NotNull(rawTokenSent);
        Assert.NotEqual(rawTokenSent, storedEntry.TokenHash); // En BD jamás debe haber token en plaintext.
    }

    [Fact]
    public async Task ConfirmReset_ValidToken_UpdatesPasswordHashAndRevokesSessions()
    {
        // Arrange
        var rawTokenTest = "dummyTokenTest==";

        var user = new UserIdentity { Id = "user-1", Email = "found@example.com", SecurityStamp = "stamp" };
        _userStoreMock.Setup(m => m.FindByIdAsync(user.Id, default)).ReturnsAsync(user);

        // Simulamos que el token exista en DB y no sea inválido
        _passwordResetStoreMock.Setup(m => m.FindByTokenHashAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new PasswordResetEntry 
            { 
                TokenHash = "hash-123", 
                UserId = user.Id, 
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(10),
                IsUsed = false 
            });

        _passwordHasherMock.Setup(m => m.HashPassword("newPass!")).Returns("newPassHashed");

        // Act
        var result = await _sut.ConfirmPasswordResetAsync(rawTokenTest, "newPass!");

        // Assert
        Assert.Equal(PasswordResetResult.Success, result);
        
        // Verifica que la nueva clave ha sido insertada en la base de datos de usuarios
        _userStoreMock.Verify(m => m.UpdatePasswordHashAsync("user-1", "newPassHashed", default), Times.Once);

        // Verifica que han sido revocadas todas las sesiones existentes activando una invalidez global
        _userStoreMock.Verify(m => m.UpdateSecurityStampAsync("user-1", It.IsAny<string>(), default), Times.Once);
        _sessionStoreMock.Verify(m => m.RevokeAllByUserAsync("user-1", default), Times.Once);

        // Marcar consumible como utilizado
        _passwordResetStoreMock.Verify(m => m.MarkAsUsedAsync(It.IsAny<string>(), default), Times.Once);
    }
    
    [Fact]
    public async Task ConfirmReset_ExpiredToken_ReturnsInvalidToken()
    {
        // Arrange
        var rawTokenTest = "dummyTokenTest==";

        _passwordResetStoreMock.Setup(m => m.FindByTokenHashAsync(It.IsAny<string>(), default))
            .ReturnsAsync(new PasswordResetEntry 
            { 
                TokenHash = "hash-123", 
                UserId = "user-1", 
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(-5), // Expired!
                IsUsed = false 
            });

        // Act
        var result = await _sut.ConfirmPasswordResetAsync(rawTokenTest, "newPass!");

        // Assert
        Assert.Equal(PasswordResetResult.InvalidToken, result);
    }
}
