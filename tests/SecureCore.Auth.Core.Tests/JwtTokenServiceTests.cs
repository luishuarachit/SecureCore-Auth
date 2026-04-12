using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests para JwtTokenService — generación y gestión de JWT y Refresh Tokens.
/// </summary>
public class JwtTokenServiceTests
{
    private readonly JwtTokenService _tokenService;
    private readonly UserIdentity _testUser;

    public JwtTokenServiceTests()
    {
        var jwtOptions = Options.Create(new JwtOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKey = "TestSigningKey_MustBeAtLeast32Characters!",
            Algorithm = "HS256"
        });

        var authOptions = Options.Create(new SecureAuthOptions
        {
            AccessTokenLifetime = TimeSpan.FromMinutes(15)
        });

        _tokenService = new JwtTokenService(jwtOptions, authOptions);

        _testUser = new UserIdentity
        {
            Id = "user-test-001",
            Email = "test@example.com",
            DisplayName = "Test User",
            SecurityStamp = Guid.NewGuid().ToString(),
            PasswordHash = "dummy-hash"
        };
    }

    [Fact]
    public async Task GenerateTokenPairAsync_ReturnsValidTokenResponse()
    {
        // Act
        var response = await _tokenService.GenerateTokenPairAsync(_testUser);

        // Assert
        Assert.NotNull(response);
        Assert.NotEmpty(response.AccessToken);
        Assert.NotEmpty(response.RefreshToken);
        Assert.True(response.ExpiresAt > DateTimeOffset.UtcNow);
    }

    [Fact]
    public void GenerateAccessToken_ReturnsNonEmptyJwt()
    {
        // Act
        var token = _tokenService.GenerateAccessToken(_testUser);

        // Assert — JWT tiene 3 partes separadas por "."
        Assert.NotEmpty(token);
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsUrlSafeString()
    {
        // Act
        var token = _tokenService.GenerateRefreshToken();

        // Assert — debe ser URL-safe (sin +, /, =)
        Assert.NotEmpty(token);
        Assert.DoesNotContain("+", token);
        Assert.DoesNotContain("/", token);
        Assert.DoesNotContain("=", token);
    }

    [Fact]
    public void GenerateRefreshToken_GeneratesUniqueTokens()
    {
        // Act
        var token1 = _tokenService.GenerateRefreshToken();
        var token2 = _tokenService.GenerateRefreshToken();

        // Assert — deben ser diferentes (aleatorios)
        Assert.NotEqual(token1, token2);
    }

    [Fact]
    public void HashRefreshToken_ReturnsDeterministicHash()
    {
        // Arrange
        var token = "test-refresh-token-value";

        // Act
        var hash1 = _tokenService.HashRefreshToken(token);
        var hash2 = _tokenService.HashRefreshToken(token);

        // Assert — SHA-256 es determinista
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashRefreshToken_DifferentTokensProduceDifferentHashes()
    {
        // Act
        var hash1 = _tokenService.HashRefreshToken("token-A");
        var hash2 = _tokenService.HashRefreshToken("token-B");

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void HashRefreshToken_ReturnsLowercaseHex()
    {
        // Act
        var hash = _tokenService.HashRefreshToken("any-token");

        // Assert — debe ser hexadecimal en minúsculas (64 chars para SHA-256)
        Assert.Equal(64, hash.Length);
        Assert.Equal(hash, hash.ToLowerInvariant());
    }

    [Fact]
    public async Task GenerateTokenPairAsync_ThrowsOnNullUser()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _tokenService.GenerateTokenPairAsync(null!));
    }
}
