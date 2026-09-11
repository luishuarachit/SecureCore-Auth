using Microsoft.Extensions.Logging;
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

        _tokenService = new JwtTokenService(jwtOptions, authOptions, Substitute.For<ILogger<JwtTokenService>>());

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

    [Fact]
    public void RoleClaim_WithAllowedSystemClaims_AppearsInJwt()
    {
        var svc = CreateTokenService(["role", "roles"]);
        var user = _testUser with { Claims = new() { ["role"] = "admin" } };

        var token = svc.GenerateAccessToken(user);
        var claims = ReadClaims(token);

        Assert.Contains(claims, c => c.Type == "role" && c.Value == "admin");
    }

    [Fact]
    public void RoleClaim_WithoutAllowedSystemClaims_IsBlocked()
    {
        var user = _testUser with { Claims = new() { ["role"] = "admin" } };

        var token = _tokenService.GenerateAccessToken(user);
        var claims = ReadClaims(token);

        Assert.DoesNotContain(claims, c => c.Type == "role");
    }

    [Fact]
    public void CustomClaim_AlwaysFlows_RegardlessOfSystemClaims()
    {
        var user = _testUser with { Claims = new() { ["department"] = "engineering" } };

        var token = _tokenService.GenerateAccessToken(user);
        var claims = ReadClaims(token);

        Assert.Contains(claims, c => c.Type == "department" && c.Value == "engineering");
    }

    [Fact]
    public void AcrClaim_DisabledByDefault_NotEmitted()
    {
        var svc = CreateTokenService();
        var user = _testUser;

        var token = svc.GenerateAccessToken(user);
        var claims = ReadClaims(token);

        // DIDÁCTICA (S3): acr es opt-in (EmitAcr=false por defecto) para no imponer
        // semántica de niveles de autenticación al implementador.
        Assert.DoesNotContain(claims, c => c.Type == "acr");
    }

    [Fact]
    public void AcrClaim_EmitAcrEnabled_EmitsConfiguredLevel()
    {
        var svc = CreateTokenService(emitAcr: true, acrLevel: "2");

        var token = svc.GenerateAccessToken(_testUser);
        var claims = ReadClaims(token);

        Assert.Contains(claims, c => c.Type == "acr" && c.Value == "2");
    }

    [Fact]
    public void AcrClaim_EmitAcrEnabled_UserClaimWins()
    {
        var svc = CreateTokenService(emitAcr: true, acrLevel: "1");
        var user = _testUser with { Claims = new() { ["acr"] = "2" } };

        var token = svc.GenerateAccessToken(user);
        var claims = ReadClaims(token);

        // DIDÁCTICA (S3): el claim explícito del implementador (p. ej. subir a AAL2 tras
        // MFA) manda sobre el valor global configurado.
        Assert.Contains(claims, c => c.Type == "acr" && c.Value == "2");
    }

    private static IEnumerable<System.Security.Claims.Claim> ReadClaims(string jwt)
    {
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var parsed = handler.ReadJwtToken(jwt);
        return parsed.Claims;
    }

    private static TimeSpan ReadExpClaim(string jwt)
    {
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var parsed = handler.ReadJwtToken(jwt);
        return parsed.ValidTo - parsed.ValidFrom;
    }

    [Fact]
    public async Task AccessTokenLifetimeProvider_ResolvesCustomTtl()
    {
        var svc = CreateTokenService(accessTokenLifetimeProvider:
            _ => TimeSpan.FromMinutes(5));

        var response = await svc.GenerateTokenPairAsync(_testUser);
        var ttl = ReadExpClaim(response.AccessToken);

        Assert.True(ttl >= TimeSpan.FromMinutes(4.5) && ttl <= TimeSpan.FromMinutes(5.5));
        var expectedExpires = DateTimeOffset.UtcNow.Add(TimeSpan.FromMinutes(5));
        Assert.True(response.ExpiresAt >= expectedExpires.AddSeconds(-10));
        Assert.True(response.ExpiresAt <= expectedExpires.AddSeconds(10));
    }

    [Fact]
    public async Task AccessTokenLifetimeProvider_ReturnsNull_UsesGlobalTtl()
    {
        var svc = CreateTokenService(accessTokenLifetimeProvider: _ => null);

        var response = await svc.GenerateTokenPairAsync(_testUser);
        var ttl = ReadExpClaim(response.AccessToken);

        Assert.True(ttl >= TimeSpan.FromMinutes(14) && ttl <= TimeSpan.FromMinutes(16));
    }

    [Fact]
    public async Task AccessTokenLifetimeProvider_ThrowsException_FallsBackToGlobalTtl()
    {
        var svc = CreateTokenService(accessTokenLifetimeProvider: _ =>
            throw new InvalidOperationException("simulated failure"));

        var response = await svc.GenerateTokenPairAsync(_testUser);
        var ttl = ReadExpClaim(response.AccessToken);

        Assert.True(ttl >= TimeSpan.FromMinutes(14) && ttl <= TimeSpan.FromMinutes(16));
    }

    [Fact]
    public async Task AccessTokenLifetimeProvider_NullProvider_UsesGlobalTtl()
    {
        var svc = CreateTokenService(accessTokenLifetimeProvider: null);

        var response = await svc.GenerateTokenPairAsync(_testUser);
        var ttl = ReadExpClaim(response.AccessToken);

        Assert.True(ttl >= TimeSpan.FromMinutes(14) && ttl <= TimeSpan.FromMinutes(16));
    }

    private JwtTokenService CreateTokenService(
        HashSet<string>? allowedSystemClaims = null,
        Func<UserIdentity, TimeSpan?>? accessTokenLifetimeProvider = null,
        bool emitAcr = false,
        string? acrLevel = null)
    {
        var jwtOptions = Options.Create(new JwtOptions
        {
            Issuer = "test-issuer",
            Audience = "test-audience",
            SigningKey = "TestSigningKey_MustBeAtLeast32Characters!",
            Algorithm = "HS256",
            AllowedSystemClaims = allowedSystemClaims ?? []
        });

        var authOptions = Options.Create(new SecureAuthOptions
        {
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            AccessTokenLifetimeProvider = accessTokenLifetimeProvider,
            EmitAcr = emitAcr,
            AcrLevel = acrLevel ?? "1"
        });

        return new JwtTokenService(jwtOptions, authOptions, Substitute.For<ILogger<JwtTokenService>>());
    }
}
