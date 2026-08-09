using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests del JwtMfaSessionService REAL (no mock). Cubren los fixes v3.1.8:
/// - lectura del claim "sub" tras el mapeo de JwtSecurityTokenHandler
/// - single-use real del token vía blacklist de jti (IMemoryCache)
/// </summary>
public class JwtMfaSessionServiceTests
{
    private readonly JwtMfaSessionService _service;
    private readonly MemoryCache _cache;

    private const string Issuer = "test-issuer";
    private const string Audience = "test-audience";

    public JwtMfaSessionServiceTests()
    {
        _cache = new MemoryCache(new MemoryCacheOptions());
        _service = new JwtMfaSessionService(
            Options.Create(new JwtOptions
            {
                Issuer = Issuer,
                Audience = Audience,
                SigningKey = "TestSigningKey_MustBeAtLeast32Characters!",
                Algorithm = "HS256"
            }),
            _cache);
    }

    [Fact]
    public async Task ValidateMfaSessionTokenAsync_ReturnsUserId()
    {
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5);

        var userId = await _service.ValidateMfaSessionTokenAsync(token);

        Assert.Equal("user-123", userId);
    }

    [Fact]
    public async Task ConsumeMfaSessionTokenAsync_ThenValidate_ReturnsNull_SingleUse()
    {
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5);

        var consumedUserId = await _service.ConsumeMfaSessionTokenAsync(token);
        var secondValidate = await _service.ValidateMfaSessionTokenAsync(token);

        Assert.Equal("user-123", consumedUserId);
        Assert.Null(secondValidate);
    }

    [Fact]
    public async Task ConsumeMfaSessionTokenAsync_Twice_SecondConsumeReturnsNull()
    {
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5);

        var first = await _service.ConsumeMfaSessionTokenAsync(token);
        var second = await _service.ConsumeMfaSessionTokenAsync(token);

        Assert.Equal("user-123", first);
        Assert.Null(second);
    }

    [Fact]
    public async Task ValidateMfaSessionTokenAsync_TwoDifferentTokens_AreIndependent()
    {
        var tokenA = await _service.CreateMfaSessionTokenAsync("user-A", "totp", 5);
        var tokenB = await _service.CreateMfaSessionTokenAsync("user-B", "totp", 5);

        await _service.ConsumeMfaSessionTokenAsync(tokenA);

        var userB = await _service.ValidateMfaSessionTokenAsync(tokenB);
        Assert.Equal("user-B", userB);
    }

    [Fact]
    public async Task ValidateMfaSessionTokenAsync_InvalidToken_ReturnsNull()
    {
        var userId = await _service.ValidateMfaSessionTokenAsync("not-a-real-token");

        Assert.Null(userId);
    }

    [Fact]
    public async Task ValidateMfaSessionTokenAsync_WrongIssuerToken_ReturnsNull()
    {
        var service = new JwtMfaSessionService(
            Options.Create(new JwtOptions
            {
                Issuer = "different-issuer",
                Audience = Audience,
                SigningKey = "TestSigningKey_MustBeAtLeast32Characters!",
                Algorithm = "HS256"
            }),
            new MemoryCache(new MemoryCacheOptions()));

        var token = await service.CreateMfaSessionTokenAsync("user-123", "totp", 5);

        // Validado con el servicio original (issuer "test-issuer") → debe fallar
        var userId = await _service.ValidateMfaSessionTokenAsync(token);

        Assert.Null(userId);
    }

    [Fact]
    public async Task GetMfaSessionTokenFingerprintAsync_ReturnsFingerprint()
    {
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5, "fp123456");

        var fingerprint = await _service.GetMfaSessionTokenFingerprintAsync(token);

        Assert.Equal("fp123456", fingerprint);
    }

    [Fact]
    public async Task GetMfaSessionTokenFingerprintAsync_WithoutFingerprint_ReturnsNull()
    {
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5, null);

        var fingerprint = await _service.GetMfaSessionTokenFingerprintAsync(token);

        Assert.Null(fingerprint);
    }

    [Fact]
    public async Task ConsumedToken_FingerprintStillReadable_ForEnrollment()
    {
        // En el flujo de enrollment, el fingerprint se lee ANTES del consume.
        // Verifica que ambos operan sobre el mismo token válido.
        var token = await _service.CreateMfaSessionTokenAsync("user-123", "totp", 5, "fp123456");

        var userId = await _service.ValidateMfaSessionTokenAsync(token);
        var fingerprint = await _service.GetMfaSessionTokenFingerprintAsync(token);
        var consumedUserId = await _service.ConsumeMfaSessionTokenAsync(token);

        Assert.Equal("user-123", userId);
        Assert.Equal("fp123456", fingerprint);
        Assert.Equal("user-123", consumedUserId);
    }
}
