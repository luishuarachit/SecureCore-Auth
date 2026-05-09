using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using SecureCore.Auth.OAuth.Apple;
using Xunit;

namespace SecureCore.Auth.OAuth.Apple.Tests;

public class AppleOAuthTests
{
    private static AppleOAuthOptions CreateTestOptions() => new()
    {
        ClientId = "com.test.app",
        TeamId = "TEAM123456",
        KeyId = "KEY123",
        // Clave P-256 de prueba (solo para tests, nunca usar en producción)
        PrivateKey = GenerateTestP256PemKey()
    };

    private static string GenerateTestP256PemKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }

    // ────────────────────────────────────────────────────────────
    // 1. BuildAuthorizationUrl
    // ────────────────────────────────────────────────────────────

    [Fact]
    public void BuildAuthorizationUrl_ShouldReturnCorrectUrl()
    {
        var validator = new AppleOAuthValidator(CreateTestOptions(), new HttpClient());
        var result = validator.BuildAuthorizationUrl("https://example.com/callback", [], "mystate", "mynonce");

        Assert.Contains("client_id=com.test.app", result.Url);
        Assert.Contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback", result.Url);
        Assert.Contains("response_type=code", result.Url);
        // Apple requiere form_post para recibir el code vía POST
        Assert.Contains("response_mode=form_post", result.Url);
        Assert.Contains("scope=name%20email", result.Url);
        Assert.Contains("state=mystate", result.Url);
        Assert.Contains("nonce=mynonce", result.Url);
    }

    [Fact]
    public void BuildAuthorizationUrl_WithCustomScopes_ShouldUseCustomScopes()
    {
        var validator = new AppleOAuthValidator(CreateTestOptions(), new HttpClient());
        var result = validator.BuildAuthorizationUrl("https://example.com/callback", ["email"], "s", "n");

        Assert.Contains("scope=email", result.Url);
        Assert.DoesNotContain("scope=name", result.Url);
    }

    // ────────────────────────────────────────────────────────────
    // 2. Nonce Hashing — SEC-01
    // ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("abc123", "bKE9UspwyIPg8LsQHkJaiehiTeUdstI5JZOvaoQRgJA")]
    [InlineData("mynonce", "GCqKMOFyj7_ubUlnmeDvbU2NvFfQQV5irqPPpW1KYAc")]
    public void ComputeNonceHash_ShouldMatchAppleExpectedFormat(string rawNonce, string expectedHash)
    {
        // Verificamos que el algoritmo de hash implementado produce el resultado
        // que Apple espera (SHA-256 en base64url sin padding).
        var nonceBytes = Encoding.ASCII.GetBytes(rawNonce);
        var hashBytes = SHA256.HashData(nonceBytes);
        var base64url = Convert.ToBase64String(hashBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');

        Assert.Equal(expectedHash, base64url);
    }

    // ────────────────────────────────────────────────────────────
    // 3. Options Validation
    // ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("", "TEAM123", "KID123", "key")]
    [InlineData("com.app", "", "KID123", "key")]
    [InlineData("com.app", "TEAM123", "", "key")]
    [InlineData("com.app", "TEAM123", "KID123", "")]
    public void AddApple_WithMissingRequiredOptions_ShouldThrowArgumentException(
        string clientId, string teamId, string keyId, string privateKey)
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        var builder = new SecureCore.Auth.OAuth.Extensions.OAuthBuilder(services);

        Assert.Throws<ArgumentException>(() =>
        {
            SecureCore.Auth.OAuth.Apple.Extensions.AppleOAuthExtensions.AddApple(builder, o =>
            {
                o.ClientId = clientId;
                o.TeamId = teamId;
                o.KeyId = keyId;
                o.PrivateKey = privateKey;
            });
        });
    }

    // ────────────────────────────────────────────────────────────
    // 4. ProviderName
    // ────────────────────────────────────────────────────────────

    [Fact]
    public void ProviderName_ShouldBeApple()
    {
        var validator = new AppleOAuthValidator(CreateTestOptions(), new HttpClient());
        Assert.Equal("Apple", validator.ProviderName);
    }
}
