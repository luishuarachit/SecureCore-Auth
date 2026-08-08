using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación de IMfaSessionStore usando JWT como token temporal.
/// </summary>
public sealed class JwtMfaSessionService(
    IOptions<JwtOptions> jwtOptions) : IMfaSessionStore
{
    private const string ClaimMfaMethod = "mfa_method";
    private const string ClaimPurpose = "purpose";
    private const string ClaimSecretFingerprint = "secret_fingerprint";
    private const string PurposeMfaVerify = "mfa_verify";

    private readonly JwtOptions _jwtOptions = jwtOptions.Value;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    public Task<string> CreateMfaSessionTokenAsync(
        string userId,
        string method,
        int validMinutes = 5,
        string? secretFingerprint = null,
        CancellationToken cancellationToken = default)
    {
        var jti = Guid.NewGuid().ToString("N");
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(validMinutes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId),
            new(JwtRegisteredClaimNames.Jti, jti),
            new(ClaimMfaMethod, method),
            new(ClaimPurpose, PurposeMfaVerify)
        };

        if (!string.IsNullOrEmpty(secretFingerprint))
        {
            claims.Add(new Claim(ClaimSecretFingerprint, secretFingerprint));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _jwtOptions.Issuer,
            Audience = _jwtOptions.Audience,
            NotBefore = now.UtcDateTime,
            IssuedAt = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = CreateSigningCredentials()
        };

        var token = _tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = _tokenHandler.WriteToken(token);

        return Task.FromResult(tokenString);
    }

    public Task<string?> ConsumeMfaSessionTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        return ValidateAndExtractUserIdAsync(token, true, cancellationToken);
    }

    public Task<string?> ValidateMfaSessionTokenAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        return ValidateAndExtractUserIdAsync(token, false, cancellationToken);
    }

    public Task<string?> GetMfaSessionTokenFingerprintAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var principal = ValidateAndGetPrincipal(token);
        if (principal is null)
            return Task.FromResult<string?>(null);

        var fingerprint = principal.Claims
            .FirstOrDefault(c => c.Type == ClaimSecretFingerprint)?.Value;

        return Task.FromResult<string?>(fingerprint);
    }

    private Task<string?> ValidateAndExtractUserIdAsync(
        string token,
        bool consume,
        CancellationToken cancellationToken)
    {
        var principal = ValidateAndGetPrincipal(token);
        if (principal is null)
            return Task.FromResult<string?>(null);

        var purpose = principal.Claims.FirstOrDefault(c => c.Type == ClaimPurpose)?.Value;
        if (purpose != PurposeMfaVerify)
            return Task.FromResult<string?>(null);

        var userId = principal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
        return Task.FromResult<string?>(userId);
    }

    private ClaimsPrincipal? ValidateAndGetPrincipal(string token)
    {
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtOptions.Issuer,
                ValidAudience = _jwtOptions.Audience,
                IssuerSigningKey = CreateSigningKey(),
                ClockSkew = TimeSpan.Zero
            };

            return _tokenHandler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }

    private SigningCredentials CreateSigningCredentials()
    {
        var algorithm = _jwtOptions.Algorithm.ToUpperInvariant();

        return algorithm switch
        {
            "RS256" or "RS384" or "RS512" => CreateRsaSigningCredentials(),
            "ES256" or "ES384" or "ES512" => CreateEcdsaSigningCredentials(),
            _ => new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_jwtOptions.SigningKey ?? throw new InvalidOperationException("SigningKey no configurada"))),
                algorithm)
        };
    }

    private SecurityKey CreateSigningKey()
    {
        var algorithm = _jwtOptions.Algorithm.ToUpperInvariant();

        return algorithm switch
        {
            "RS256" or "RS384" or "RS512" => CreateRsaKey(),
            "ES256" or "ES384" or "ES512" => CreateEcdsaKey(),
            _ => new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtOptions.SigningKey ?? throw new InvalidOperationException("SigningKey no configurada")))
        };
    }

    private SigningCredentials CreateRsaSigningCredentials()
    {
        if (string.IsNullOrEmpty(_jwtOptions.PrivateKey))
            throw new InvalidOperationException("PrivateKey no configurada para RS256");

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(_jwtOptions.PrivateKey);
        return new SigningCredentials(new RsaSecurityKey(rsa), _jwtOptions.Algorithm);
    }

    private SigningCredentials CreateEcdsaSigningCredentials()
    {
        if (string.IsNullOrEmpty(_jwtOptions.PrivateKey))
            throw new InvalidOperationException("PrivateKey no configurada para ES256");

        var ecdsa = System.Security.Cryptography.ECDsa.Create();
        ecdsa.ImportFromPem(_jwtOptions.PrivateKey);
        return new SigningCredentials(new ECDsaSecurityKey(ecdsa), _jwtOptions.Algorithm);
    }

    private SecurityKey CreateRsaKey()
    {
        if (string.IsNullOrEmpty(_jwtOptions.PublicKey))
            throw new InvalidOperationException("PublicKey no configurada para validación RS256");

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(_jwtOptions.PublicKey);
        return new RsaSecurityKey(rsa);
    }

    private SecurityKey CreateEcdsaKey()
    {
        if (string.IsNullOrEmpty(_jwtOptions.PublicKey))
            throw new InvalidOperationException("PublicKey no configurada para validación ES256");

        var ecdsa = System.Security.Cryptography.ECDsa.Create();
        ecdsa.ImportFromPem(_jwtOptions.PublicKey);
        return new ECDsaSecurityKey(ecdsa);
    }
}
