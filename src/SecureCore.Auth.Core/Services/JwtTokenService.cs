using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Servicio de generación y gestión de tokens JWT y Refresh Tokens.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este servicio maneja dos tipos de tokens:
///
/// 1. ACCESS TOKEN (JWT): Un token firmado digitalmente que contiene claims del usuario.
///    Es corto (15 min) y se envía en cada petición HTTP en el header "Authorization: Bearer {token}".
///    El servidor puede validarlo SIN consultar la base de datos (es "stateless").
///
/// 2. REFRESH TOKEN: Una cadena aleatoria de 32 bytes (base64url). Es largo (7 días)
///    y solo se usa para obtener un nuevo Access Token. Se almacena como hash SHA-256
///    en la base de datos para poder revocarlo.
///
/// El claim personalizado "ssv" (Security Stamp Version) es lo que permite la revocación
/// global de sesiones. Si el SecurityStamp del usuario cambia, todos los tokens con
/// el valor anterior del "ssv" serán rechazados.
/// </remarks>
public sealed class JwtTokenService(
    IOptions<JwtOptions> jwtOptions,
    IOptions<SecureAuthOptions> authOptions) : ITokenService
{
    private readonly JwtOptions _jwtOptions = jwtOptions.Value;
    private readonly SecureAuthOptions _authOptions = authOptions.Value;

    /// <inheritdoc />
    public Task<TokenResponse> GenerateTokenPairAsync(
        UserIdentity user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();
        var expiresAt = DateTimeOffset.UtcNow.Add(_authOptions.AccessTokenLifetime);

        var response = new TokenResponse(accessToken, refreshToken, expiresAt);
        return Task.FromResult(response);
    }

    /// <inheritdoc />
    public string GenerateAccessToken(UserIdentity user)
    {
        ArgumentNullException.ThrowIfNull(user);

        // Creamos la clave de firma a partir de la configuración
        var securityKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_jwtOptions.SigningKey));
        var credentials = new SigningCredentials(securityKey, _jwtOptions.Algorithm);

        // Definimos los claims del token
        // DIDÁCTICA: Los claims son "afirmaciones" sobre el usuario que el servidor
        // incluye en el token. El cliente puede leerlos, pero no modificarlos
        // sin invalidar la firma.
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Sub] = user.Id,
            [JwtRegisteredClaimNames.Email] = user.Email,
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString(),
            // ssv = Security Stamp Version: claim personalizado para revocación global
            ["ssv"] = user.SecurityStamp
        };

        // Si el usuario tiene nombre para mostrar, lo incluimos
        if (!string.IsNullOrEmpty(user.DisplayName))
        {
            claims[JwtRegisteredClaimNames.Name] = user.DisplayName;
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
            ]),
            Claims = claims,
            Expires = DateTime.UtcNow.Add(_authOptions.AccessTokenLifetime),
            Issuer = _jwtOptions.Issuer,
            Audience = _jwtOptions.Audience,
            SigningCredentials = credentials
        };

        var tokenHandler = new JsonWebTokenHandler();
        return tokenHandler.CreateToken(tokenDescriptor);
    }

    /// <inheritdoc />
    public string GenerateRefreshToken()
    {
        // Generamos 32 bytes aleatorios criptográficamente seguros
        // y los codificamos en base64url (URL-safe, sin padding) usando el encoder estándar.
        var randomBytes = RandomNumberGenerator.GetBytes(32);
        return Base64UrlEncoder.Encode(randomBytes);
    }

    /// <inheritdoc />
    public string HashRefreshToken(string refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        // Usamos SHA-256 para hashear el refresh token antes de almacenarlo
        // DIDÁCTICA: Igual que las contraseñas, nunca almacenamos tokens en texto plano.
        // Si un atacante accede a la base de datos, solo verá los hashes.
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(refreshToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
