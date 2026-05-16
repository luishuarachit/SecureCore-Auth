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

    // DIDÁCTICA: Conjunto de claims que el sistema gestiona internamente y no deben
    // ser inyectados desde UserIdentity.Claims. Cualquier intento de sobrescribirlos
    // se ignora silenciosamente para evitar suplantación, escalación de privilegios
    // o bypass de mecanismos de seguridad como el SecurityStamp.
    private static readonly HashSet<string> SystemClaims =
    [
        JwtRegisteredClaimNames.Sub,
        JwtRegisteredClaimNames.Email,
        JwtRegisteredClaimNames.Jti,
        JwtRegisteredClaimNames.Iss,
        JwtRegisteredClaimNames.Aud,
        JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Iat,
        JwtRegisteredClaimNames.Nbf,
        JwtRegisteredClaimNames.Name,
        "ssv",
        "role",
        "roles",
        "auth_time",
        "amr",
        "acr",
        "azp",
        "nonce",
    ];

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

        // DIDÁCTICA: Los claims son "afirmaciones" sobre el usuario que el servidor
        // incluye en el token. El cliente puede leerlos, pero no modificarlos
        // sin invalidar la firma.
        //
        // Los claims 'sub' y 'email' se definen en Subject (líneas abajo) y NO deben
        // repetirse en el diccionario Claims, porque el handler los mergea y genera
        // claims duplicados en el JWT. Algunos parsers del lado cliente pueden
        // comportarse de forma impredecible con claims duplicados.
        var claims = new Dictionary<string, object>
        {
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString(),
            // ssv = Security Stamp Version: claim personalizado para revocación global
            ["ssv"] = user.SecurityStamp
        };

        // Si el usuario tiene nombre para mostrar, lo incluimos
        if (!string.IsNullOrEmpty(user.DisplayName))
        {
            claims[JwtRegisteredClaimNames.Name] = user.DisplayName;
        }

        // Si hay claims adicionales definidos por el implementador, los incluimos
        // con protección contra inyección de claims sensibles del sistema.
        if (user.Claims != null)
        {
            foreach (var kv in user.Claims)
            {
                // DIDÁCTICA: Bloqueamos explícitamente claims que el sistema ya gestiona
                // o que son críticos de seguridad. Esto evita que un implementador
                // (o un atacante que comprometa el UserStore) pueda inyectar claims
                // como 'sub' (suplantación de identidad), 'role' (escalación de
                // privilegios) o 'ssv' (bypass de revocación global).
                if (!SystemClaims.Contains(kv.Key))
                {
                    claims[kv.Key] = kv.Value;
                }
            }
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
