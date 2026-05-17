using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.Apple;

/// <summary>
/// Validador para Apple Sign In with Apple (OIDC sobre OAuth 2.0).
///
/// Particularidades importantes respecto a otros proveedores:
/// 1. El 'client_secret' NO es un valor estático: es un JWT firmado con ES256
///    usando la llave privada (.p8) descargada del Apple Developer Portal.
/// 2. El campo 'nonce' en el id_token de Apple es el SHA-256 del nonce original
///    codificado en base64url. Hay que hashear antes de comparar.
/// 3. Apple envía el authorization code vía HTTP POST (form_post), no GET.
/// 4. El nombre del usuario solo llega en el PRIMER inicio de sesión.
/// </summary>
public class AppleOAuthValidator : IOAuthProviderValidator
{
    private readonly AppleOAuthOptions _options;
    private readonly HttpClient _httpClient;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    private static Lazy<Task<JsonWebKeySet>>? _jwksRefreshTask;
    private static DateTime _jwksLastRefreshed;
    private static readonly TimeSpan JwksCacheDuration = TimeSpan.FromHours(24);
    private static readonly object _cacheLock = new();

    private const string JwksUri = "https://appleid.apple.com/auth/keys";
    private const string TokenEndpoint = "https://appleid.apple.com/auth/token";
    private const string Issuer = "https://appleid.apple.com";

    public AppleOAuthValidator(AppleOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "Apple";

    public async Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        try
        {
            return await ValidateIdTokenCoreAsync(idToken, expectedNonce, cancellationToken);
        }
        catch (Exception ex) when (ex is SecurityTokenSignatureKeyNotFoundException
                                or SecurityTokenInvalidSignatureException)
        {
            var freshKeys = await GetSigningKeysAsync(cancellationToken, forceRefresh: true);
            try
            {
                return await ValidateTokenWithKeysAsync(idToken, expectedNonce, freshKeys, cancellationToken);
            }
            catch (Exception innerEx)
            {
                return OAuthIdentityResult.Failure("validation_error",
                    $"Falló incluso con llaves frescas: {innerEx.Message}");
            }
        }
        catch (Exception ex)
        {
            return OAuthIdentityResult.Failure("validation_error", ex.Message);
        }
    }

    private async Task<OAuthIdentityResult> ValidateIdTokenCoreAsync(
        string idToken, string? expectedNonce, CancellationToken cancellationToken)
    {
        var keys = await GetSigningKeysAsync(cancellationToken);
        return await ValidateTokenWithKeysAsync(idToken, expectedNonce, keys, cancellationToken);
    }

    private async Task<OAuthIdentityResult> ValidateTokenWithKeysAsync(
        string idToken, string? expectedNonce, IEnumerable<SecurityKey> keys, CancellationToken cancellationToken)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = Issuer,
            ValidateAudience = true,
            ValidAudience = _options.ClientId,
            ValidateLifetime = true,
            IssuerSigningKeys = keys,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        var principal = _tokenHandler.ValidateToken(idToken, validationParameters, out var validatedToken);
        var jwt = (JwtSecurityToken)validatedToken;

        // [SEC-01] Validación de Nonce — CRÍTICO:
        // Apple NO almacena el nonce en texto plano en el id_token.
        // Almacena el hash SHA-256 del nonce original codificado en base64url (sin padding).
        // La comparación directa con el nonce original SIEMPRE fallaría.
        if (expectedNonce is not null)
        {
            var tokenNonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
            var nonceSupported = jwt.Claims.FirstOrDefault(c => c.Type == "nonce_supported")?.Value;

            // Si Apple indica que nonce_supported es false, no validamos el nonce
            // (Apple no lo procesó). Solo validamos si está presente o supported == true.
            bool shouldValidateNonce = nonceSupported is null ||
                                       nonceSupported.Equals("true", StringComparison.OrdinalIgnoreCase);

            if (shouldValidateNonce)
            {
                var expectedNonceHash = ComputeNonceHash(expectedNonce);
                if (tokenNonce != expectedNonceHash)
                {
                    return OAuthIdentityResult.Failure("invalid_nonce", "Security threat: Nonce mismatch.");
                }
            }
        }

        // Apple codifica email_verified como booleano JSON real en algunos flujos
        // y como string "true"/"false" en otros. Manejamos ambos casos.
        var emailVerifiedClaim = principal.FindFirst("email_verified")?.Value;
        bool emailVerified = emailVerifiedClaim?.Equals("true", StringComparison.OrdinalIgnoreCase) == true;

        // Validar que sub no sea nulo — es el identificador único del usuario
        var providerKey = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(providerKey))
            return OAuthIdentityResult.Failure("missing_sub", "Apple id_token does not contain a 'sub' claim.");

        return new OAuthIdentityResult
        {
            Succeeded = true,
            ProviderKey = providerKey,
            Email = principal.FindFirst("email")?.Value,
            // Apple solo envía el nombre en el PRIMER inicio de sesión.
            // En inicios de sesión subsecuentes, esta claim estará ausente.
            DisplayName = principal.FindFirst("name")?.Value,
            EmailVerified = emailVerified,
            IdToken = idToken
        };
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        var allScopes = string.Join(" ", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        
        // Apple requiere response_mode=form_post si pides scopes de usuario, pero
        // si usamos solo el standard flow para web, 'code' es suficiente.
        var url = $"https://appleid.apple.com/auth/authorize" +
                  $"?client_id={_options.ClientId}" +
                  $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                  $"&response_type=code" +
                  $"&scope={Uri.EscapeDataString(allScopes)}" +
                  $"&response_mode=form_post" + // Apple suele requerir form_post para enviar el code
                  $"&state={state}" +
                  $"&nonce={nonce}";
                  
        return new OAuthAuthorizationUrl(url);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        var clientSecret = CreateClientSecret();

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("code", authorizationCode),
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("redirect_uri", redirectUri)
        });

        var response = await _httpClient.PostAsync(TokenEndpoint, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("exchange_failed", error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<AppleTokenResponse>(cancellationToken: cancellationToken);
        
        if (string.IsNullOrEmpty(tokenResponse?.IdToken))
            return OAuthIdentityResult.Failure("missing_id_token", "No id_token returned from Apple.");

        var identityResult = await ValidateIdTokenAsync(tokenResponse.IdToken, expectedNonce, cancellationToken);
        
        if (identityResult.Succeeded)
        {
            return identityResult with
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                TokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn)
            };
        }
            
        return identityResult;
    }

    public async Task<ExternalTokenRefreshResult> RefreshProviderAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var clientSecret = CreateClientSecret();

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("grant_type", "refresh_token")
        });

        var response = await _httpClient.PostAsync(TokenEndpoint, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return new ExternalTokenRefreshResult(false, null, null, error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<AppleTokenResponse>(cancellationToken: cancellationToken);
        
        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse?.AccessToken, 
            tokenResponse != null ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private string CreateClientSecret()
    {
        var now = DateTimeOffset.UtcNow;
        // Duración corta por seguridad. El máximo permitido por Apple es 6 meses.
        var expires = now.AddMinutes(5);

        // ECDsaSecurityKey mantiene una referencia al objeto ECDsa para firmar.
        // NO usar 'using' aquí porque WriteToken() necesita la referencia
        // después de que este código termine de ejecutarse.
        // El objeto se libera correctamente al final de este método mediante try/finally.
        var ecdsa = ECDsa.Create();
        try
        {
            // ImportFromPem acepta PKCS#8 ("BEGIN PRIVATE KEY") que es el formato .p8 de Apple.
            ecdsa.ImportFromPem(_options.PrivateKey);

            // [SEC-02] Verificar que la clave sea una curva P-256 (requerida por Apple).
            if (ecdsa.KeySize != 256)
            {
                throw new InvalidOperationException(
                    $"Apple requires a P-256 (256-bit) key, but the provided key has {ecdsa.KeySize} bits.");
            }

            // Pasamos el objeto ECDsa a ECDsaSecurityKey. El key firma sincrónico en WriteToken.
            var key = new ECDsaSecurityKey(ecdsa) { KeyId = _options.KeyId };
            var credentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Iss, _options.TeamId),
                new Claim(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Exp, expires.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Aud, Issuer),
                new Claim(JwtRegisteredClaimNames.Sub, _options.ClientId)
            };

            var token = new JwtSecurityToken(
                header: new JwtHeader(credentials),
                payload: new JwtPayload(claims)
            );

            // WriteToken firma el JWT completamente de forma sincrónica antes de retornar.
            return _tokenHandler.WriteToken(token);
        }
        finally
        {
            // Liberamos la llave DESPUÉS de que WriteToken() haya completado.
            ecdsa.Dispose();
        }
    }

    /// <summary>
    /// Computa el hash SHA-256 del nonce en base64url (sin padding),
    /// que es el formato exacto que Apple almacena en el claim 'nonce' del id_token.
    /// Comparar el nonce original directamente con el claim siempre fallaría.
    /// </summary>
    private static string ComputeNonceHash(string nonce)
    {
        var nonceBytes = Encoding.ASCII.GetBytes(nonce);
        var hashBytes = SHA256.HashData(nonceBytes);
        // Base64url encoding sin padding (RFC 4648 §5)
        return Convert.ToBase64String(hashBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }

    private async Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(CancellationToken ct, bool forceRefresh = false)
    {
        var now = DateTime.UtcNow;

        // Primera verificación SIN lock: caso común (caché válida)
        if (!forceRefresh && _jwksRefreshTask is { IsValueCreated: true } && now - _jwksLastRefreshed < JwksCacheDuration)
        {
            var jwks = await _jwksRefreshTask.Value;
            return jwks.GetSigningKeys();
        }

        lock (_cacheLock)
        {
            // Segunda verificación CON lock
            if (!forceRefresh && _jwksRefreshTask is { IsValueCreated: true } && now - _jwksLastRefreshed < JwksCacheDuration)
            {
                return _jwksRefreshTask.Value.Result.GetSigningKeys();
            }

            // Necesitamos refresh: crear nueva Lazy<Task>
            _jwksLastRefreshed = now;
            _jwksRefreshTask = new Lazy<Task<JsonWebKeySet>>(() => FetchJwksAsync(ct));
        }

        var jwksResult = await _jwksRefreshTask.Value;
        return jwksResult.GetSigningKeys();
    }

    private async Task<JsonWebKeySet> FetchJwksAsync(CancellationToken ct)
    {
        var response = await _httpClient.GetStringAsync(JwksUri, ct);
        return new JsonWebKeySet(response);
    }

    private class AppleTokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("token_type")] public string? TokenType { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("id_token")] public string? IdToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }
}
