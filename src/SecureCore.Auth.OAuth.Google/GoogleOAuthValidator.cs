using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Http.Json;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.Google;

public class GoogleOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public string[] DefaultScopes { get; set; } = ["openid", "email", "profile"];
}

/// <summary>
/// Validador para Google usando el estándar OpenID Connect (OIDC).
/// OIDC es una capa de identidad sobre OAuth 2.0 que nos permite obtener
/// un "ID Token" (un JWT firmado) que contiene la información verificada del usuario.
/// </summary>
public class GoogleOAuthValidator : IOAuthProviderValidator
{
    private readonly GoogleOAuthOptions _options;
    private readonly HttpClient _httpClient;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    // Caché de llaves de Google (rotan con menos frecuencia que las de MS, pero seguimos el mismo estándar)
    private static (JsonWebKeySet Keys, DateTime Expiry)? _keysCache;
    private static readonly SemaphoreSlim _cacheLock = new(1, 1);

    private const string JwksUri = "https://www.googleapis.com/oauth2/v3/certs";
    private const string TokenEndpoint = "https://oauth2.googleapis.com/token";

    public GoogleOAuthValidator(GoogleOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "Google";

    /// <summary>
    /// Valida criptográficamente un ID Token emitido por Google.
    /// Pasos de seguridad:
    /// 1. Obtiene las llaves públicas de Google (usando caché para evitar latencia).
    /// 2. Verifica la firma (firma digital RS256).
    /// 3. Valida la audiencia (que sea para nuestro ClientId).
    /// 4. Valida el 'nonce' para prevenir ataques de repetición.
    /// </summary>
    public async Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var keys = await GetSigningKeysAsync(cancellationToken);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuers = new[] { "https://accounts.google.com", "accounts.google.com" },
                ValidateAudience = true,
                ValidAudience = _options.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = keys,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var principal = _tokenHandler.ValidateToken(idToken, validationParameters, out var validatedToken);
            var jwt = (JwtSecurityToken)validatedToken;

            // Validación de Nonce para prevenir ataques de repetición
            if (expectedNonce is not null)
            {
                var tokenNonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
                if (tokenNonce != expectedNonce)
                {
                    return OAuthIdentityResult.Failure("invalid_nonce", "Security threat: Nonce mismatch.");
                }
            }

            var emailVerifiedStr = principal.FindFirst("email_verified")?.Value;
            bool.TryParse(emailVerifiedStr, out var emailVerified);

            return new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = principal.FindFirst("sub")?.Value,
                Email = principal.FindFirst("email")?.Value,
                DisplayName = principal.FindFirst("name")?.Value,
                AvatarUrl = principal.FindFirst("picture")?.Value,
                EmailVerified = emailVerified,
                IdToken = idToken
            };
        }
        catch (Exception ex)
        {
            return OAuthIdentityResult.Failure("validation_error", ex.Message);
        }
    }

    private async Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(CancellationToken ct)
    {
        await _cacheLock.WaitAsync(ct);
        try
        {
            if (_keysCache.HasValue && _keysCache.Value.Expiry > DateTime.UtcNow)
            {
                return _keysCache.Value.Keys.GetSigningKeys();
            }

            var response = await _httpClient.GetStringAsync(JwksUri, ct);
            var jwks = new JsonWebKeySet(response);
            
            _keysCache = (jwks, DateTime.UtcNow.AddHours(24));
            return jwks.GetSigningKeys();
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        var allScopes = string.Join(" ", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        
        // Google v2.0 Auth Endpoint
        var url = $"https://accounts.google.com/o/oauth2/v2/auth" +
                  $"?client_id={_options.ClientId}" +
                  $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                  $"&response_type=code" +
                  $"&scope={Uri.EscapeDataString(allScopes)}" +
                  $"&access_type=offline" + // Para obtener refresh_token
                  $"&state={state}" +
                  $"&nonce={nonce}";
                  
        return new OAuthAuthorizationUrl(url);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
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

        var tokenResponse = await response.Content.ReadFromJsonAsync<GoogleTokenResponse>(cancellationToken: cancellationToken);
        
        if (string.IsNullOrEmpty(tokenResponse?.IdToken))
            return OAuthIdentityResult.Failure("missing_id_token", "No id_token returned from Google.");

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
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("grant_type", "refresh_token")
        });

        var response = await _httpClient.PostAsync(TokenEndpoint, content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return new ExternalTokenRefreshResult(false, null, null, error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<GoogleTokenResponse>(cancellationToken: cancellationToken);
        
        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse?.AccessToken, 
            tokenResponse != null ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private class GoogleTokenResponse
    {
        [System.Text.Json.Serialization.JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("id_token")] public string? IdToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }
}
