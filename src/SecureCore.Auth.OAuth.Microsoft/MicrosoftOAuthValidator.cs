using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.Microsoft;

public class MicrosoftOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    
    /// <summary>
    /// El tenant de Microsoft Entra ID. Por defecto es "common" (multitenant).
    /// </summary>
    public string Tenant { get; set; } = "common";
    
    public string[] DefaultScopes { get; set; } = ["openid", "profile", "email", "offline_access"];
}

/// <summary>
/// Validador para Microsoft Entra ID (antes Azure AD).
/// Implementa OIDC v2.0 y soporta validación dinámica de Issuers para entornos multi-tenant.
/// </summary>
public class MicrosoftOAuthValidator : IOAuthProviderValidator
{
    private readonly MicrosoftOAuthOptions _options;
    private readonly HttpClient _httpClient;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();
    
    // Caché simple para evitar latencia en cada login
    private static (JsonWebKeySet Keys, DateTime Expiry)? _keysCache;
    private static readonly SemaphoreSlim _cacheLock = new(1, 1);

    public MicrosoftOAuthValidator(MicrosoftOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "Microsoft";

    private string GetAuthority() => $"https://login.microsoftonline.com/{_options.Tenant}";
    private string GetTokenEndpoint() => $"{GetAuthority()}/oauth2/v2.0/token";
    private string GetAuthorizeEndpoint() => $"{GetAuthority()}/oauth2/v2.0/authorize";
    private string GetJwksUri() => $"https://login.microsoftonline.com/{_options.Tenant}/discovery/v2.0/keys";

    /// <summary>
    /// Valida un ID Token de Microsoft.
    /// Nota especial: Microsoft usa issuers dinámicos con el ID del tenant.
    /// Implementamos una validación flexible que asegura que el token venga de login.microsoftonline.com.
    ///
    /// DIDÁCTICA (Key Rotation Resilience):
    /// Microsoft Entra ID rota sus llaves de firma periódicamente. Si la validación falla
    /// por firma inválida o llave no encontrada, este método invalida automáticamente la
    /// caché JWKS y reintenta con llaves frescas, asegurando cero downtime ante rotaciones.
    /// </summary>
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
            ValidateAudience = true,
            ValidAudience = _options.ClientId,
            ValidateLifetime = true,
            IssuerSigningKeys = keys,
            ClockSkew = TimeSpan.FromMinutes(5),

            // Lógica de Validación de Issuer para Microsoft
            ValidateIssuer = true,
            IssuerValidator = (issuer, token, parameters) =>
            {
                // En Entra ID v2.0, el issuer es https://login.microsoftonline.com/{tenantid}/v2.0
                if (issuer.StartsWith("https://login.microsoftonline.com/") && issuer.EndsWith("/v2.0"))
                {
                    return issuer;
                }
                throw new SecurityTokenInvalidIssuerException($"Invalid issuer: {issuer}");
            }
        };

        var principal = _tokenHandler.ValidateToken(idToken, validationParameters, out var validatedToken);
        var jwtToken = (JwtSecurityToken)validatedToken;

        // Validación de Nonce (Requerido por Microsoft en OIDC)
        if (!string.IsNullOrEmpty(expectedNonce))
        {
            var tokenNonce = jwtToken.Payload.ContainsKey("nonce") ? jwtToken.Payload["nonce"].ToString() : null;
            if (tokenNonce != expectedNonce)
                return OAuthIdentityResult.Failure("invalid_nonce", "Nonce mismatch for security.");
        }

        // Microsoft recomienda usar 'preferred_username' para el email en v2.0
        var email = principal.FindFirst("preferred_username")?.Value
                 ?? principal.FindFirst(ClaimTypes.Email)?.Value
                 ?? principal.FindFirst("email")?.Value;

        return new OAuthIdentityResult
        {
            Succeeded = true,
            ProviderKey = jwtToken.Subject, // OID o Sub
            Email = email,
            DisplayName = principal.FindFirst("name")?.Value,
            EmailVerified = true,
            IdToken = idToken
        };
    }

    private async Task<IEnumerable<SecurityKey>> GetSigningKeysAsync(CancellationToken ct, bool forceRefresh = false)
    {
        if (!forceRefresh && _keysCache.HasValue && _keysCache.Value.Expiry > DateTime.UtcNow)
        {
            return _keysCache.Value.Keys.GetSigningKeys();
        }

        await _cacheLock.WaitAsync(ct);
        try
        {
            if (!forceRefresh && _keysCache.HasValue && _keysCache.Value.Expiry > DateTime.UtcNow)
            {
                return _keysCache.Value.Keys.GetSigningKeys();
            }

            var jwks = await _httpClient.GetFromJsonAsync<JsonWebKeySet>(GetJwksUri(), ct);
            if (jwks != null)
            {
                _keysCache = (jwks, DateTime.UtcNow.AddHours(24));
                return jwks.GetSigningKeys();
            }
            throw new Exception("Failed to fetch Microsoft JWKS");
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        var allScopes = string.Join(" ", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        
        // Incluimos response_mode=query para asegurar el retorno vía GET al callback.
        // Microsoft v2.0 exige nonce para id_tokens.
        var url = $"{GetAuthorizeEndpoint()}?client_id={_options.ClientId}" +
                  $"&response_type=code" +
                  $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                  $"&scope={Uri.EscapeDataString(allScopes)}" +
                  $"&state={state}" +
                  $"&nonce={nonce}" +
                  $"&response_mode=query";
                  
        return new OAuthAuthorizationUrl(url);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("code", authorizationCode),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("grant_type", "authorization_code")
        });

        var response = await _httpClient.PostAsync(GetTokenEndpoint(), content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("exchange_failed", error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<MicrosoftTokenResponse>(cancellationToken: cancellationToken);
        if (string.IsNullOrEmpty(tokenResponse?.IdToken)) 
            return OAuthIdentityResult.Failure("no_id_token", "The response from Microsoft did not contain an id_token.");

        var result = await ValidateIdTokenAsync(tokenResponse.IdToken, expectedNonce, cancellationToken);
        
        if (result.Succeeded)
        {
            return result with
            {
                AccessToken = tokenResponse.AccessToken,
                RefreshToken = tokenResponse.RefreshToken,
                TokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn),
                Scopes = tokenResponse.Scope?.Split(' ')
            };
        }
        
        return result;
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

        var response = await _httpClient.PostAsync(GetTokenEndpoint(), content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return new ExternalTokenRefreshResult(false, null, null, error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<MicrosoftTokenResponse>(cancellationToken: cancellationToken);
        
        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse?.AccessToken, 
            tokenResponse != null ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private class MicrosoftTokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("id_token")] public string? IdToken { get; set; }
        [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
        [JsonPropertyName("scope")] public string? Scope { get; set; }
    }
}
