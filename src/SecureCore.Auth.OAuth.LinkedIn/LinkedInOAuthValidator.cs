using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.LinkedIn;

public class LinkedInOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public string[] DefaultScopes { get; set; } = ["openid", "profile", "email"];
}

/// <summary>
/// Validador para LinkedIn.
/// LinkedIn ha migrado recientemente a OpenID Connect (OIDC) para la autenticación de usuarios,
/// lo que permite una validación criptográfica más robusta mediante ID Tokens.
/// </summary>
public class LinkedInOAuthValidator : IOAuthProviderValidator
{
    private readonly LinkedInOAuthOptions _options;
    private readonly HttpClient _httpClient;
    private readonly JwtSecurityTokenHandler _tokenHandler = new();

    private static (JsonWebKeySet Keys, DateTime Expiry)? _keysCache;
    private static readonly SemaphoreSlim _cacheLock = new(1, 1);

    private const string JwksUri = "https://www.linkedin.com/oauth/openid/jwks";
    private const string TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
    private const string AuthorizeEndpoint = "https://www.linkedin.com/oauth/v2/authorization";

    public LinkedInOAuthValidator(LinkedInOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "LinkedIn";

    public async Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var keys = await GetSigningKeysAsync(cancellationToken);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "https://www.linkedin.com",
                ValidateAudience = true,
                ValidAudience = _options.ClientId,
                ValidateLifetime = true,
                IssuerSigningKeys = keys,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var principal = _tokenHandler.ValidateToken(idToken, validationParameters, out var validatedToken);
            var jwt = (JwtSecurityToken)validatedToken;

            // Validación de Nonce
            if (expectedNonce is not null)
            {
                var tokenNonce = jwt.Claims.FirstOrDefault(c => c.Type == "nonce")?.Value;
                if (tokenNonce != expectedNonce)
                {
                    return OAuthIdentityResult.Failure("invalid_nonce", "Nonce mismatch.");
                }
            }

            return new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = principal.FindFirst("sub")?.Value,
                Email = principal.FindFirst("email")?.Value,
                DisplayName = principal.FindFirst("name")?.Value,
                AvatarUrl = principal.FindFirst("picture")?.Value,
                EmailVerified = true,
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
        var url = $"{AuthorizeEndpoint}?client_id={_options.ClientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope={Uri.EscapeDataString(allScopes)}&state={state}&nonce={nonce}";
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

        var tokenResponse = await response.Content.ReadFromJsonAsync<LinkedInTokenResponse>(cancellationToken: cancellationToken);
        if (string.IsNullOrEmpty(tokenResponse?.IdToken))
            return OAuthIdentityResult.Failure("missing_id_token", "No id_token returned from LinkedIn.");

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

        var tokenResponse = await response.Content.ReadFromJsonAsync<LinkedInTokenResponse>(cancellationToken: cancellationToken);
        
        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse?.AccessToken, 
            tokenResponse != null ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private class LinkedInTokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("id_token")] public string? IdToken { get; set; }
        [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }
}
