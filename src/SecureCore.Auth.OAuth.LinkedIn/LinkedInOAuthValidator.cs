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

    private static Lazy<Task<JsonWebKeySet>>? _jwksRefreshTask;
    private static DateTime _jwksLastRefreshed;
    private static readonly TimeSpan JwksCacheDuration = TimeSpan.FromHours(24);
    private static readonly object _cacheLock = new();

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
