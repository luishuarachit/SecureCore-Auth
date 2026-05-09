using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.Facebook;

public class FacebookOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public string ApiVersion { get; set; } = "v18.0";
    public string[] DefaultScopes { get; set; } = ["email", "public_profile"];
}

/// <summary>
/// Validador para Facebook (Meta).
/// Facebook NO usa OIDC nativamente en su flujo estándar, por lo que usamos OAuth 2.0 puro.
/// Implementamos 'appsecret_proof' para asegurar las llamadas de servidor a servidor.
/// </summary>
public class FacebookOAuthValidator : IOAuthProviderValidator
{
    private readonly FacebookOAuthOptions _options;
    private readonly HttpClient _httpClient;

    public FacebookOAuthValidator(FacebookOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "Facebook";

    private string GetBaseUrl() => $"https://graph.facebook.com/{_options.ApiVersion}";

    /// <summary>
    /// Genera el appsecret_proof requerido para llamadas seguras server-to-server.
    /// Esto evita que un Access Token robado pueda ser usado desde otro servidor 
    /// que no posea nuestro ClientSecret.
    /// </summary>
    private string GenerateAppSecretProof(string accessToken)
    {
        var keyBytes = System.Text.Encoding.UTF8.GetBytes(_options.ClientSecret);
        var tokenBytes = System.Text.Encoding.UTF8.GetBytes(accessToken);
        using var hmac = new System.Security.Cryptography.HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(tokenBytes);
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    public Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(OAuthIdentityResult.Failure("not_supported", "Facebook does not support id_tokens. Use ExchangeCodeAsync."));
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        var allScopes = string.Join(",", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        var url = $"https://www.facebook.com/{_options.ApiVersion}/dialog/oauth" +
                  $"?client_id={_options.ClientId}" +
                  $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                  $"&scope={Uri.EscapeDataString(allScopes)}" +
                  $"&state={state}";
                  
        return new OAuthAuthorizationUrl(url);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        // 1. Intercambiar código por access token (short-lived)
        var tokenUrl = $"{GetBaseUrl()}/oauth/access_token" +
                      $"?client_id={_options.ClientId}" +
                      $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                      $"&client_secret={_options.ClientSecret}" +
                      $"&code={authorizationCode}";
        
        var response = await _httpClient.GetAsync(tokenUrl, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("exchange_failed", error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<FacebookTokenResponse>(cancellationToken: cancellationToken);
        if (string.IsNullOrEmpty(tokenResponse?.AccessToken)) 
            return OAuthIdentityResult.Failure("exchange_failed", "No access token returned from Facebook.");

        var accessToken = tokenResponse.AccessToken;
        var proof = GenerateAppSecretProof(accessToken);

        // 2. Obtener perfil del usuario (Usando appsecret_proof para máxima seguridad)
        var profileUrl = $"{GetBaseUrl()}/me" +
                        $"?fields=id,name,email,picture" +
                        $"&access_token={accessToken}" +
                        $"&appsecret_proof={proof}";
                        
        var profileResponse = await _httpClient.GetAsync(profileUrl, cancellationToken);
        if (!profileResponse.IsSuccessStatusCode)
        {
            var error = await profileResponse.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("profile_failed", $"Failed to retrieve Facebook profile: {error}");
        }

        var profile = await profileResponse.Content.ReadFromJsonAsync<FacebookUserProfile>(cancellationToken: cancellationToken);
        if (profile == null) return OAuthIdentityResult.Failure("profile_failed", "Failed to parse Facebook profile.");

        return new OAuthIdentityResult
        {
            Succeeded = true,
            ProviderKey = profile.Id,
            Email = profile.Email,
            DisplayName = profile.Name,
            AvatarUrl = profile.Picture?.Data?.Url,
            EmailVerified = true,
            AccessToken = accessToken,
            TokenExpiresAt = tokenResponse.ExpiresIn > 0 ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null
        };
    }

    public async Task<ExternalTokenRefreshResult> RefreshProviderAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        // Facebook usa "long-lived tokens" en lugar de Refresh Tokens estándar en su flujo web básico.
        // El intercambio de un short-lived por un long-lived se hace en el server.
        return new ExternalTokenRefreshResult(false, null, null, "Facebook uses long-lived tokens; standard refresh flow not applicable.");
    }

    private class FacebookTokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("token_type")] public string? TokenType { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
    }

    private class FacebookUserProfile
    {
        [JsonPropertyName("id")] public string Id { get; set; } = null!;
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("email")] public string? Email { get; set; }
        [JsonPropertyName("picture")] public FacebookPicture? Picture { get; set; }
    }

    private class FacebookPicture
    {
        [JsonPropertyName("data")] public FacebookPictureData? Data { get; set; }
    }

    private class FacebookPictureData
    {
        [JsonPropertyName("url")] public string? Url { get; set; }
    }
}
