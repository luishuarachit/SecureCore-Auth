using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.OAuth.TikTok;

public class TikTokOAuthOptions
{
    public required string ClientKey { get; set; }
    public required string ClientSecret { get; set; }
    public string[] DefaultScopes { get; set; } = ["user.info.basic"];
}

/// <summary>
/// Validador para TikTok Login Kit V2.
/// TikTok tiene un manejo de errores particular: a veces devuelve 200 OK 
/// pero con un cuerpo JSON que indica un error interno. Este validador maneja esa lógica.
/// </summary>
public class TikTokOAuthValidator : IOAuthProviderValidator
{
    private readonly TikTokOAuthOptions _options;
    private readonly HttpClient _httpClient;

    public TikTokOAuthValidator(TikTokOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "TikTok";

    public Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(OAuthIdentityResult.Failure("not_supported", "TikTok does not support id_tokens."));
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        var allScopes = string.Join(",", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        // TikTok usa client_key en lugar de client_id en la URL de autorización
        var url = $"https://www.tiktok.com/v2/auth/authorize/?client_key={_options.ClientKey}&scope={Uri.EscapeDataString(allScopes)}&response_type=code&redirect_uri={Uri.EscapeDataString(redirectUri)}&state={state}";
        return new OAuthAuthorizationUrl(url);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_key", _options.ClientKey),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("code", authorizationCode),
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("redirect_uri", redirectUri)
        });

        var response = await _httpClient.PostAsync("https://open.tiktokapis.com/v2/oauth/token/", content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("exchange_failed", error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<TikTokTokenResponse>(cancellationToken: cancellationToken);
        if (!string.IsNullOrEmpty(tokenResponse?.Error))
        {
            return OAuthIdentityResult.Failure("exchange_failed", $"{tokenResponse.Error}: {tokenResponse.ErrorDescription}");
        }

        if (tokenResponse?.AccessToken == null) return OAuthIdentityResult.Failure("exchange_failed", "No access token returned.");

        // Obtener perfil
        using var userRequest = new HttpRequestMessage(HttpMethod.Get, "https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name");
        userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
        
        var userResponse = await _httpClient.SendAsync(userRequest, cancellationToken);
        var profileContainer = await userResponse.Content.ReadFromJsonAsync<TikTokUserProfileContainer>(cancellationToken: cancellationToken);

        if (profileContainer?.Error != null && profileContainer.Error.Code != "ok")
        {
            return OAuthIdentityResult.Failure("profile_failed", $"TikTok API Error: {profileContainer.Error.Message} (Code: {profileContainer.Error.Code})");
        }

        var profile = profileContainer?.Data?.User;
        
        if (profile == null) return OAuthIdentityResult.Failure("profile_failed", "Failed to parse TikTok profile.");

        return new OAuthIdentityResult
        {
            Succeeded = true,
            ProviderKey = profile.OpenId,
            DisplayName = profile.DisplayName,
            AvatarUrl = profile.AvatarUrl,
            EmailVerified = false, // TikTok v2 basic info no suele incluir email por defecto
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            TokenExpiresAt = tokenResponse.ExpiresIn > 0 ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null
        };
    }

    public async Task<ExternalTokenRefreshResult> RefreshProviderAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_key", _options.ClientKey),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("grant_type", "refresh_token")
        });

        var response = await _httpClient.PostAsync("https://open.tiktokapis.com/v2/oauth/token/", content, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return new ExternalTokenRefreshResult(false, null, null, "Failed to refresh TikTok token");
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<TikTokTokenResponse>(cancellationToken: cancellationToken);
        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse?.AccessToken, 
            tokenResponse != null ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private class TikTokTokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
        [JsonPropertyName("open_id")] public string? OpenId { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("error_description")] public string? ErrorDescription { get; set; }
    }

    private class TikTokUserProfileContainer
    {
        [JsonPropertyName("data")] public TikTokData? Data { get; set; }
        [JsonPropertyName("error")] public TikTokError? Error { get; set; }
    }

    private class TikTokError
    {
        [JsonPropertyName("code")] public string? Code { get; set; }
        [JsonPropertyName("message")] public string? Message { get; set; }
    }

    private class TikTokData
    {
        [JsonPropertyName("user")] public TikTokUser? User { get; set; }
    }

    private class TikTokUser
    {
        [JsonPropertyName("open_id")] public string OpenId { get; set; } = null!;
        [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
        [JsonPropertyName("avatar_url")] public string? AvatarUrl { get; set; }
    }
}
