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

namespace SecureCore.Auth.OAuth.GitHub;

public class GitHubOAuthOptions
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public string[] DefaultScopes { get; set; } = ["read:user", "user:email"];
}

/// <summary>
/// Validador para GitHub.
/// GitHub usa un flujo OAuth 2.0 tradicional. Requiere un paso adicional 
/// para obtener el email si el usuario lo tiene configurado como privado.
/// </summary>
public class GitHubOAuthValidator : IOAuthProviderValidator
{
    private readonly GitHubOAuthOptions _options;
    private readonly HttpClient _httpClient;

    private const string AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
    private const string TokenEndpoint = "https://github.com/login/oauth/access_token";
    private const string UserEndpoint = "https://api.github.com/user";
    private const string EmailsEndpoint = "https://api.github.com/user/emails";

    public GitHubOAuthValidator(GitHubOAuthOptions options, HttpClient httpClient)
    {
        _options = options;
        _httpClient = httpClient;
    }

    public string ProviderName => "GitHub";

    public Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        // GitHub OAuth no emite id_token (no es OIDC). Flujo B no es compatible.
        return Task.FromResult(OAuthIdentityResult.Failure("not_supported", "GitHub does not support OIDC / id_token."));
    }

    public OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce)
    {
        // GitHub ignora el nonce ya que no es OIDC, pero sí usa state.
        var allScopes = string.Join(" ", scopes.Length > 0 ? scopes : _options.DefaultScopes);
        var uri = $"{AuthorizationEndpoint}?client_id={_options.ClientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={Uri.EscapeDataString(allScopes)}&state={state}";
        return new OAuthAuthorizationUrl(uri);
    }

    public async Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default)
    {
        // 1. Intercambiar código por access token
        var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("code", authorizationCode),
            new KeyValuePair<string, string>("redirect_uri", redirectUri)
        });

        var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
            return OAuthIdentityResult.Failure("exchange_failed", errorContent);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: cancellationToken);
        if (tokenResponse?.AccessToken is null)
        {
            return OAuthIdentityResult.Failure("exchange_failed", "Access token not found in response.");
        }

        // 2. Obtener identidad del usuario usando el access_token
        using var userRequest = new HttpRequestMessage(HttpMethod.Get, UserEndpoint);
        userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
        // GitHub API requiere User-Agent
        userRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("SecureCore.Auth.OAuth", "2.0.0"));

        var userResponse = await _httpClient.SendAsync(userRequest, cancellationToken);
        if (!userResponse.IsSuccessStatusCode)
        {
            return OAuthIdentityResult.Failure("profile_failed", "Failed to retrieve GitHub profile.");
        }

        var profile = await userResponse.Content.ReadFromJsonAsync<GitHubUserProfile>(cancellationToken: cancellationToken);
        if (profile is null)
        {
            return OAuthIdentityResult.Failure("profile_failed", "Failed to parse GitHub profile.");
        }

        var email = profile.Email;
        var emailVerified = true; // Si GitHub nos lo da, suele estar verificado o podemos chequear /user/emails

        // Si el email es privado, obtener de endpoint secundario
        if (string.IsNullOrEmpty(email))
        {
            using var emailsRequest = new HttpRequestMessage(HttpMethod.Get, EmailsEndpoint);
            emailsRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
            emailsRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("SecureCore.Auth.OAuth", "2.0.0"));

            var emailsResponse = await _httpClient.SendAsync(emailsRequest, cancellationToken);
            if (emailsResponse.IsSuccessStatusCode)
            {
                var emails = await emailsResponse.Content.ReadFromJsonAsync<List<GitHubEmail>>(cancellationToken: cancellationToken);
                var primaryEmail = emails?.Find(e => e.Primary);
                if (primaryEmail is not null)
                {
                    email = primaryEmail.Email;
                    emailVerified = primaryEmail.Verified;
                }
            }
        }

        return new OAuthIdentityResult
        {
            Succeeded = true,
            ProviderKey = profile.Id.ToString(),
            Email = email,
            DisplayName = profile.Name ?? profile.Login,
            AvatarUrl = profile.AvatarUrl,
            EmailVerified = emailVerified,
            AccessToken = tokenResponse.AccessToken,
            RefreshToken = tokenResponse.RefreshToken,
            Scopes = tokenResponse.Scope?.Split(' '),
            TokenExpiresAt = tokenResponse.ExpiresIn > 0 
                ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) 
                : DateTimeOffset.UtcNow.AddHours(8) // Fallback típico
        };
    }

    public async Task<ExternalTokenRefreshResult> RefreshProviderAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("client_id", _options.ClientId),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("grant_type", "refresh_token")
        });

        var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            return new ExternalTokenRefreshResult(false, null, null, error);
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: cancellationToken);
        if (tokenResponse?.AccessToken is null)
        {
            return new ExternalTokenRefreshResult(false, null, null, "Failed to parse refreshed token.");
        }

        return new ExternalTokenRefreshResult(
            true, 
            tokenResponse.AccessToken, 
            tokenResponse.ExpiresIn > 0 ? DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn) : null,
            null);
    }

    private class GitHubTokenResponse
    {
        [JsonPropertyName("access_token")] public string? AccessToken { get; set; }
        [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
        [JsonPropertyName("scope")] public string? Scope { get; set; }
    }

    private class GitHubUserProfile
    {
        [JsonPropertyName("id")] public long Id { get; set; }
        [JsonPropertyName("login")] public string? Login { get; set; }
        [JsonPropertyName("name")] public string? Name { get; set; }
        [JsonPropertyName("email")] public string? Email { get; set; }
        [JsonPropertyName("avatar_url")] public string? AvatarUrl { get; set; }
    }

    private class GitHubEmail
    {
        [JsonPropertyName("email")] public string? Email { get; set; }
        [JsonPropertyName("verified")] public bool Verified { get; set; }
        [JsonPropertyName("primary")] public bool Primary { get; set; }
    }
}
