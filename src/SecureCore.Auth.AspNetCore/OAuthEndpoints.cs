using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.OAuth.Abstractions;
using SecureCore.Auth.OAuth.Services;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Expone los endpoints HTTP para el ecosistema OAuth de SecureCore.
/// Estos endpoints manejan la redirección, el callback y el intercambio de tokens
/// abstrayendo la complejidad de cada proveedor para el desarrollador.
/// </summary>
public static class OAuthEndpoints
{
    private const string AccessTokenCookie = "auth_access_token";
    private const string RefreshTokenCookie = "auth_refresh_token";

    public static RouteGroupBuilder MapSecureOAuthEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth/oauth")
    {
        var group = endpoints.MapGroup(prefix)
            .WithTags("SecureCore OAuth");

        // ─────────────────────────────────────────────────────────
        //  POST /auth/oauth/{provider}/token (Flujo B - Frontend Token)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/{provider}/token", async (
            string provider,
            OAuthTokenRequest request,
            OAuthOrchestrator orchestrator,
            IOptions<OAuthSignInOptions> options,
            HttpContext context,
            CancellationToken ct) =>
        {
            var valRequest = new OAuthValidationRequest { IdToken = request.IdToken };
            var result = await orchestrator.SignInOrRegisterAsync(provider, valRequest, options.Value, ct);

            if (result.Succeeded && result.Tokens is not null)
            {
                return HandleOAuthSuccess(options.Value, result, null, context);
            }

            if (result.IsLockedOut)
                return Results.Json(new { error = "account_locked", message = result.ErrorMessage }, statusCode: StatusCodes.Status429TooManyRequests);

            return Results.Json(new { error = "oauth_failed", message = result.ErrorMessage }, statusCode: StatusCodes.Status401Unauthorized);
        })
        .WithName("OAuthToken")
        .WithDescription("Inicia sesión usando un token emitido por el proveedor al frontend (Flujo B).")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  GET /auth/oauth/{provider}/authorize (Flujo A - Redirect)
        // ─────────────────────────────────────────────────────────
        group.MapGet("/{provider}/authorize", async (
            string provider,
            string redirectUri,
            HttpContext context,
            IServiceProvider serviceProvider,
            IOAuthStateStore stateStore,
            IOptions<OAuthSignInOptions> options,
            CancellationToken ct) =>
        {
            // DIDÁCTICA: Normalizamos la URL eliminando "www." para coincidir
            // con los redirect URIs registrados en los OAuth providers.
            var normalizedRedirectUri = NormalizeUrl(redirectUri);

            var validators = serviceProvider.GetServices<IOAuthProviderValidator>();
            var validator = validators.FirstOrDefault(v => v.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));

            if (validator is null)
                return Results.NotFound(new { error = "provider_not_found" });

            var state = GenerateSecureRandomString(32);
            var nonce = GenerateSecureRandomString(32);

            var entry = new OAuthStateEntry(nonce, provider, normalizedRedirectUri, DateTimeOffset.UtcNow);
            await stateStore.SaveAsync(state, entry, TimeSpan.FromMinutes(10), ct);

            var authUrl = validator.BuildAuthorizationUrl(normalizedRedirectUri, [], state, nonce);
            return Results.Redirect(authUrl.Url);
        })
        .WithName("OAuthAuthorize")
        .WithDescription("Redirige al usuario al proveedor para iniciar el Flujo A.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  GET /auth/oauth/{provider}/callback (Flujo A - Callback)
        // ─────────────────────────────────────────────────────────
        group.MapGet("/{provider}/callback", async (
            string provider,
            string code,
            string state,
            OAuthOrchestrator orchestrator,
            IOptions<OAuthSignInOptions> options,
            IOAuthStateStore stateStore,
            HttpContext context,
            CancellationToken ct) =>
        {
            var stateEntry = await stateStore.ConsumeAsync(state, ct);
            if (stateEntry is null || !stateEntry.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase))
            {
                return Results.Json(new { error = "invalid_state", message = "El state es inválido o expiró." }, statusCode: StatusCodes.Status400BadRequest);
            }

            var valRequest = new OAuthValidationRequest 
            { 
                Code = code,
                State = state,
                RedirectUri = stateEntry.RedirectUri,
                Nonce = stateEntry.Nonce
            };

            var result = await orchestrator.SignInOrRegisterAsync(provider, valRequest, options.Value, ct);

            if (result.Succeeded && result.Tokens is not null)
            {
                return HandleOAuthSuccess(options.Value, result, stateEntry.RedirectUri, context);
            }

            if (result.IsLockedOut)
                return Results.Json(new { error = "account_locked", message = result.ErrorMessage }, statusCode: StatusCodes.Status429TooManyRequests);

            return Results.Json(new { error = "oauth_failed", message = result.ErrorMessage }, statusCode: StatusCodes.Status401Unauthorized);
        })
        .WithName("OAuthCallback")
        .WithDescription("Recibe el código de autorización del proveedor y emite los tokens.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  DELETE /auth/oauth/{provider}
        // ─────────────────────────────────────────────────────────
        group.MapDelete("/{provider}", async (
            string provider,
            HttpContext context,
            IExternalTokenStore tokenStore,
            CancellationToken ct) =>
        {
            var userId = context.User.FindFirst("sub")?.Value 
                      ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (userId is null) return Results.Unauthorized();

            await tokenStore.RevokeAsync(userId, provider, ct);
            return Results.Ok(new { message = $"Conexión con {provider} revocada." });
        })
        .WithName("RevokeOAuthProvider")
        .WithDescription("Desconecta la cuenta del proveedor.")
        .RequireAuthorization();

        return group;
    }

    private static string NormalizeUrl(string url)
    {
        if (string.IsNullOrEmpty(url))
            return url;

        // DIDÁCTICA: Eliminamos "www." del host para normalizar URLs.
        // Muchos OAuth providers (Google, Microsoft) son estrictos con el matching
        // exacto del redirect_uri. Si registraste "https://example.com/callback"
        // pero el usuario llegó desde "https://www.example.com", el OAuth provider
        // rechazará la solicitud.
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            if (uri.Host.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
            {
                var builder = new UriBuilder(uri)
                {
                    Host = uri.Host[4..] // Remover "www."
                };
                return builder.Uri.ToString().TrimEnd('/');
            }
        }

        return url;
    }

    /// <summary>
    /// Maneja el caso de éxito del flujo OAuth.
    /// Si SetCookiesDirectly está habilitado, setea cookies HttpOnly y redirige al SPA.
    /// Si no, retorna JSON con los tokens (comportamiento por defecto).
    /// </summary>
    private static IResult HandleOAuthSuccess(
        OAuthSignInOptions signInOptions,
        OAuthSignInResult result,
        string? redirectUri,
        HttpContext context)
    {
        if (signInOptions.SetCookiesDirectly)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = result.Tokens!.ExpiresAt.UtcDateTime
            };

            if (!string.IsNullOrEmpty(signInOptions.CookieDomain))
            {
                cookieOptions.Domain = signInOptions.CookieDomain;
            }

            context.Response.Cookies.Append(AccessTokenCookie, result.Tokens.AccessToken, cookieOptions);

            // DIDÁCTICA: El refresh token tiene una vida más larga que el access token.
            // Su cookie debe expirar según el RefreshTokenLifetime, no el ExpiresAt del
            // access token (que es solo 15 minutos).
            var refreshCookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict
            };

            if (!string.IsNullOrEmpty(signInOptions.CookieDomain))
            {
                refreshCookieOptions.Domain = signInOptions.CookieDomain;
            }

            context.Response.Cookies.Append(RefreshTokenCookie, result.Tokens.RefreshToken, refreshCookieOptions);

            var postLoginUrl = signInOptions.PostLoginRedirectUrl ?? "/";

            // Agregamos isNewUser como query param para que el SPA pueda mostrar onboarding
            if (result.IsNewUser)
            {
                postLoginUrl = postLoginUrl.Contains('?')
                    ? $"{postLoginUrl}&isNewUser=true"
                    : $"{postLoginUrl}?isNewUser=true";
            }

            return Results.Redirect(postLoginUrl);
        }

        // Comportamiento por defecto: retornar tokens en JSON
        return Results.Ok(new
        {
            accessToken = result.Tokens!.AccessToken,
            refreshToken = result.Tokens.RefreshToken,
            expiresAt = result.Tokens.ExpiresAt,
            isNewUser = result.IsNewUser
        });
    }

    private static string GenerateSecureRandomString(int bytes)
    {
        var data = RandomNumberGenerator.GetBytes(bytes);
        return Convert.ToBase64String(data)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}

public record OAuthTokenRequest(string IdToken);
