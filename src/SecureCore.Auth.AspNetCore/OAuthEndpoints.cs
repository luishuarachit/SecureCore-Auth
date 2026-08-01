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
            string? redirectUri,
            HttpContext context,
            IServiceProvider serviceProvider,
            IOAuthStateStore stateStore,
            IOptions<OAuthSignInOptions> options,
            CancellationToken ct) =>
        {
            // DIDÁCTICA: El redirect_uri del proveedor SIEMPRE es el callback de la API,
            // nunca la URL del SPA. Los providers (Google, Microsoft, etc.) exigen que
            // coincida exactamente con el registrado en su consola. La URL del SPA
            // (redirectUri) solo se usa como destino post-login y se valida para
            // prevenir open redirect.
            var callbackUrl = BuildCallbackUrl(prefix, provider, options.Value, context);

            var validators = serviceProvider.GetServices<IOAuthProviderValidator>();
            var validator = validators.FirstOrDefault(v => v.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));

            if (validator is null)
                return Results.NotFound(new { error = "provider_not_found" });

            string? postLoginTarget;
            if (!string.IsNullOrWhiteSpace(redirectUri))
            {
                if (!IsSafePostLoginTarget(redirectUri, options.Value))
                {
                    return Results.Json(
                        new { error = "invalid_redirect_uri", message = "redirectUri debe ser https y su host debe estar en la lista de hosts permitidos." },
                        statusCode: StatusCodes.Status400BadRequest);
                }

                // Normalizamos la URL eliminando "www." para coincidir con el host permitido.
                postLoginTarget = NormalizeUrl(redirectUri);
            }
            else
            {
                postLoginTarget = options.Value.PostLoginRedirectUrl;
            }

            var state = GenerateSecureRandomString(32);
            var nonce = GenerateSecureRandomString(32);

            var entry = new OAuthStateEntry(nonce, provider, postLoginTarget ?? "/", DateTimeOffset.UtcNow, callbackUrl);
            await stateStore.SaveAsync(state, entry, TimeSpan.FromMinutes(10), ct);

            var authUrl = validator.BuildAuthorizationUrl(callbackUrl, [], state, nonce);
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

            // Usamos el CallbackUri almacenado en el authorize (mismo valor enviado al
            // provider). Fallback defensivo por si el store no lo persistió (entradas viejas
            // o implementaciones custom de IOAuthStateStore).
            var callbackUrl = stateEntry.CallbackUri ?? BuildCallbackUrl(prefix, provider, options.Value, context);

            var valRequest = new OAuthValidationRequest
            {
                Code = code,
                State = state,
                RedirectUri = callbackUrl,
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
    /// Construye la URL del callback de la API que se envía como redirect_uri al
    /// proveedor OAuth. Usa PublicBaseUrl si está configurado; si no, la deriva del
    /// request actual (scheme + host). Aplica NormalizeUrl para eliminar "www.".
    /// </summary>
    internal static string BuildCallbackUrl(string prefix, string provider, OAuthSignInOptions options, HttpContext context)
    {
        var baseUrl = options.PublicBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        }

        var callbackUrl = $"{baseUrl.TrimEnd('/')}/{prefix.Trim('/')}/{provider}/callback";
        return NormalizeUrl(callbackUrl);
    }

    /// <summary>
    /// Valida que una URL pueda usarse como destino del redirect post-login (SPA).
    /// Debe ser absoluta, https y su host debe estar en AllowedPostLoginHosts o
    /// coincidir con el host de PostLoginRedirectUrl. Previene open redirect.
    /// </summary>
    internal static bool IsSafePostLoginTarget(string? url, OAuthSignInOptions options)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return false;

        var host = uri.Host;
        if (string.IsNullOrEmpty(host))
            return false;

        foreach (var allowed in options.AllowedPostLoginHosts)
        {
            if (string.Equals(host, allowed, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (!string.IsNullOrEmpty(options.PostLoginRedirectUrl)
            && Uri.TryCreate(options.PostLoginRedirectUrl, UriKind.Absolute, out var configured)
            && string.Equals(host, configured.Host, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
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

            // SEGURIDAD: Solo redirigimos al redirectUri del request si pasó la validación
            // (https + host permitido). En cualquier otro caso (incluido Flujo B, donde no
            // hay redirectUri), usamos el PostLoginRedirectUrl configurado.
            var postLoginUrl = IsSafePostLoginTarget(redirectUri, signInOptions)
                ? redirectUri!
                : signInOptions.PostLoginRedirectUrl ?? "/";

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
