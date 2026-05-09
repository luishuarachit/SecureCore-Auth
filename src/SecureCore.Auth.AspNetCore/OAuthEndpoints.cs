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
            CancellationToken ct) =>
        {
            var valRequest = new OAuthValidationRequest { IdToken = request.IdToken };
            var result = await orchestrator.SignInOrRegisterAsync(provider, valRequest, options.Value, ct);

            if (result.Succeeded && result.Tokens is not null)
            {
                return Results.Ok(new
                {
                    accessToken = result.Tokens.AccessToken,
                    refreshToken = result.Tokens.RefreshToken,
                    expiresAt = result.Tokens.ExpiresAt,
                    isNewUser = result.IsNewUser
                });
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
            CancellationToken ct) =>
        {
            var validators = serviceProvider.GetServices<IOAuthProviderValidator>();
            var validator = validators.FirstOrDefault(v => v.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));

            if (validator is null)
                return Results.NotFound(new { error = "provider_not_found" });

            // Generar State y Nonce seguros
            var state = GenerateSecureRandomString(32);
            var nonce = GenerateSecureRandomString(32);

            var entry = new OAuthStateEntry(nonce, provider, redirectUri, DateTimeOffset.UtcNow);
            await stateStore.SaveAsync(state, entry, TimeSpan.FromMinutes(10), ct);

            var authUrl = validator.BuildAuthorizationUrl(redirectUri, [], state, nonce);
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
            CancellationToken ct) =>
        {
            // Consumir el state (obtener y borrar de forma atómica)
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
                return Results.Ok(new
                {
                    accessToken = result.Tokens.AccessToken,
                    refreshToken = result.Tokens.RefreshToken,
                    expiresAt = result.Tokens.ExpiresAt,
                    isNewUser = result.IsNewUser
                });
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
