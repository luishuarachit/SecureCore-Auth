using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Endpoints opcionales de autenticación como Minimal APIs de ASP.NET Core.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los Minimal APIs son una forma ligera de definir endpoints HTTP
/// sin necesidad de controladores. Son ideales para librerías que quieren
/// proveer endpoints "listos para usar" que el desarrollador pueda mapear
/// opcionalmente en su pipeline.
///
/// El desarrollador los agrega así:
/// <code>
/// app.MapSecureAuthEndpoints("/auth");
/// </code>
/// Esto mapeará: /auth/login, /auth/refresh, /auth/logout, /auth/revoke-all
/// </remarks>
public static class SecureAuthEndpoints
{
    /// <summary>
    /// Mapea los endpoints de autenticación en la ruta especificada.
    /// </summary>
    /// <param name="endpoints">El builder de endpoints de la aplicación.</param>
    /// <param name="prefix">Prefijo de ruta (ej: "/auth").</param>
    /// <returns>El grupo de endpoints creado.</returns>
    public static RouteGroupBuilder MapSecureAuthEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
    {
        var group = endpoints.MapGroup(prefix)
            .WithTags("SecureCore Auth");

        // ─────────────────────────────────────────────────────────
        //  POST /auth/login
        // ─────────────────────────────────────────────────────────
        group.MapPost("/login", async (
            LoginRequest request,
            IdentityOrchestrator orchestrator,
            CancellationToken ct) =>
        {
            var (result, tokens) = await orchestrator.SignInWithPasswordAsync(
                request.Email, request.Password, ct);

            if (result.Succeeded && tokens is not null)
            {
                return Results.Ok(new
                {
                    accessToken = tokens.AccessToken,
                    refreshToken = tokens.RefreshToken,
                    expiresAt = tokens.ExpiresAt
                });
            }

            if (result.IsLockedOut)
            {
                return Results.Json(
                    new { error = "account_locked", message = result.Message },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            if (result.RequiresTwoFactor)
            {
                return Results.Json(
                    new { error = "two_factor_required", message = "Se requiere segundo factor." },
                    statusCode: StatusCodes.Status200OK);
            }

            // Respuesta genérica para evitar enumeración de usuarios
            return Results.Json(
                new { error = "invalid_credentials", message = result.Message },
                statusCode: StatusCodes.Status401Unauthorized);
        })
        .WithName("Login")
        .WithDescription("Inicia sesión con email y contraseña.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/refresh
        // ─────────────────────────────────────────────────────────
        group.MapPost("/refresh", async (
            RefreshRequest request,
            SessionOrchestrator session,
            CancellationToken ct) =>
        {
            var tokens = await session.RotateRefreshTokenAsync(request.RefreshToken, ct);

            if (tokens is null)
            {
                return Results.Json(
                    new { error = "invalid_token", message = "El token de actualización es inválido o ha expirado." },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new
            {
                accessToken = tokens.AccessToken,
                refreshToken = tokens.RefreshToken,
                expiresAt = tokens.ExpiresAt
            });
        })
        .WithName("RefreshToken")
        .WithDescription("Rota el Refresh Token y emite un nuevo par de tokens.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/logout
        // ─────────────────────────────────────────────────────────
        group.MapPost("/logout", async (
            LogoutRequest request,
            SessionOrchestrator session,
            CancellationToken ct) =>
        {
            await session.LogoutAsync(request.RefreshToken, ct);
            return Results.Ok(new { message = "Sesión cerrada exitosamente." });
        })
        .WithName("Logout")
        .WithDescription("Cierra la sesión actual revocando el Refresh Token.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/revoke-all
        // ─────────────────────────────────────────────────────────
        group.MapPost("/revoke-all", async (
            HttpContext context,
            SessionOrchestrator session,
            CancellationToken ct) =>
        {
            var userId = context.User.FindFirst("sub")?.Value
                         ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (userId is null)
            {
                return Results.Unauthorized();
            }

            await session.RevokeAllSessionsAsync(userId, ct);
            return Results.Ok(new { message = "Todas las sesiones han sido cerradas." });
        })
        .WithName("RevokeAllSessions")
        .WithDescription("Cierra todas las sesiones del usuario (botón de pánico).")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/forgot-password
        // ─────────────────────────────────────────────────────────
        /// <remarks>
        /// DIDÁCTICA: Este endpoint es "ciego". Siempre retorna 200 OK para evitar 
        /// ataques de enumeración (donde un atacante prueba emails para ver cuáles 
        /// están registrados). Además, verifica si el servicio está configurado 
        /// de forma segura para evitar excepciones en tiempo de ejecución.
        /// </remarks>
        group.MapPost("/forgot-password", async (
            ForgotPasswordRequest request,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<PasswordResetOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "password_reset_not_configured", message = "El restablecimiento de contraseña no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            await orchestrator.RequestPasswordResetAsync(request.Email, ct);
            
            // Siempre respondemos 200 OK independientemente de qué ocurrió en Orchestrator.
            return Results.Ok(new { message = "Si tu dirección existe en nuestro sistema, recibirás un correo con instrucciones." });
        })
        .WithName("ForgotPassword")
        .WithDescription("Solicita un enlace para restablecer la contraseña.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/reset-password
        // ─────────────────────────────────────────────────────────
        group.MapPost("/reset-password", async (
            ResetPasswordRequest request,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<PasswordResetOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "password_reset_not_configured", message = "El restablecimiento de contraseña no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var result = await orchestrator.ConfirmPasswordResetAsync(request.Token, request.NewPassword, ct);

            if (result == SecureCore.Auth.Abstractions.Models.PasswordResetResult.Success)
            {
                return Results.Ok(new { message = "Contraseña restablecida exitosamente. Por seguridad, todas tus sesiones han sido cerradas." });
            }

            return Results.Json(
                new { error = "invalid_token", message = "El enlace de restablecimiento es inválido o ha expirado." },
                statusCode: StatusCodes.Status400BadRequest);
        })
        .WithName("ResetPassword")
        .WithDescription("Confirma y actualiza la contraseña con un token válido.")
        .AllowAnonymous();

        return group;
    }
}

// ─────────────────────────────────────────────────────────
//  Request DTOs para los endpoints
// ─────────────────────────────────────────────────────────

/// <summary>
/// Solicitud de inicio de sesión.
/// </summary>
public record LoginRequest(string Email, string Password);

/// <summary>
/// Solicitud de rotación de Refresh Token.
/// </summary>
public record RefreshRequest(string RefreshToken);

/// <summary>
/// Solicitud de cierre de sesión.
/// </summary>
public record LogoutRequest(string RefreshToken);

/// <summary>
/// Solicitud de enlace para recuperar contraseña por email.
/// </summary>
public record ForgotPasswordRequest(string Email);

/// <summary>
/// Solicitud de inserción de nueva contraseña ligada a un token.
/// </summary>
public record ResetPasswordRequest(string Token, string NewPassword);
