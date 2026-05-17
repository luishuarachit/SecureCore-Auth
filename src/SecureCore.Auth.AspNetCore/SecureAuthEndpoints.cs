using System.ComponentModel.DataAnnotations;
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
            IRateLimiter rateLimiter,
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            // DIDÁCTICA: Rate limiting por IP antes de cualquier procesamiento.
            // Si la IP excede el límite, rechazamos inmediatamente.
            // Esto evita que un atacante use recursos del servidor para probar muchas cuentas.
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (!rateLimiter.IsAllowed(ipAddress))
            {
                return Results.Json(
                    new { error = "too_many_requests", message = "Demasiados intentos. Intenta más tarde." },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            var (result, tokens, mfaToken) = await orchestrator.SignInWithPasswordAsync(
                request.Email, request.Password, ct);

            if (result.Succeeded && tokens is not null)
            {
                // DIDÁCTICA: Reset del rate limit en login exitoso.
                // Importante para no penalizar al usuario legítimo.
                rateLimiter.Reset(ipAddress);

                return Results.Ok(new
                {
                    accessToken = tokens.AccessToken,
                    refreshToken = tokens.RefreshToken,
                    expiresAt = tokens.ExpiresAt
                });
            }

            if (result.RequiresTwoFactor || result.RequiresTwoFactorRegistration)
            {
                return Results.Ok(new
                {
                    requiresTwoFactor = true,
                    requiresTwoFactorRegistration = result.RequiresTwoFactorRegistration,
                    mfaSessionToken = mfaToken
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
            ISessionStore sessionStore,
            ITokenService tokenService,
            HttpContext context,
            CancellationToken ct) =>
        {
            // SEGURIDAD: Validar que el Refresh Token pertenece al usuario autenticado.
            // Esto previene que un usuario A revoque la sesión de usuario B (DoS/escalación).
            var userId = context.User.FindFirst("sub")?.Value
                         ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (userId is null)
            {
                return Results.Unauthorized();
            }

            // Hashear el token para buscar la entrada en la base de datos
            var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
            var entry = await sessionStore.FindByTokenHashAsync(tokenHash, ct);

            // SEGURIDAD: Si el token existe pero no pertenece al usuario autenticado, rechazar
            if (entry is not null && entry.UserId != userId)
            {
                // Log del intento malicioso
                System.Diagnostics.Debug.WriteLine(
                    $"INTENTO DE ESCALACIÓN: Usuario {userId} intentó revocar sesión del usuario {entry.UserId}");
                
                return Results.Forbid();  // 403 Forbidden
            }

            // Logout normal si el token pertenece al usuario autenticado
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
        // DIDÁCTICA: Este endpoint es "ciego". Siempre retorna 200 OK para evitar
        // ataques de enumeración (donde un atacante prueba emails para ver cuáles
        // están registrados). Además, verifica si el servicio está configurado
        // de forma segura para evitar excepciones en tiempo de ejecución.
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
/// <remarks>
/// DIDÁCTICA: Usamos data annotations para validación automática en Minimal APIs.
/// ASP.NET Core valida el request antes de ejecutar el handler del endpoint.
/// Si la validación falla, retorna 400 Bad Request automáticamente.
/// </remarks>
public record LoginRequest(
    [property: Required(ErrorMessage = "El email es requerido.")]
    [property: EmailAddress(ErrorMessage = "El email no tiene formato válido.")]
    string Email,

    [property: Required(ErrorMessage = "La contraseña es requerida.")]
    [property: MinLength(1, ErrorMessage = "La contraseña no puede estar vacía.")]
    string Password);

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
