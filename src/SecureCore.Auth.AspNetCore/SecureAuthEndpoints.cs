using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
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
            IAuthEventDispatcher eventDispatcher,
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            // DIDÁCTICA: Rate limiting por IP antes de cualquier procesamiento.
            // Si la IP excede el límite, rechazamos inmediatamente.
            // Esto evita que un atacante use recursos del servidor para probar muchas cuentas.
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (!rateLimiter.IsAllowed(ipAddress))
            {
                await eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
                {
                    EventType = Abstractions.Models.AuthEventType.RateLimitExceeded,
                    TimestampUtc = DateTime.UtcNow
                }, ct);

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
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
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
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
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
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<PasswordResetOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "password_reset_not_configured", message = "El restablecimiento de contraseña no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            // DIDÁCTICA (Nº5): Throttling por IP SILENCIOSO. A diferencia de /login, aquí NO
            // se responde 429: el endpoint sigue devolviendo el 200 ciego para no revelar al
            // atacante cuándo se le limita (evita oráculos extra y feedback de throttling).
            // Al superarse el presupuesto la solicitud simplemente se descarta. Usamos un
            // limiter dedicado (keyed "forgot-password") para no compartir el presupuesto
            // con el de login.
            var limiter = serviceProvider.GetRequiredKeyedService<IRateLimiter>("forgot-password");
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (!limiter.IsAllowed("forgot-password:" + ipAddress))
            {
                return Results.Ok(new { message = "Si tu dirección existe en nuestro sistema, recibirás un correo con instrucciones." });
            }

            await orchestrator.RequestPasswordResetAsync(request.Email, ct);

            // Siempre respondemos 200 OK independientemente de qué ocurrió en Orchestrator.
            return Results.Ok(new { message = "Si tu dirección existe en nuestro sistema, recibirás un correo con instrucciones." });
        })
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
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
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
        .WithName("ResetPassword")
        .WithDescription("Confirma y actualiza la contraseña con un token válido.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/verify-action/send (S3, step-up opt-in)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA: Endpoint autenticado para solicitar el OTP de verify-action. Si el
        // orquestador no está registrado responde 503. Los fallos reportan mensajes genéricos
        // (no-enumeración, sin revelar si el usuario existe o si el envío falló).
        group.MapPost("/verify-action/send", async (
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<VerifyActionOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "verify_action_not_configured", message = "La verificación de acciones sensibles no está configurada." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var result = await orchestrator.SendVerifyCodeAsync(userId, cancellationToken: ct);

            if (result.Success)
            {
                return Results.Ok(new { message = "Se envió un código de verificación a tu correo." });
            }

            return Results.Json(
                new { error = "verify_action_send_failed", message = result.ErrorMessage ?? "No se pudo enviar el código." },
                statusCode: StatusCodes.Status400BadRequest);
        })
        .WithName("SendVerifyActionCode")
        .WithDescription("Solicita un código OTP de verify-action para una acción sensible.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/verify-action/verify (S3, step-up opt-in)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/verify-action/verify", async (
            VerifyActionRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<VerifyActionOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "verify_action_not_configured", message = "La verificación de acciones sensibles no está configurada." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var result = await orchestrator.VerifyActionAsync(userId, request.Code, ct);

            if (result.Success)
            {
                return Results.Ok(new { verified = true });
            }

            return Results.Json(
                new { verified = false, error = "invalid_code", message = result.ErrorMessage ?? "Código inválido." },
                statusCode: StatusCodes.Status400BadRequest);
        })
        .WithName("VerifyActionCode")
        .WithDescription("Valida el código OTP y marca la sesión como verify-action verificada.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/create-password (S3, A-22 opt-in)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA: crea la contraseña de una cuenta passwordless exigiendo la ventana de
        // verify-action ABIERTA (paso previo: POST /verify-action/send + POST /verify-action/verify).
        // El OTP se consume en ese paso (M1, auditoría); aquí solo se comprueba la ventana. Al
        // rotar el SecurityStamp, el access token usado en ESTA petición queda revocado al salir;
        // por eso la respuesta incluye el nuevo par de tokens, que el cliente debe adoptar.
        group.MapPost("/create-password", async (
            CreatePasswordRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<ChangePasswordOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "change_password_not_configured", message = "El flujo de contraseña no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var result = await orchestrator.CreateAsync(userId, request.NewPassword, ct);
            return MapPasswordChangeResult(result);
        })
        .WithName("CreatePassword")
        .WithDescription("Crea la contraseña de una cuenta sin ella, exigiendo una verificación previa de verify-action.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST /auth/change-password (S3, A-22 opt-in)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/change-password", async (
            ChangePasswordRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<ChangePasswordOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "change_password_not_configured", message = "El flujo de contraseña no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var result = await orchestrator.ChangeAsync(userId, request.CurrentPassword, request.NewPassword, ct);
            return MapPasswordChangeResult(result);
        })
        .WithName("ChangePassword")
        .WithDescription("Cambia la contraseña validando la actual; revoca las sesiones previas.")
        .RequireAuthorization();

        return group;
    }

    /// <summary>
    /// Traduce un ChangePasswordResult a una respuesta HTTP con tokens (éxito) o error genérico.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Los mensajes provienen del orquestador y ya son genéricos; el código de error
    /// permite al host distinguir la rama programáticamente. El éxito incluye el nuevo par de
    /// tokens porque la rotación del SecurityStamp revocó el token usado para esta petición.
    /// </remarks>
    private static IResult MapPasswordChangeResult(ChangePasswordResult result)
    {
        if (result.Success && result.Tokens is not null)
        {
            return Results.Ok(new
            {
                message = "Contraseña actualizada. El resto de sesiones fueron cerradas.",
                accessToken = result.Tokens.AccessToken,
                refreshToken = result.Tokens.RefreshToken,
                expiresAt = result.Tokens.ExpiresAt
            });
        }

        return Results.Json(
            new { error = result.ErrorCode ?? Abstractions.Models.ChangePasswordError.GenericFailure, message = result.ErrorMessage },
            statusCode: StatusCodes.Status400BadRequest);
    }

    /// <summary>
    /// Endpoint filter que acota el tamaño máximo del cuerpo de las solicitudes
    /// en los endpoints de autenticación anónimos.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: En Minimal APIs el binding del cuerpo ocurre ANTES de que se ejecuten
    /// los endpoint filters, por lo que un filter NO puede rechazar el body vía
    /// <c>IHttpMaxRequestBodySizeFeature</c> (Kestrel ya habría leído el payload).
    /// La protección real la aporta el middleware <c>UseSecureAuthRequestSizeLimit</c>,
    /// que asigna la feature ANTES del binding.
    ///
    /// Este filtro es complementario: descarta de forma rápida (por Content-Length, sin
    /// leer el cuerpo) cualquier payload VÁLIDO que supere el límite, devolviendo 413 JSON
    /// a nivel de aplicación. Además es verificable en TestServer, donde el límite físico
    /// del servidor no siempre está disponible.
    ///
    /// Lo resolvemos por request desde <c>RequestServices</c> para no capturar opciones en
    /// tiempo de mapeo (las opciones se configuran de forma diferida).
    /// </remarks>
    private static async ValueTask<object?> EnforceAnonymousRequestSizeLimit(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var options = context.HttpContext.RequestServices
            .GetRequiredService<IOptions<SecureAuthOptions>>().Value;
        var limit = options.MaxAuthRequestBodySize;

        // DIDÁCTICA: Los endpoint filters se ejecutan DESPUÉS del binding de parámetros
        // (reciben los argumentos ya enlazados). Por tanto, un cuerpo malformado será
        // rechazado por el JSON binder con 400 antes de llegar aquí: igualmente queda
        // bloqueado. Lo que este filtro garantiza es que un cuerpo VÁLIDO pero superior
        // al límite (Content-Length conocido) se rechace con 413 sin procesarse.
        //
        // Para cuerpos en chunked (sin Content-Length) la barrera física la pone el
        // middleware UseSecureAuthRequestSizeLimit via IHttpMaxRequestBodySizeFeature
        // (Kestrel responde 413 al leer el body). Este filtro añade defensa en profundidad
        // a nivel de aplicación, también verificable en TestServer.
        var contentLength = context.HttpContext.Request.ContentLength;
        if (contentLength is not null && contentLength.Value > limit)
        {
            return Results.Json(
                new { error = "payload_too_large", message = "El cuerpo de la solicitud excede el límite permitido." },
                statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        return await next(context);
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

/// <summary>
/// Solicitud de validateación del código OTP de verify-action (S3).
/// </summary>
/// <remarks>
/// DIDÁCTICA (H3): además del mínimo, fijamos un máximo de 8 dígitos (límite superior de
/// <c>VerifyActionOptions.CodeLength</c>) para rechazar en binding cuerpos absurdos antes
/// de que lleguen al hash/store del orquestador.
/// </remarks>
public record VerifyActionRequest(
    [property: Required(ErrorMessage = "El código es requerido.")]
    [property: MinLength(6, ErrorMessage = "El código debe tener al menos 6 dígitos.")]
    [property: MaxLength(8, ErrorMessage = "El código no puede superar 8 dígitos.")]
    string Code);

/// <summary>
/// Solicitud de creación de contraseña con ventana de verify-action previa (S3, A-22).
/// </summary>
/// <remarks>
/// DIDÁCTICA (M1, auditoría): NO se incluye OTP en el cuerpo. El código ya se consumió en
/// POST /verify-action/verify (single-use atómico); crear la contraseña solo requiere que
/// la ventana mfa_verified siga abierta.
/// </remarks>
public record CreatePasswordRequest(
    [property: Required(ErrorMessage = "La nueva contraseña es requerida.")]
    [property: MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña no puede superar 1024 caracteres.")]
    string NewPassword);

/// <summary>
/// Solicitud de cambio de contraseña validando la contraseña actual (S3, A-22).
/// </summary>
/// <remarks>
/// DIDÁCTICA (H3, auditoría): la contraseña actual se acota a 1024 caracteres en el binding
/// (y de nuevo en el orquestador) para impedir la amplificación de Argon2 con inputs gigantes.
/// </remarks>
public record ChangePasswordRequest(
    [property: Required(ErrorMessage = "La contraseña actual es requerida.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña actual no puede superar 1024 caracteres.")]
    string CurrentPassword,

    [property: Required(ErrorMessage = "La nueva contraseña es requerida.")]
    [property: MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña no puede superar 1024 caracteres.")]
    string NewPassword);
