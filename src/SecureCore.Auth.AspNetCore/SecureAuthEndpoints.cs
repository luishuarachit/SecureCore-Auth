using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
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
        //  GET /auth/me (F6, A-25 — perfil del usuario autenticado)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA (S6): expone de forma FRESCA (leído del store en cada llamada) el estado de
        // credenciales del usuario autenticado. hasPassword NO va en claims: un token emitido
        // antes de crear la contraseña mentiría tras el cambio; este endpoint lo lee al momento.
        // Es AUTENTICADO (solo la cuenta del token, sin riesgo de enumeración).
        group.MapGet("/me", async (
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var userStore = serviceProvider.GetService<IUserStore>();
            if (userStore is null)
            {
                return Results.Json(
                    new { error = "me_not_configured", message = "El perfil de usuario no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var user = await userStore.FindByIdAsync(userId, ct);
            if (user is null)
            {
                // DIDÁCTICA: usuario no encontrado → 401 genérico (sin oráculo).
                return Results.Unauthorized();
            }

            return Results.Ok(new MeResponse(
                user.Id,
                user.Email,
                user.PasswordHash is not null,
                user.TwoFactorEnabled,
                user.MfaEnrollmentStatus,
                user.PreferredMfaMethod));
        })
        .WithName("Me")
        .WithDescription("Perfil del usuario autenticado: hasPassword y estado MFA (F6, A-25).")
        .RequireAuthorization();

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

            // DIDÁCTICA (A-24): blacklist OPT-IN del access token actual. El logout de sesión
            // individual NO rota el SecurityStamp, por lo que el access token seguiría válido
            // hasta expirar. Si el host registró un ITokenBlacklist real, el jti del access token
            // se revoca con TTL = vida restante; con el default NoOpTokenBlacklist es un no-op.
            var blacklist = context.RequestServices.GetService<ITokenBlacklist>();
            var accessTokenInfo = TryReadAccessTokenJti(context.Request.Headers.Authorization.ToString());
            if (blacklist is not null && accessTokenInfo is not null &&
                !string.IsNullOrEmpty(accessTokenInfo.Value.Jti))
            {
                var remaining = accessTokenInfo.Value.ValidTo is { } validTo && validTo > DateTime.UtcNow
                    ? validTo - DateTime.UtcNow
                    : TimeSpan.Zero;
                if (remaining > TimeSpan.Zero)
                {
                    await blacklist.AddAsync(accessTokenInfo.Value.Jti, remaining, ct);
                }
            }

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
    /// Mapea los endpoints de recovery codes (F5, A-18/A-20) en la ruta especificada.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: es un mapper dedicado (no vive dentro de <c>MapSecureAuthEndpoints</c>) por dos
    /// razones. Primero, sigue el precedente de <c>MapSecureAuthWebAuthnEndpoints</c> (S4): cada
    /// subdominio opt-in de MFA agrupa sus rutas en su propio método para que el host controle
    /// exactamente qué expone. Segundo, los flujos <c>verify</c> y <c>use</c> son ANÓNIMOS pero
    /// tutelados: la cuenta se resuelve desde el <c>mfaSessionToken</c> del login en curso
    /// (mismo patrón que <c>IdentityOrchestrator.CompleteMfaLoginAsync</c>), nunca desde el cuerpo.
    ///
    /// El flujo de negocio sigue siendo del HOST: tras un <c>use</c> exitoso completará el login
    /// con ese mismo <c>mfaSessionToken</c> y, según su política, rotará el SecurityStamp (el
    /// evento <c>RecoveryCodeRedeemed</c> se emite precisamente para eso).
    ///
    /// Si <c>AddMfa()</c> no se usó (no hay <c>RecoveryCodeOrchestrator</c> registrado), todas
    /// las rutas responden 503 <c>recovery_codes_not_configured</c>.
    /// </remarks>
    /// <param name="endpoints">El builder de endpoints de la aplicación.</param>
    /// <param name="prefix">Prefijo de ruta (ej: "/auth/recovery-codes").</param>
    /// <returns>El grupo de endpoints creado.</returns>
    public static RouteGroupBuilder MapSecureAuthRecoveryCodesEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth/recovery-codes")
    {
        var group = endpoints.MapGroup(prefix);

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/generate (F5, A-20 — opt-in con MFA)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA: genera un lote nuevo de recovery codes y los devuelve en texto plano UNA
        // SOLA VEZ (el store solo persiste hashes SHA-256). Al regenerar, el lote anterior
        // queda invalidado por completo. Es un endpoint AUTENTICADO: quien genera códigos de
        // emergencia debe estar dentro de la cuenta. Si el orquestador no está registrado
        // (AddMfa) responde 503.
        group.MapPost("/generate", async (
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<RecoveryCodeOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "recovery_codes_not_configured", message = "Los códigos de recuperación no están configurados." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = httpContext.User.FindFirst("sub")?.Value
                         ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            var result = await orchestrator.GenerateAsync(userId, ct);
            if (result.Success && result.Codes is not null)
            {
                return Results.Ok(new
                {
                    message = "Guarda estos códigos: solo se muestran una vez.",
                    codes = result.Codes
                });
            }

            return Results.Json(
                new { error = "recovery_codes_disabled", message = result.ErrorMessage ?? "No se pudieron generar los códigos." },
                statusCode: StatusCodes.Status400BadRequest);
        })
        .WithName("GenerateRecoveryCodes")
        .WithDescription("Regenera los recovery codes de la cuenta autenticada (se muestran una sola vez).")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/verify (F5, A-20 — opt-in con MFA)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA: comprueba si un código es redimible SIN consumirlo. Es ANÓNIMO pero no
        // acepta un userId del cliente: la cuenta se resuelve desde el mfaSessionToken del
        // paso de login (mismo patrón que IdentityOrchestrator.CompleteMfaLoginAsync). Así un
        // atacante no puede probar códigos contra cuentas arbitrarias. NO distingue en la
        // respuesta "código inexistente" vs "ya consumido" vs "bloqueado" (anti-enumeración).
        group.MapPost("/verify", async (
            RecoveryCodeRedemptionRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<RecoveryCodeOrchestrator>();
            var mfaSessionStore = serviceProvider.GetService<IMfaSessionStore>();
            if (orchestrator is null || mfaSessionStore is null)
            {
                return Results.Json(
                    new { error = "recovery_codes_not_configured", message = "Los códigos de recuperación no están configurados." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            // DIDÁCTICA (B1, auditoría): verify es anónimo y cada intento ejecuta validación JWT
            // del mfaSessionToken (RS256/ES256) + lecturas al caché. Se limita por IP con el
            // presupuesto keyed "recovery-verify" ANTES de validar el token (el host sin
            // AddSecureAuth no registra el limiter → degradación elegante, sin 429).
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var verifyLimiter = serviceProvider.GetKeyedService<IRateLimiter>("recovery-verify");
            if (verifyLimiter is not null && !verifyLimiter.IsAllowed(ipAddress))
            {
                return Results.Json(
                    new { error = "too_many_requests", message = "Demasiados intentos. Intenta más tarde." },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            // DIDÁCTICA (no-enumeración): token inválido/código inválido se responden igual.
            var userId = await mfaSessionStore.ValidateMfaSessionTokenAsync(request.MfaSessionToken, ct);
            if (userId is null)
            {
                return Results.Json(new { valid = false });
            }

            var result = await orchestrator.VerifyAsync(userId, request.Code, ct);

            // DIDÁCTICA (B1): un verify exitoso resetea el presupuesto por IP (no penalizar al
            // usuario legítimo que completa el flujo, mismo patrón que /auth/login).
            if (result.IsValid)
            {
                verifyLimiter?.Reset(ipAddress);
            }

            return Results.Ok(new { valid = result.IsValid });
        })
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
        .WithName("VerifyRecoveryCode")
        .WithDescription("Comprueba si un recovery code es redimible sin consumirlo (anti-enumeración).")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/use (F5, A-20 — opt-in con MFA)
        // ─────────────────────────────────────────────────────────
        // DIDÁCTICA: consume el código de forma atómica (single-use) y emite el evento
        // RecoveryCodeRedeemed para que el HOST decida rotar el SecurityStamp o revocar
        // sesiones (el flujo de completar el login es patrón de negocio del consumidor).
        // El mfaSessionToken se valida SIN consumirse: el host lo usará en su flujo
        // CompleteMfaLoginAsync. Respuestas: 200 redimido, 429 bloqueado (sin detalles),
        // 400 código inválido (genérico).
        group.MapPost("/use", async (
            RecoveryCodeRedemptionRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<RecoveryCodeOrchestrator>();
            var mfaSessionStore = serviceProvider.GetService<IMfaSessionStore>();
            if (orchestrator is null || mfaSessionStore is null)
            {
                return Results.Json(
                    new { error = "recovery_codes_not_configured", message = "Los códigos de recuperación no están configurados." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            // DIDÁCTICA (B1, auditoría): use consume el single-use y el presupuesto S1 por cuenta;
            // es el endpoint más sensible del flujo. Presupuesto por IP keyed "recovery-use" (5/min
            // por defecto) ANTES de validar el token o tocar el store. Sin AddSecureAuth no hay
            // limiter registrado → degradación elegante.
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var useLimiter = serviceProvider.GetKeyedService<IRateLimiter>("recovery-use");
            if (useLimiter is not null && !useLimiter.IsAllowed(ipAddress))
            {
                return Results.Json(
                    new { error = "too_many_requests", message = "Demasiados intentos. Intenta más tarde." },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            var userId = await mfaSessionStore.ValidateMfaSessionTokenAsync(request.MfaSessionToken, ct);
            if (userId is null)
            {
                return Results.Json(
                    new { error = "invalid_code", message = "Código inválido." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var result = await orchestrator.UseAsync(userId, request.Code, ct);
            if (result.Success)
            {
                // DIDÁCTICA (B1): reset del presupuesto por IP en éxito (no penalizar al legítimo).
                useLimiter?.Reset(ipAddress);

                return Results.Ok(new
                {
                    redeemed = true,
                    message = "Código redimido. Rota tu SecurityStamp si sospechas que tus códigos fueron comprometidos."
                });
            }

            if (result.LockedOut)
            {
                return Results.Json(
                    new { error = "too_many_attempts", message = result.ErrorMessage },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            return Results.Json(
                new { error = "invalid_code", message = result.ErrorMessage ?? "Código inválido." },
                statusCode: StatusCodes.Status400BadRequest);
        })
        .AddEndpointFilter(EnforceAnonymousRequestSizeLimit)
        .WithName("UseRecoveryCode")
        .WithDescription("Consume un recovery code (single-use atómico) y emite RecoveryCodeRedeemed.")
        .AllowAnonymous();

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

    /// <summary>
    /// Extrae el jti y la expiración de un access token del header Authorization (A-24).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: se usa <c>ReadJwtToken</c> (parseo SIN validación de firma/vida) solo para
    /// obtener el <c>jti</c> y el <c>ValidTo</c> en el logout; la validación real ya la hizo el
    /// middleware JWT al autenticar la request. Tokens malformados o ausentes → null (sin
    /// excepción). El TTL de blacklist se acota a la vida restante del token.
    /// </remarks>
    private static (string Jti, DateTime? ValidTo)? TryReadAccessTokenJti(string? authorizationHeader)
    {
        if (string.IsNullOrWhiteSpace(authorizationHeader) ||
            !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        try
        {
            var token = new JwtSecurityTokenHandler().ReadJwtToken(
                authorizationHeader["Bearer ".Length..].Trim());
            var jti = token.Id;
            return string.IsNullOrEmpty(jti) ? null : (jti, token.ValidTo);
        }
        catch (ArgumentException)
        {
            return null;
        }
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

/// <summary>
/// Solicitud de verificación/redención de un recovery code (F5, A-20).
/// </summary>
/// <remarks>
/// DIDÁCTICA: la cuenta se resuelve desde el <c>mfaSessionToken</c> del paso de login (nunca
/// desde un userId del cliente) para impedir probar códigos contra cuentas arbitrarias. El
/// token se valida SIN consumirse: el host lo reutiliza en su flujo CompleteMfaLoginAsync.
/// </remarks>
public record RecoveryCodeRedemptionRequest(
    [property: Required(ErrorMessage = "El token de sesión MFA es requerido.")]
    string MfaSessionToken,

    [property: Required(ErrorMessage = "El código de recuperación es requerido.")]
    [property: MaxLength(128, ErrorMessage = "El código no puede superar 128 caracteres.")]
    string Code);

/// <summary>
/// Respuesta del perfil del usuario autenticado (F6, A-25).
/// </summary>
/// <remarks>
/// DIDÁCTICA: es un endpoint AUTENTICADO (solo la cuenta del token). <c>HasPassword</c> se lee
/// del store en cada llamada (nunca de un claim, que mentiría tras crear la contraseña). No
/// expone datos sensibles: es la propia cuenta del usuario consultando su estado.
/// </remarks>
/// <param name="Id">Identificador del usuario (claim sub).</param>
/// <param name="Email">Email del usuario.</param>
/// <param name="HasPassword">true si la cuenta tiene contraseña registrada (nullable de primera clase).</param>
/// <param name="TwoFactorEnabled">true si la cuenta tiene 2FA habilitado.</param>
/// <param name="MfaEnrollmentStatus">Estado del enrollment MFA.</param>
/// <param name="PreferredMfaMethod">Método MFA preferido (totp/email), si existe.</param>
public record MeResponse(
    string Id,
    string? Email,
    bool HasPassword,
    bool TwoFactorEnabled,
    MfaEnrollmentStatus MfaEnrollmentStatus,
    string? PreferredMfaMethod);
