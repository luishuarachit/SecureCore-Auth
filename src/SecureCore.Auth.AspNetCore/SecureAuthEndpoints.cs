using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
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
/// Endpoints opcionales de autenticación como Minimal APIs de ASP.NET Core (kit componible, F7).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F7, A-26): cada feature es un HANDLER público reutilizable + un DESCRIPTOR
/// declarativo; los mappers solo componen descriptores. El host puede:
/// - Mapear solo las features que quiere (mappers por grupo).
/// - Re-rutear cualquier handler a su propia ruta/verbo: <c>app.MapPost("/custom", SecureAuthEndpoints.LoginHandler)</c>.
/// - Reutilizar los filtros de protección (<c>EnforceAnonymousRequestSizeLimit</c>).
/// <c>MapSecureAuthEndpoints</c> sigue siendo la composición de TODAS las features (no-breaking).
/// </remarks>
public static class SecureAuthEndpoints
{
    // HANDLERS PÚBLICOS (un delegate por feature). DIDÁCTICA (F7): el handler solo traduce
    // request → orquestador → IResult (SRP); depende de abstracciones que la DI resuelve (DIP).

    /// <summary>Handler de <c>POST /login</c> (rate limit por IP + SignInWithPasswordAsync).</summary>
    public static readonly Func<LoginRequest, IdentityOrchestrator, IRateLimiter, IAuthEventDispatcher, HttpContext, CancellationToken, Task<IResult>> LoginHandler = async (
        LoginRequest request,
        IdentityOrchestrator orchestrator,
        IRateLimiter rateLimiter,
        IAuthEventDispatcher eventDispatcher,
        HttpContext httpContext,
        CancellationToken ct) =>
    {
        // DIDÁCTICA (F8): protección de tamaño intrínseca (viaja con el handler re-ruteado).
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

        var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!rateLimiter.IsAllowed(ipAddress))
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.RateLimitExceeded,
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

        return Results.Json(
            new { error = "invalid_credentials", message = result.Message },
            statusCode: StatusCodes.Status401Unauthorized);
    };

    /// <summary>Handler de <c>GET /me</c> — perfil del usuario autenticado (F6, A-25).</summary>
    public static readonly Func<HttpContext, IServiceProvider, CancellationToken, Task<IResult>> MeHandler = async (
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
            return Results.Unauthorized();
        }

        return Results.Ok(new MeResponse(
            user.Id,
            user.Email,
            user.PasswordHash is not null,
            user.TwoFactorEnabled,
            user.MfaEnrollmentStatus,
            user.PreferredMfaMethod));
    };

    /// <summary>Handler de <c>POST /refresh</c> — rotación de Refresh Token (RTR).</summary>
    public static readonly Func<RefreshRequest, SessionOrchestrator, HttpContext, CancellationToken, Task<IResult>> RefreshHandler = async (
        RefreshRequest request,
        SessionOrchestrator session,
        HttpContext httpContext,
        CancellationToken ct) =>
    {
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

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
    };

    /// <summary>Handler de <c>POST /logout</c> — revoca el refresh + blacklista el jti (A-24).</summary>
    public static readonly Func<LogoutRequest, SessionOrchestrator, ISessionStore, ITokenService, HttpContext, CancellationToken, Task<IResult>> LogoutHandler = async (
        LogoutRequest request,
        SessionOrchestrator session,
        ISessionStore sessionStore,
        ITokenService tokenService,
        HttpContext context,
        CancellationToken ct) =>
    {
        var userId = context.User.FindFirst("sub")?.Value
                     ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        if (userId is null)
        {
            return Results.Unauthorized();
        }

        var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
        var entry = await sessionStore.FindByTokenHashAsync(tokenHash, ct);

        if (entry is not null && entry.UserId != userId)
        {
            return Results.Forbid();
        }

        await session.LogoutAsync(request.RefreshToken, ct);

        // DIDÁCTICA (A-24): blacklist OPT-IN del access token actual (jti con TTL = vida restante).
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
    };

    /// <summary>Handler de <c>POST /revoke-all</c> — cierre global de sesiones (botón de pánico).</summary>
    public static readonly Func<HttpContext, SessionOrchestrator, CancellationToken, Task<IResult>> RevokeAllHandler = async (
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
    };

    /// <summary>Handler de <c>POST /forgot-password</c> — solicitud de reset (200 ciego).</summary>
    public static readonly Func<ForgotPasswordRequest, IServiceProvider, HttpContext, CancellationToken, Task<IResult>> ForgotPasswordHandler = async (
        ForgotPasswordRequest request,
        IServiceProvider serviceProvider,
        HttpContext httpContext,
        CancellationToken ct) =>
    {
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

        var orchestrator = serviceProvider.GetService<PasswordResetOrchestrator>();
        if (orchestrator is null)
        {
            return Results.Json(
                new { error = "password_reset_not_configured", message = "El restablecimiento de contraseña no está configurado." },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        // DIDÁCTICA (Nº5): throttling por IP SILENCIOSO (siempre 200 ciego, sin oráculo).
        var limiter = serviceProvider.GetRequiredKeyedService<IRateLimiter>("forgot-password");
        var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!limiter.IsAllowed("forgot-password:" + ipAddress))
        {
            return Results.Ok(new { message = "Si tu dirección existe en nuestro sistema, recibirás un correo con instrucciones." });
        }

        await orchestrator.RequestPasswordResetAsync(request.Email, ct);

        return Results.Ok(new { message = "Si tu dirección existe en nuestro sistema, recibirás un correo con instrucciones." });
    };

    /// <summary>Handler de <c>POST /reset-password</c> — confirmación con token.</summary>
    public static readonly Func<ResetPasswordRequest, IServiceProvider, HttpContext, CancellationToken, Task<IResult>> ResetPasswordHandler = async (
        ResetPasswordRequest request,
        IServiceProvider serviceProvider,
        HttpContext httpContext,
        CancellationToken ct) =>
    {
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

        var orchestrator = serviceProvider.GetService<PasswordResetOrchestrator>();
        if (orchestrator is null)
        {
            return Results.Json(
                new { error = "password_reset_not_configured", message = "El restablecimiento de contraseña no está configurado." },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        var result = await orchestrator.ConfirmPasswordResetAsync(request.Token, request.NewPassword, ct);

        if (result == PasswordResetResult.Success)
        {
            return Results.Ok(new { message = "Contraseña restablecida exitosamente. Por seguridad, todas tus sesiones han sido cerradas." });
        }

        return Results.Json(
            new { error = "invalid_token", message = "El enlace de restablecimiento es inválido o ha expirado." },
            statusCode: StatusCodes.Status400BadRequest);
    };

    /// <summary>Handler de <c>POST /verify-action/send</c> — envía el OTP de step-up (S3).</summary>
    public static readonly Func<HttpContext, IServiceProvider, CancellationToken, Task<IResult>> VerifyActionSendHandler = async (
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
    };

    /// <summary>Handler de <c>POST /verify-action/verify</c> — consume el OTP de step-up (S3).</summary>
    public static readonly Func<VerifyActionRequest, HttpContext, IServiceProvider, CancellationToken, Task<IResult>> VerifyActionVerifyHandler = async (
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
    };

    /// <summary>Handler de <c>POST /create-password</c> — crea contraseña (requiere step-up, S3).</summary>
    public static readonly Func<CreatePasswordRequest, HttpContext, IServiceProvider, CancellationToken, Task<IResult>> CreatePasswordHandler = async (
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
    };

    /// <summary>Handler de <c>POST /change-password</c> — cambia contraseña validando la actual (S3).</summary>
    public static readonly Func<ChangePasswordRequest, HttpContext, IServiceProvider, CancellationToken, Task<IResult>> ChangePasswordHandler = async (
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
    };

    // ─────────────────────────────────────────────────────────
    //  Recovery codes (F5, A-20) — handlers públicos
    // ─────────────────────────────────────────────────────────

    /// <summary>Handler de <c>POST /generate</c> — regenera el lote y lo muestra una sola vez.</summary>
    public static readonly Func<HttpContext, IServiceProvider, CancellationToken, Task<IResult>> GenerateRecoveryCodesHandler = async (
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
    };

    /// <summary>Handler de <c>POST /verify</c> — comprueba si un código es redimible sin consumirlo.</summary>
    public static readonly Func<RecoveryCodeRedemptionRequest, HttpContext, IServiceProvider, CancellationToken, Task<IResult>> VerifyRecoveryCodeHandler = async (
        RecoveryCodeRedemptionRequest request,
        HttpContext httpContext,
        IServiceProvider serviceProvider,
        CancellationToken ct) =>
    {
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

        var orchestrator = serviceProvider.GetService<RecoveryCodeOrchestrator>();
        var mfaSessionStore = serviceProvider.GetService<IMfaSessionStore>();
        if (orchestrator is null || mfaSessionStore is null)
        {
            return Results.Json(
                new { error = "recovery_codes_not_configured", message = "Los códigos de recuperación no están configurados." },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        // DIDÁCTICA (B1, auditoría): limiter por IP keyed "recovery-verify" antes de validar el token.
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

        if (result.IsValid)
        {
            verifyLimiter?.Reset(ipAddress);
        }

        return Results.Ok(new { valid = result.IsValid });
    };

    /// <summary>Handler de <c>POST /use</c> — consume el código (single-use atómico, F5).</summary>
    public static readonly Func<RecoveryCodeRedemptionRequest, HttpContext, IServiceProvider, CancellationToken, Task<IResult>> UseRecoveryCodeHandler = async (
        RecoveryCodeRedemptionRequest request,
        HttpContext httpContext,
        IServiceProvider serviceProvider,
        CancellationToken ct) =>
    {
        var sizeBlocked = CheckAnonymousBodySize(httpContext);
        if (sizeBlocked is not null)
        {
            return sizeBlocked;
        }

        var orchestrator = serviceProvider.GetService<RecoveryCodeOrchestrator>();
        var mfaSessionStore = serviceProvider.GetService<IMfaSessionStore>();
        if (orchestrator is null || mfaSessionStore is null)
        {
            return Results.Json(
                new { error = "recovery_codes_not_configured", message = "Los códigos de recuperación no están configurados." },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        // DIDÁCTICA (B1, auditoría): limiter por IP keyed "recovery-use" (5/min por defecto).
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
    };

    // ─────────────────────────────────────────────────────────
    //  DESCRIPTORES (dato) — OCP: feature nueva = descriptor nuevo
    // ─────────────────────────────────────────────────────────

    private static AuthEndpointDescriptor Login() => new(
        HttpMethod.Post, "/login", LoginHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "Login", Description: "Inicia sesión con email y contraseña.");

    private static AuthEndpointDescriptor Me() => new(
        HttpMethod.Get, "/me", MeHandler,
        RequiresAuthorization: true,
        Name: "Me", Description: "Perfil del usuario autenticado: hasPassword y estado MFA (F6, A-25).");

    private static AuthEndpointDescriptor Refresh() => new(
        HttpMethod.Post, "/refresh", RefreshHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "Refresh", Description: "Rota el Refresh Token y emite un nuevo par.");

    private static AuthEndpointDescriptor Logout() => new(
        HttpMethod.Post, "/logout", LogoutHandler,
        RequiresAuthorization: true,
        Name: "Logout", Description: "Cierra la sesión actual revocando el Refresh Token.");

    private static AuthEndpointDescriptor RevokeAll() => new(
        HttpMethod.Post, "/revoke-all", RevokeAllHandler,
        RequiresAuthorization: true,
        Name: "RevokeAllSessions", Description: "Cierra todas las sesiones del usuario (botón de pánico).");

    private static AuthEndpointDescriptor ForgotPassword() => new(
        HttpMethod.Post, "/forgot-password", ForgotPasswordHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "ForgotPassword", Description: "Solicita un enlace para restablecer la contraseña.");

    private static AuthEndpointDescriptor ResetPassword() => new(
        HttpMethod.Post, "/reset-password", ResetPasswordHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "ResetPassword", Description: "Confirma y actualiza la contraseña con un token válido.");

    private static AuthEndpointDescriptor VerifyActionSend() => new(
        HttpMethod.Post, "/verify-action/send", VerifyActionSendHandler,
        RequiresAuthorization: true,
        Name: "SendVerifyActionCode", Description: "Solicita un código OTP de verify-action para una acción sensible.");

    private static AuthEndpointDescriptor VerifyActionVerify() => new(
        HttpMethod.Post, "/verify-action/verify", VerifyActionVerifyHandler,
        RequiresAuthorization: true,
        Name: "VerifyActionCode", Description: "Valida el código OTP y marca la sesión como verify-action verificada.");

    private static AuthEndpointDescriptor CreatePassword() => new(
        HttpMethod.Post, "/create-password", CreatePasswordHandler,
        RequiresAuthorization: true,
        Name: "CreatePassword", Description: "Crea la contraseña de una cuenta sin ella, exigiendo una verificación previa de verify-action.");

    private static AuthEndpointDescriptor ChangePassword() => new(
        HttpMethod.Post, "/change-password", ChangePasswordHandler,
        RequiresAuthorization: true,
        Name: "ChangePassword", Description: "Cambia la contraseña validando la actual; revoca las sesiones previas.");

    private static AuthEndpointDescriptor GenerateRecoveryCodes() => new(
        HttpMethod.Post, "/generate", GenerateRecoveryCodesHandler,
        RequiresAuthorization: true,
        Name: "GenerateRecoveryCodes", Description: "Regenera los recovery codes de la cuenta autenticada (se muestran una sola vez).");

    private static AuthEndpointDescriptor VerifyRecoveryCode() => new(
        HttpMethod.Post, "/verify", VerifyRecoveryCodeHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "VerifyRecoveryCode", Description: "Comprueba si un recovery code es redimible sin consumirlo (anti-enumeración).");

    private static AuthEndpointDescriptor UseRecoveryCode() => new(
        HttpMethod.Post, "/use", UseRecoveryCodeHandler,
        RequiresAuthorization: false,
        Configure: b => b.AddEndpointFilter(EnforceAnonymousRequestSizeLimit),
        Name: "UseRecoveryCode", Description: "Consume un recovery code (single-use atómico) y emite RecoveryCodeRedeemed.");

    // ─────────────────────────────────────────────────────────
    //  MAPPERS (composición) — SRP: solo registran descriptores
    // ─────────────────────────────────────────────────────────

    /// <summary>
    /// Compositor genérico del kit (F7, A-26): registra los descriptores indicados bajo un prefijo.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: es la ÚNICA mecánica de registro. Los mappers <c>MapSecureAuth*</c> son wrappers
    /// que seleccionan descriptores. Aplica autorización/anonymous, filtros, nombre y descripción
    /// de cada descriptor (comportamiento idéntico al mapeo inline previo).
    /// </remarks>
    public static RouteGroupBuilder MapAuthEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix,
        string? tag = "SecureCore Auth",
        params AuthEndpointDescriptor[] descriptors)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(descriptors);

        var group = endpoints.MapGroup(prefix).WithTags(tag ?? "SecureCore Auth");

        foreach (var descriptor in descriptors)
        {
            var builder = group.MapMethods(descriptor.RouteTemplate, [descriptor.Method.Method], descriptor.Handler);

            if (descriptor.RequiresAuthorization)
            {
                builder.RequireAuthorization();
            }
            else
            {
                builder.AllowAnonymous();
            }

            descriptor.Configure?.Invoke(builder);

            if (descriptor.Name is not null)
            {
                builder.WithName(descriptor.Name);
            }

            if (descriptor.Description is not null)
            {
                builder.WithDescription(descriptor.Description);
            }
        }

        return group;
    }

    /// <summary>
    /// Mapea TODOS los endpoints del bundle (composición de descriptores, comportamiento idéntico).
    /// </summary>
    public static RouteGroupBuilder MapSecureAuthEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        return endpoints.MapAuthEndpoints(prefix, null, AllDescriptors);
    }

    /// <summary>Mapea solo sesión: login, me, refresh, logout, revoke-all.</summary>
    public static RouteGroupBuilder MapSecureAuthSessionEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
        => endpoints.MapAuthEndpoints(prefix, null, SessionDescriptors);

    /// <summary>Mapea solo recuperación de contraseña: forgot-password, reset-password.</summary>
    public static RouteGroupBuilder MapSecureAuthPasswordResetEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
        => endpoints.MapAuthEndpoints(prefix, null, PasswordResetDescriptors);

    /// <summary>Mapea solo credenciales: create-password, change-password.</summary>
    public static RouteGroupBuilder MapSecureAuthCredentialEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
        => endpoints.MapAuthEndpoints(prefix, null, CredentialDescriptors);

    /// <summary>Mapea solo step-up: verify-action/send, verify-action/verify.</summary>
    public static RouteGroupBuilder MapSecureAuthVerifyActionEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth")
        => endpoints.MapAuthEndpoints(prefix, null, VerifyActionDescriptors);

    /// <summary>
    /// Mapea los endpoints de recovery codes (F5, A-18/A-20).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (F7): ahora también es un wrapper del kit — los handlers son públicos
    /// (<c>GenerateRecoveryCodesHandler</c>, <c>VerifyRecoveryCodeHandler</c>, <c>UseRecoveryCodeHandler</c>)
    /// y el host puede re-rutearlos o componer su propia superficie.
    /// </remarks>
    public static RouteGroupBuilder MapSecureAuthRecoveryCodesEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth/recovery-codes")
        => endpoints.MapAuthEndpoints(prefix, null, RecoveryDescriptors);

    // ─────────────────────────────────────────────────────────
    //  GRUPOS (arrays de descriptores; rutas relativas al prefijo)
    // ─────────────────────────────────────────────────────────

    private static readonly AuthEndpointDescriptor[] SessionDescriptors =
        [Login(), Me(), Refresh(), Logout(), RevokeAll()];

    private static readonly AuthEndpointDescriptor[] PasswordResetDescriptors =
        [ForgotPassword(), ResetPassword()];

    private static readonly AuthEndpointDescriptor[] CredentialDescriptors =
        [CreatePassword(), ChangePassword()];

    private static readonly AuthEndpointDescriptor[] VerifyActionDescriptors =
        [VerifyActionSend(), VerifyActionVerify()];

    private static readonly AuthEndpointDescriptor[] RecoveryDescriptors =
        [GenerateRecoveryCodes(), VerifyRecoveryCode(), UseRecoveryCode()];

    private static readonly AuthEndpointDescriptor[] AllDescriptors =
        [.. SessionDescriptors, .. PasswordResetDescriptors, .. CredentialDescriptors, .. VerifyActionDescriptors];

    // ─────────────────────────────────────────────────────────
    //  HELPERS PRIVADOS
    // ─────────────────────────────────────────────────────────

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
    /// Endpoint filter PÚBLICO que acota el tamaño del cuerpo de endpoints anónimos (A-10).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (F7): es público para que el host lo reutilice en su propia superficie compuesta.
    /// En Minimal APIs los filters se ejecutan DESPUÉS del binding; la barrera física real la pone
    /// el middleware <c>UseSecureAuthRequestSizeLimit</c>. Este filtro descarta por Content-Length
    /// los payloads válidos que superan <c>MaxAuthRequestBodySize</c> (413 JSON).
    /// </remarks>
    public static async ValueTask<object?> EnforceAnonymousRequestSizeLimit(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        var options = context.HttpContext.RequestServices
            .GetRequiredService<IOptions<SecureAuthOptions>>().Value;
        var limit = options.MaxAuthRequestBodySize;

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
    /// Comprueba el tamaño del cuerpo de una request anónima (F8, limitación C).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (F8): los handlers anónimos se protegen A SÍ MISMOS (check de Content-Length >
    /// <c>MaxAuthRequestBodySize</c>) para que la protección viaje con el handler a cualquier ruta
    /// re-ruteada por el host. El filtro público <c>EnforceAnonymousRequestSizeLimit</c> se conserva
    /// como utilidad y defensa en profundidad en los descriptores.
    /// </remarks>
    private static IResult? CheckAnonymousBodySize(HttpContext httpContext)
    {
        var options = httpContext.RequestServices
            .GetRequiredService<IOptions<SecureAuthOptions>>().Value;
        var contentLength = httpContext.Request.ContentLength;
        return contentLength is not null && contentLength.Value > options.MaxAuthRequestBodySize
            ? Results.Json(
                new { error = "payload_too_large", message = "El cuerpo de la solicitud excede el límite permitido." },
                statusCode: StatusCodes.Status413PayloadTooLarge)
            : null;
    }

    /// <summary>
    /// Extrae el jti y la expiración de un access token del header Authorization (A-24).
    /// </summary>
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
public record LoginRequest(
    [property: Required(ErrorMessage = "El email es requerido.")]
    [property: EmailAddress(ErrorMessage = "El email no tiene formato válido.")]
    string Email,

    [property: Required(ErrorMessage = "La contraseña es requerida.")]
    [property: MinLength(1, ErrorMessage = "La contraseña no puede estar vacía.")]
    string Password);

/// <summary>Solicitud de rotación de Refresh Token.</summary>
public record RefreshRequest(string RefreshToken);

/// <summary>Solicitud de cierre de sesión.</summary>
public record LogoutRequest(string RefreshToken);

/// <summary>Solicitud de enlace para recuperar contraseña por email.</summary>
public record ForgotPasswordRequest(string Email);

/// <summary>Solicitud de inserción de nueva contraseña ligada a un token.</summary>
public record ResetPasswordRequest(string Token, string NewPassword);

/// <summary>Solicitud del código OTP de verify-action (S3).</summary>
public record VerifyActionRequest(
    [property: Required(ErrorMessage = "El código es requerido.")]
    [property: MinLength(6, ErrorMessage = "El código debe tener al menos 6 dígitos.")]
    [property: MaxLength(8, ErrorMessage = "El código no puede superar 8 dígitos.")]
    string Code);

/// <summary>Solicitud de creación de contraseña (ventana verify-action previa, S3).</summary>
public record CreatePasswordRequest(
    [property: Required(ErrorMessage = "La nueva contraseña es requerida.")]
    [property: MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña no puede superar 1024 caracteres.")]
    string NewPassword);

/// <summary>Solicitud de cambio de contraseña validando la actual (S3).</summary>
public record ChangePasswordRequest(
    [property: Required(ErrorMessage = "La contraseña actual es requerida.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña actual no puede superar 1024 caracteres.")]
    string CurrentPassword,

    [property: Required(ErrorMessage = "La nueva contraseña es requerida.")]
    [property: MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres.")]
    [property: MaxLength(1024, ErrorMessage = "La contraseña no puede superar 1024 caracteres.")]
    string NewPassword);

/// <summary>Solicitud de verificación/redención de un recovery code (F5, A-20).</summary>
public record RecoveryCodeRedemptionRequest(
    [property: Required(ErrorMessage = "El token de sesión MFA es requerido.")]
    string MfaSessionToken,

    [property: Required(ErrorMessage = "El código de recuperación es requerido.")]
    [property: MaxLength(128, ErrorMessage = "El código no puede superar 128 caracteres.")]
    string Code);

/// <summary>Respuesta del perfil del usuario autenticado (F6, A-25).</summary>
public record MeResponse(
    string Id,
    string? Email,
    bool HasPassword,
    bool TwoFactorEnabled,
    MfaEnrollmentStatus MfaEnrollmentStatus,
    string? PreferredMfaMethod);
