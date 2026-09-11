using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.WebAuthn;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Endpoints opcionales de WebAuthn/Passkeys de primera clase (S4, A-23) como Minimal APIs.
/// </summary>
/// <remarks>
/// DIDÁCTICA: complementan <see cref="SecureAuthEndpoints.MapSecureAuthEndpoints"/> con las
/// ceremonias FIDO2 orquestadas. Requieren <c>AddWebAuthn()</c> (si no está registrado,
/// responden 503). Se mapean así:
/// <code>
/// app.MapSecureAuthWebAuthnEndpoints("/auth/webauthn");
/// </code>
/// Esto mapeará:
/// - POST /auth/webauthn/register/begin    (autenticado)
/// - POST /auth/webauthn/register/complete (autenticado)
/// - POST /auth/webauthn/login/begin       (anónimo; Discoverable Credentials o por userId)
/// - POST /auth/webauthn/login/complete    (anónimo; devuelve tokens)
///
/// SEGURIDAD: las respuestas de error son genéricas (no distinguen credencial no encontrada
/// vs firma inválida vs challenge reusado) y el origin se valida en el orquestador contra
/// <c>WebAuthnOptions.Origins</c> (fail-closed si la lista está vacía).
///
/// NOTA DEL LÍMITE DE PAYLOAD: los payloads FIDO2 superan el límite de
/// <c>SecureAuthOptions.MaxAuthRequestBodySize</c> (2048 bytes, pensado para /login y friends).
/// <c>UseSecureAuthRequestSizeLimit</c> exceptúa las rutas /…/webauthn/* del límite de
/// credenciales y les asigna un tope propio
/// (<c>SecureAuthOptions.MaxWebAuthnRequestBodySize</c>, 64KB por defecto — A-29).
/// </remarks>
public static class SecureAuthWebAuthnEndpoints
{
    /// <summary>
    /// Mapea los endpoints de ceremonia WebAuthn en la ruta especificada.
    /// </summary>
    /// <param name="endpoints">El builder de endpoints de la aplicación.</param>
    /// <param name="prefix">Prefijo de ruta (ej: "/auth/webauthn").</param>
    /// <returns>El grupo de endpoints creado.</returns>
    public static RouteGroupBuilder MapSecureAuthWebAuthnEndpoints(
        this IEndpointRouteBuilder endpoints,
        string prefix = "/auth/webauthn")
    {
        var group = endpoints.MapGroup(prefix)
            .WithTags("SecureCore Auth WebAuthn");

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/register/begin (S4, autenticado)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/register/begin", async (
            WebAuthnBeginRegistrationRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<WebAuthnOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "webauthn_not_configured", message = "WebAuthn no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = GetUserId(httpContext);
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            try
            {
                var result = await orchestrator.BeginRegistrationAsync(userId, request.Origin, ct);
                return Results.Ok(new WebAuthnBeginRegistrationResponse(
                    result.ChallengeId,
                    JsonSerializer.Deserialize<JsonElement>(result.Options.ToJson())));
            }
            catch (WebAuthnOriginNotAllowedException)
            {
                // DIDÁCTICA: el origin rechazado NUNCA se devuelve (anti-enumeración); se audita
                // por log en el orquestador.
                return Results.Json(
                    new { error = "webauthn_origin_not_allowed", message = "Origin no autorizado." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        })
        .AddEndpointFilter(DataAnnotationsValidationFilter<WebAuthnBeginRegistrationRequest>.Instance)
        .WithName("WebAuthnRegisterBegin")
        .WithDescription("Paso 1 de registro: genera el challenge y las opciones de creación para una passkey.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/register/complete (S4, autenticado)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/register/complete", async (
            WebAuthnCompleteRegistrationRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<WebAuthnOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "webauthn_not_configured", message = "WebAuthn no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            var userId = GetUserId(httpContext);
            if (userId is null)
            {
                return Results.Unauthorized();
            }

            if (request.AttestationResponse is null)
            {
                return Results.Json(
                    new { error = "invalid_payload", message = "La respuesta del autenticador es inválida." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var result = await orchestrator.CompleteRegistrationAsync(
                userId,
                request.Origin,
                request.ChallengeId,
                request.AttestationResponse,
                request.DeviceNickname,
                ct);

            if (!result.Success)
            {
                return Results.Json(
                    new { error = "registration_failed", message = result.ErrorMessage ?? "No se pudo completar el registro." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            return Results.Ok(new WebAuthnRegisterCompleteResponse(
                Registered: true,
                CredentialId: Convert.ToBase64String(result.Credential!.CredentialId),
                DeviceNickname: result.Credential.DeviceNickname));
        })
        .AddEndpointFilter(DataAnnotationsValidationFilter<WebAuthnCompleteRegistrationRequest>.Instance)
        .WithName("WebAuthnRegisterComplete")
        .WithDescription("Paso 2 de registro: consume el challenge single-use y verifica la attestation.")
        .RequireAuthorization();

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/login/begin (S4, anónimo)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/login/begin", async (
            WebAuthnBeginLoginRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<WebAuthnOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "webauthn_not_configured", message = "WebAuthn no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            // DIDÁCTICA (A-29): el begin es anónimo y barato (generar + persistir un challenge);
            // un flood satura el almacén de challenges (Storage DoS). Se limita por IP con el
            // presupuesto keyed "webauthn-begin" (AddSecureAuth lo registra con InMemoryRateLimiter;
            // el host puede sustituirlo por uno distribuido). Antes de generar el challenge.
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var beginLimiter = serviceProvider.GetKeyedService<IRateLimiter>("webauthn-begin");
            if (beginLimiter is not null && !beginLimiter.IsAllowed(ipAddress))
            {
                return Results.Json(
                    new { error = "too_many_requests", message = "Demasiados intentos. Intenta más tarde." },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            try
            {
                var result = await orchestrator.BeginLoginAsync(request.UserId, request.Origin, ct);
                return Results.Ok(new WebAuthnBeginLoginResponse(
                    result.ChallengeId,
                    JsonSerializer.Deserialize<JsonElement>(result.Options.ToJson())));
            }
            catch (WebAuthnOriginNotAllowedException)
            {
                return Results.Json(
                    new { error = "webauthn_origin_not_allowed", message = "Origin no autorizado." },
                    statusCode: StatusCodes.Status400BadRequest);
            }
        })
        .AddEndpointFilter(DataAnnotationsValidationFilter<WebAuthnBeginLoginRequest>.Instance)
        .WithName("WebAuthnLoginBegin")
        .WithDescription("Paso 1 de login: genera el challenge y las opciones de aserción para una passkey.")
        .AllowAnonymous();

        // ─────────────────────────────────────────────────────────
        //  POST {prefix}/login/complete (S4, anónimo)
        // ─────────────────────────────────────────────────────────
        group.MapPost("/login/complete", async (
            WebAuthnCompleteLoginRequest request,
            HttpContext httpContext,
            IServiceProvider serviceProvider,
            CancellationToken ct) =>
        {
            var orchestrator = serviceProvider.GetService<WebAuthnOrchestrator>();
            if (orchestrator is null)
            {
                return Results.Json(
                    new { error = "webauthn_not_configured", message = "WebAuthn no está configurado." },
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            // DIDÁCTICA (A-29): el complete es anónimo y costoso (verificación criptográfica de
            // firma + consumo del presupuesto S1 por cuenta). Se limita por IP con el presupuesto
            // keyed "webauthn-complete" ANTES de consumir el challenge ni tocar Fido2.
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var completeLimiter = serviceProvider.GetKeyedService<IRateLimiter>("webauthn-complete");
            if (completeLimiter is not null && !completeLimiter.IsAllowed(ipAddress))
            {
                return Results.Json(
                    new { error = "too_many_requests", message = "Demasiados intentos. Intenta más tarde." },
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            if (request.AssertionResponse is null)
            {
                return Results.Json(
                    new { error = "invalid_payload", message = "La respuesta del autenticador es inválida." },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var result = await orchestrator.CompleteLoginAsync(
                request.Origin,
                request.ChallengeId,
                request.AssertionResponse,
                ct);

            if (result.Success && result.Tokens is not null)
            {
                // DIDÁCTICA: reset del rate limit en éxito para no penalizar al usuario legítimo
                // (mismo patrón que /auth/login).
                completeLimiter?.Reset(ipAddress);

                return Results.Ok(new
                {
                    accessToken = result.Tokens.AccessToken,
                    refreshToken = result.Tokens.RefreshToken,
                    expiresAt = result.Tokens.ExpiresAt
                });
            }

            return Results.Json(
                new { error = "authentication_failed", message = result.ErrorMessage ?? "Autenticación fallida." },
                statusCode: result.LockedOut
                    ? StatusCodes.Status423Locked
                    : StatusCodes.Status400BadRequest);
        })
        .AddEndpointFilter(DataAnnotationsValidationFilter<WebAuthnCompleteLoginRequest>.Instance)
        .WithName("WebAuthnLoginComplete")
        .WithDescription("Paso 2 de login: consume el challenge single-use, valida la firma y emite tokens.")
        .AllowAnonymous();

        return group;
    }

    /// <summary>
    /// Extrae el ID de usuario (claim "sub"/NameIdentifier) del contexto autenticado.
    /// </summary>
    private static string? GetUserId(HttpContext httpContext)
    {
        return httpContext.User.FindFirst("sub")?.Value
               ?? httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
    }
}

// ─────────────────────────────────────────────────────────
//  Request DTOs para los endpoints WebAuthn (S4)
// ─────────────────────────────────────────────────────────

/// <summary>
/// Solicitud del paso "begin" de registro (autenticado).
/// </summary>
public record WebAuthnBeginRegistrationRequest(
    [property: Required(ErrorMessage = "El origin es requerido.")]
    string Origin);

/// <summary>
/// Solicitud del paso "complete" de registro (autenticado).
/// </summary>
/// <remarks>
/// DIDÁCTICA: el <c>AttestationResponse</c> es el payload estándar del browser
/// (<c>navigator.credentials.create</c>) con <c>rawId</c> y <c>response.clientDataJSON</c>
/// en Base64URL. El challenge se consume single-use por <c>ChallengeId</c>.
/// </remarks>
public record WebAuthnCompleteRegistrationRequest(
    [property: Required(ErrorMessage = "El origin es requerido.")]
    string Origin,

    [property: Required(ErrorMessage = "El identificador del challenge es requerido.")]
    string ChallengeId,

    AuthenticatorAttestationRawResponse? AttestationResponse,

    [property: MaxLength(64, ErrorMessage = "El apodo del dispositivo no puede superar 64 caracteres.")]
    string? DeviceNickname = null);

/// <summary>
/// Solicitud del paso "begin" de login (anónimo).
/// </summary>
/// <remarks>
/// DIDÁCTICA: <c>UserId</c> es opcional. Si se omite se usan Discoverable Credentials
/// (la señal permite login sin username). Si se indica un usuario inexistente, el begin
/// responde igual (no-enumeración; el veredicto llega en complete).
/// </remarks>
public record WebAuthnBeginLoginRequest(
    [property: Required(ErrorMessage = "El origin es requerido.")]
    string Origin,
    string? UserId = null);

/// <summary>
/// Solicitud del paso "complete" de login (anónimo).
/// </summary>
public record WebAuthnCompleteLoginRequest(
    [property: Required(ErrorMessage = "El origin es requerido.")]
    string Origin,

    [property: Required(ErrorMessage = "El identificador del challenge es requerido.")]
    string ChallengeId,

    AuthenticatorAssertionRawResponse? AssertionResponse);

// ─────────────────────────────────────────────────────────
//  Response DTOs inmutables (records)
// ─────────────────────────────────────────────────────────

/// <summary>
/// Respuesta del paso "begin" de registro: <c>challengeId</c> + opciones para el navegador.
/// </summary>
/// <param name="ChallengeId">Identificador que se devuelve en /register/complete.</param>
/// <param name="Options">Opciones de creación (publicKey para navigator.credentials.create).</param>
public sealed record WebAuthnBeginRegistrationResponse(string ChallengeId, JsonElement Options);

/// <summary>
/// Respuesta del paso "complete" de registro: credencial almacenada (ref. pública).
/// </summary>
/// <param name="Registered">true si la credencial se verificó y almacenó.</param>
/// <param name="CredentialId">ID público de la credencial (Base64).</param>
/// <param name="DeviceNickname">Apodo del dispositivo (si se proporcionó).</param>
public sealed record WebAuthnRegisterCompleteResponse(
    bool Registered,
    string CredentialId,
    string? DeviceNickname);

/// <summary>
/// Respuesta del paso "begin" de login: <c>challengeId</c> + opciones para el navegador.
/// </summary>
/// <param name="ChallengeId">Identificador que se devuelve en /login/complete.</param>
/// <param name="Options">Opciones de aserción (publicKey para navigator.credentials.get).</param>
public sealed record WebAuthnBeginLoginResponse(string ChallengeId, JsonElement Options);
