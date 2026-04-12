using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Middleware que valida el Security Stamp (ssv) en cada petición autenticada.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este middleware es el guardián que hace posible la revocación global
/// de sesiones. Se ejecuta en cada petición HTTP que lleva un JWT válido y verifica
/// que el claim "ssv" (Security Stamp Version) del token coincida con el valor actual
/// del usuario en caché/base de datos.
///
/// ¿Por qué un middleware?
/// Porque necesitamos que se ejecute en CADA petición, antes de que llegue al controlador.
/// El orden en el pipeline de ASP.NET Core es:
/// Request → Auth → OUR MIDDLEWARE → [...] → Controller → Response
///
/// Si el ssv no coincide, el middleware retorna 401 Unauthorized y el request
/// nunca llega al controlador.
/// </remarks>
public sealed class SecurityStampMiddleware(
    RequestDelegate next,
    SecurityStampValidator stampValidator,
    ILogger<SecurityStampMiddleware> logger)
{
    /// <summary>
    /// Procesa la petición HTTP, validando el Security Stamp si el usuario está autenticado.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        // Solo validamos si el usuario está autenticado
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? context.User.FindFirstValue("sub");

            var securityStamp = context.User.FindFirstValue("ssv");

            if (userId is not null && securityStamp is not null)
            {
                var isValid = await stampValidator.ValidateAsync(
                    userId,
                    securityStamp,
                    context.RequestAborted);

                if (!isValid)
                {
                    logger.LogWarning(
                        "Security Stamp inválido para usuario {UserId}. Sesión revocada.",
                        userId);

                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "session_revoked",
                        message = "La sesión ha sido revocada. Inicie sesión nuevamente."
                    }, context.RequestAborted);
                    return;
                }
            }
        }

        await next(context);
    }
}
