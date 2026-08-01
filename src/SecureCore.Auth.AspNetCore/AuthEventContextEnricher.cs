using Microsoft.AspNetCore.Http;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Decorator de <see cref="IAuthEventDispatcher"/> que enriquece automáticamente
/// los eventos de autenticación con contexto HTTP (IP, path, User-Agent,
/// X-Forwarded-For, roles del usuario autenticado).
/// </summary>
/// <remarks>
/// Este enricher no modifica el flujo de autenticación ni las decisiones
/// de seguridad. Solo adjunta metadatos informativos a cada evento.
///
/// Si no hay HttpContext disponible (p.ej. en tests unitarios), el evento
/// se despacha sin enriquecer.
/// </remarks>
public sealed class AuthEventContextEnricher(
    IHttpContextAccessor httpContextAccessor,
    IAuthEventDispatcher inner) : IAuthEventDispatcher
{
    public async Task DispatchAsync(AuthEvent authEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authEvent);

        var ctx = httpContextAccessor.HttpContext;
        if (ctx != null)
        {
            var metadata = new Dictionary<string, string>(authEvent.Metadata)
            {
                ["ip"] = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                ["path"] = ctx.Request.Path.ToString()
            };

            var xff = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(xff))
                metadata["xff"] = xff;

            var ua = ctx.Request.Headers["User-Agent"].FirstOrDefault();
            if (!string.IsNullOrEmpty(ua))
                metadata["ua"] = ua;

            if (ctx.User.Identity?.IsAuthenticated == true)
            {
                var roles = ctx.User.Claims
                    .Where(c => c.Type == "role" ||
                                c.Type.EndsWith("/claims/role", StringComparison.OrdinalIgnoreCase))
                    .Select(c => c.Value)
                    .ToList();

                if (roles.Count > 0)
                    metadata["roles"] = string.Join(",", roles);
            }

            authEvent = authEvent with { Metadata = metadata };
        }

        await inner.DispatchAsync(authEvent, cancellationToken);
    }
}
