using System;
using System.Threading;
using System.Threading.Tasks;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Blacklist de Access Tokens (jti) — SPI OPT-IN (A-24).
/// </summary>
/// <remarks>
/// DIDÁCTICA (A-24): la librería NO aplica blacklist de access tokens por defecto
/// (decisión documentada en <c>SecureAuthOptions</c>): la revocación real la aportan el
/// SecurityStamp (revocación global) y la rotación de familias (RTR). Este contrato es un
/// SINK opcional para hosts que necesitan revocar el access token ACTUAL en un logout de
/// sesión individual: al registrarlo, el endpoint <c>/logout</c> blacklistea el <c>jti</c>
/// con TTL = vida restante y la validación JWT lo rechaza por request.
///
/// El default registrado es <c>NoOpTokenBlacklist</c> (no-op): sin una implementación real
/// del host, el comportamiento es exactamente el anterior (D-03, opt-in).
///
/// El <c>jti</c> se considera un secreto de corta vida; el TTL recomendado es la vida restante
/// del token (nunca mayor). El backend de la implementación lo decide el host (in-memory,
/// Redis, etc.).
/// </remarks>
public interface ITokenBlacklist
{
    /// <summary>
    /// Añade un jti a la blacklist durante <paramref name="ttl"/>.
    /// </summary>
    /// <param name="jti">Identificador único del access token (claim "jti").</param>
    /// <param name="ttl">Tiempo que el jti debe permanecer bloqueado (vida restante del token).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask AddAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>
    /// Indica si un jti está en la blacklist.
    /// </summary>
    /// <param name="jti">Identificador único del access token.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si el token debe ser rechazado.</returns>
    ValueTask<bool> IsBlacklistedAsync(string jti, CancellationToken cancellationToken = default);
}
