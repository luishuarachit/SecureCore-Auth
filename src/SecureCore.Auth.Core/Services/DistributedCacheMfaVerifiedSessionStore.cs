using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de IMfaVerifiedSessionStore sobre IDistributedCache (S3).
/// </summary>
/// <remarks>
/// DIDÁCTICA: La ventana "mfa_verified" se guarda con TTL <c>SecureAuthOptions.MfaVerifiedTtl</c>
/// (default 8 h). Vivir en caché distribuida (Redis, SQL…) la hace consistente entre nodos
/// y le da expiración automática sin jobs de limpieza.
///
/// La clave alamacena el método con el que se verificó ("totp", "email", "email_otp"),
/// útil para auditoría; la presencia de la clave (no expirada) es la señal de verificado.
/// </remarks>
public sealed class DistributedCacheMfaVerifiedSessionStore(
    IDistributedCache cache,
    IOptions<SecureAuthOptions> options,
    ILogger<DistributedCacheMfaVerifiedSessionStore> logger)
    : IMfaVerifiedSessionStore
{
    private const string KeyPrefix = "mfa_verified:";

    /// <summary>
    /// TTL efectivo. Defensivo: un valor no positivo (misconfiguración) decae al default de 8 h.
    /// </summary>
    private TimeSpan EffectiveTtl(TimeSpan configured) =>
        configured > TimeSpan.Zero ? configured : TimeSpan.FromHours(8);

    /// <inheritdoc />
    public ValueTask SetVerifiedAsync(string userId, string method, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(method);

        var ttl = EffectiveTtl(options.Value.MfaVerifiedTtl);
        logger.LogDebug("Marcando sesión mfa_verified para {UserId} (método {Method}, TTL {Ttl})", userId, method, ttl);

        return new ValueTask(cache.SetStringAsync(
            KeyPrefix + userId,
            method,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl },
            cancellationToken));
    }

    /// <inheritdoc />
    public async ValueTask<bool> IsVerifiedAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        var value = await cache.GetStringAsync(KeyPrefix + userId, cancellationToken);
        return value is not null;
    }

    /// <inheritdoc />
    public ValueTask ClearAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        logger.LogDebug("Limpiando ventana mfa_verified para {UserId}", userId);
        return new ValueTask(cache.RemoveAsync(KeyPrefix + userId, cancellationToken));
    }
}
