using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de <see cref="ISingleUseTokenStore"/> usando IDistributedCache.
/// </summary>
/// <remarks>
/// DIDÁCTICA: IDistributedCache funciona con múltiples backends (MemoryCache, Redis, SQL Server),
/// por lo que la primitiva es válida en single-instance y, con un backend compatible, multi-instancia.
///
/// LIMITACIÓN (riesgo residual): <see cref="GetAndRemoveAsync"/> implementa GET + REMOVE
/// (NO atómico). Existe una ventana TOCTOU de ~1 ms entre la lectura y la eliminación. Para
/// operación verdaderamente atómica, implemente un <see cref="ISingleUseTokenStore"/> propio con
/// GETDEL/Lua (Redis) u otro mecanismo atómico de su backend; el contrato no impone el almacén.
///
/// En single-instance (MemoryDistributedCache u otra cache in-process) el riesgo es nulo:
/// la cache centraliza las operaciones dentro del proceso.
/// </remarks>
public sealed class DistributedCacheSingleUseTokenStore(IDistributedCache cache) : ISingleUseTokenStore
{
    public async ValueTask SetAsync(
        string key,
        string value,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("La clave no puede ser nula o vacía.", nameof(key));
        }

        ArgumentNullException.ThrowIfNull(value);

        if (ttl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ttl), "El TTL debe ser mayor que cero.");
        }

        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
        await cache.SetStringAsync(key, value, options, cancellationToken);
    }

    public async ValueTask<string?> GetAndRemoveAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new ArgumentException("La clave no puede ser nula o vacía.", nameof(key));
        }

        var value = await cache.GetStringAsync(key, cancellationToken);
        if (value is null)
        {
            return null;
        }

        await cache.RemoveAsync(key, cancellationToken);
        return value;
    }
}
