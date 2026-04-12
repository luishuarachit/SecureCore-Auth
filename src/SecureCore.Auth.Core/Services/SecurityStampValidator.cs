using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Valida el Security Stamp del usuario en cada petición usando caché distribuida.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El SecurityStampValidator implementa el patrón "Cache-Aside" para
/// optimizar el rendimiento de la validación de sesiones.
///
/// ¿Por qué necesitamos esto?
/// El JWT puede vivir 15 minutos, pero si el usuario cierra todas sus sesiones (botón de pánico),
/// no queremos esperar 15 minutos para que el token expire. En su lugar, cada petición
/// verifica que el "ssv" (Security Stamp Version) del token coincida con el valor actual.
///
/// ¿Por qué usar caché?
/// Si consultamos la base de datos en cada petición, el rendimiento se degradaría enormemente.
/// Usando IDistributedCache (Redis, por ejemplo), mantenemos el SecurityStamp en caché
/// por 5 minutos. Esto significa que, en el peor caso, un token revocado seguirá siendo
/// válido por 5 minutos más. Es un tradeoff aceptable entre seguridad y rendimiento.
///
/// Flujo Cache-Aside:
/// 1. Buscar en caché → HIT: comparar y responder
/// 2. Si MISS → consultar IUserStore → guardar en caché (TTL 5 min) → comparar y responder
/// </remarks>
public sealed class SecurityStampValidator(
    IUserStore userStore,
    IDistributedCache cache,
    IOptions<SecureAuthOptions> options,
    ILogger<SecurityStampValidator> logger)
{
    private readonly SecureAuthOptions _options = options.Value;
    private const string CacheKeyPrefix = "secureauth:ssv:";

    /// <summary>
    /// Valida que el Security Stamp del token coincida con el valor actual del usuario.
    /// </summary>
    /// <param name="userId">ID del usuario extraído del claim "sub" del JWT.</param>
    /// <param name="tokenSecurityStamp">Valor del claim "ssv" del JWT.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si el Security Stamp es válido, false si ha sido revocado.</returns>
    public async ValueTask<bool> ValidateAsync(
        string userId,
        string tokenSecurityStamp,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(tokenSecurityStamp);

        // Paso 1: Intentar obtener el SecurityStamp desde la caché
        var cacheKey = $"{CacheKeyPrefix}{userId}";
        var cachedStamp = await cache.GetStringAsync(cacheKey, cancellationToken);

        if (cachedStamp is not null)
        {
            // Cache HIT: comparamos y retornamos sin consultar la base de datos
            return string.Equals(cachedStamp, tokenSecurityStamp, StringComparison.Ordinal);
        }

        // Paso 2: Cache MISS → consultamos la base de datos
        logger.LogDebug("Cache MISS para SecurityStamp del usuario {UserId}. Consultando IUserStore.", userId);
        var currentStamp = await userStore.GetSecurityStampAsync(userId, cancellationToken);

        if (currentStamp is null)
        {
            // El usuario no existe o no tiene SecurityStamp → rechazar
            logger.LogWarning("No se encontró SecurityStamp para usuario {UserId}", userId);
            return false;
        }

        // Paso 3: Guardar en caché para las próximas peticiones
        await cache.SetStringAsync(
            cacheKey,
            currentStamp,
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _options.SecurityStampCacheDuration
            },
            cancellationToken);

        // Paso 4: Comparar y retornar
        return string.Equals(currentStamp, tokenSecurityStamp, StringComparison.Ordinal);
    }

    /// <summary>
    /// Invalida la entrada de caché del SecurityStamp de un usuario.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Cuando el usuario cierra todas sus sesiones (botón de pánico),
    /// además de cambiar el SecurityStamp en la base de datos, debemos invalidar
    /// la caché para que la próxima petición consulte el valor nuevo inmediatamente.
    /// Sin esta invalidación, los tokens seguirían siendo válidos hasta que la caché expire.
    /// </remarks>
    /// <param name="userId">ID del usuario cuya caché se debe invalidar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    public async Task InvalidateCacheAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        var cacheKey = $"{CacheKeyPrefix}{userId}";
        await cache.RemoveAsync(cacheKey, cancellationToken);

        logger.LogInformation("Caché de SecurityStamp invalidada para usuario {UserId}", userId);
    }
}
