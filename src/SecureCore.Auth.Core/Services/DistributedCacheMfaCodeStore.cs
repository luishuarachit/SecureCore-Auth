using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación de IMfaCodeStore usando IDistributedCache de ASP.NET Core.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta implementación es la recomendada para producción porque
/// IDistributedCache funciona con múltiples backends (MemoryCache, Redis, SQL Server).
/// En entornos distribuidos, usar Redis asegura que el código sea válido en todos los nodos.
///
/// SEGURIDAD:
/// - El código se almacena como hash SHA-256, nunca en texto plano.
/// - La validación usa CryptographicOperations.FixedTimeEquals para prevenir timing attacks.
/// - Los códigos son single-use: se eliminan de la caché tras la validación (éxito o fallo
///   si coincide la clave, aunque el código no coincida, para forzar rate-limiting).
/// - La clave incluye userId para aislamiento entre usuarios.
/// </remarks>
public sealed class DistributedCacheMfaCodeStore : IMfaCodeStore
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<DistributedCacheMfaCodeStore> _logger;

    public DistributedCacheMfaCodeStore(
        IDistributedCache cache,
        ILogger<DistributedCacheMfaCodeStore> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task StoreCodeHashAsync(
        string key,
        string codeHash,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = ttl
        };

        await _cache.SetStringAsync(key, codeHash, options, cancellationToken);
        _logger.LogDebug("Código MFA almacenado en caché con clave {Key}, TTL: {TTL}", key, ttl);
    }

    public async Task<bool> ValidateAndRemoveCodeAsync(
        string key,
        string code,
        CancellationToken cancellationToken = default)
    {
        var storedHash = await _cache.GetStringAsync(key, cancellationToken);

        if (string.IsNullOrEmpty(storedHash))
        {
            _logger.LogDebug("Código MFA no encontrado en caché para clave {Key} (expirado o ya usado)", key);
            return false;
        }

        var providedHash = ComputeHash(code);

        // DIDÁCTICA: Usamos FixedTimeEquals para comparación en tiempo constante.
        // Esto previene timing attacks donde un atacante podría inferir cuántos
        // caracteres acertó midiendo el tiempo de respuesta.
        var isValid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(storedHash),
            Encoding.UTF8.GetBytes(providedHash));

        // Eliminamos de la caché SIEMPRE (single-use).
        // Incluso si el código no coincide, eliminamos para evitar que
        // un mismo código pueda ser reutilizado en reintentos.
        await _cache.RemoveAsync(key, cancellationToken);

        if (isValid)
        {
            _logger.LogDebug("Código MFA validado correctamente para clave {Key}", key);
        }
        else
        {
            _logger.LogWarning("Código MFA inválido para clave {Key}", key);
        }

        return isValid;
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
