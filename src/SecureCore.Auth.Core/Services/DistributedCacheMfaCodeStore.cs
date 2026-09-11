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
/// - Los códigos son single-use: la entrada se elimina SOLO cuando el código coincide. Un intento
///   erróneo NO la destruye (auditoría): el marcador anti-replay TOTP debe sobrevivir a fallos
///   ajenos, o un intento inválido re-habilitaría el replay del código legítimo. El abuso de
///   reintentos lo acotan el lockout legacy (MaxVerificationAttempts) y el scope MFA de S1.
/// - La clave incluye userId para aislamiento entre usuarios.
/// </remarks>
public sealed class DistributedCacheMfaCodeStore(
    IDistributedCache cache,
    ILogger<DistributedCacheMfaCodeStore> logger) : IMfaCodeStore
{
    private readonly IDistributedCache _cache = cache;
    private readonly ILogger<DistributedCacheMfaCodeStore> _logger = logger;

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

        // DIDÁCTICA (auditoría): eliminamos la entrada SOLO si el código coincide (single-use real).
        // Si un intento inválido destruyera el marcador anti-replay TOTP, cualquier fallo ajeno
        // re-habilitaría el replay del código legítimo dentro de la ventana de tolerancia.
        if (isValid)
        {
            await _cache.RemoveAsync(key, cancellationToken);
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
