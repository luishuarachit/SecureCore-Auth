using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.OAuth.Abstractions;

namespace SecureCore.Auth.AspNetCore.Extensions;

/// <summary>
/// Implementación de IOAuthStateStore usando IDistributedCache de ASP.NET Core.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este store implementa el patrón de Anti-Replay para el state de OAuth.
/// Cuando el callback de OAuth llega con un state, consumimos el entry para garantizar
/// que ese state no pueda usarse una segunda vez.
///
/// SEGURIDAD - TOCTOU:
/// Este método usa GET + REMOVE (no atómico). La ventana TOCTOU es mínima (~1ms) y
/// requeriría que un atacante coordinara dos requests exactamente en ese micro-intervalo.
///
/// Para operación ATÓMICA (Redis GETDEL), el implementador debe usar una implementación
/// personalizada de IOAuthStateStore que acceda directamente a Redis via StackExchange.Redis.
/// Esto está fuera del alcance de esta librería por no ser una dependencia requerida.
/// El riesgo en la práctica es teórico y aceptable para la mayoría de aplicaciones.
///
/// BACKENDS SOPORTADOS:
/// - MemoryDistributedCache (in-process)
/// - SqlServerDistributedCache
/// - Redis (con implementación personalizada)
/// </remarks>
public class DistributedCacheOAuthStateStore(
    IDistributedCache cache,
    ILogger<DistributedCacheOAuthStateStore>? logger = null) : IOAuthStateStore
{
    private const string Prefix = "OAuthState_";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        MaxDepth = 32,
        PropertyNameCaseInsensitive = true
    };

    public async Task SaveAsync(string state, OAuthStateEntry entry, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        var key = SanitizeAndValidateKey(state);

        var json = JsonSerializer.Serialize(entry, JsonOptions);
        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };

        await cache.SetStringAsync(key, json, options, cancellationToken);
    }

    public async ValueTask<OAuthStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default)
    {
        var key = SanitizeAndValidateKey(state);

        // DIDÁCTICA: Operación GET + REMOVE no atómica.
        // La ventana TOCTOU es ~1ms. Para aplicaciones de alto riesgo,
        // implementar una versión con Redis GETDEL directamente.
        var json = await cache.GetStringAsync(key, cancellationToken);

        if (json is null)
        {
            logger?.LogWarning("OAuth state not found or expired - possible replay attack attempt: {Key}", key);
            return null;
        }

        await cache.RemoveAsync(key, cancellationToken);

        try
        {
            return JsonSerializer.Deserialize<OAuthStateEntry>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            logger?.LogError(ex, "OAuth state deserialization failed - possible tampered data: {Key}", key);
            return null;
        }
    }

    /// <summary>
    /// Sanitiza y valida el state para prevenir inyección en keys de cache.
    /// </summary>
    /// <remarks>
    /// El state generado por OAuthEndpoints.GenerateSecureRandomString usa:
    /// - 32 bytes de entropy
    /// - Base64URL encoding (A-Z, a-z, 0-9, -, _)
    /// Longitud esperada: ~43 caracteres después de encoding
    /// </remarks>
    private static string SanitizeAndValidateKey(string state)
    {
        if (string.IsNullOrEmpty(state))
        {
            throw new ArgumentException("OAuth state no puede ser nulo o vacío.", nameof(state));
        }

        // El state de OAuth debe ser base64url - verificar que solo contenga caracteres válidos
        // Base64url: A-Z, a-z, 0-9, -, _
        if (!IsValidBase64Url(state))
        {
            throw new ArgumentException("OAuth state tiene formato inválido.", nameof(state));
        }

        // Longitud típica para 32 bytes en base64url es 43-44 caracteres
        // Allow 32-64 para cubrir posibles variaciones
        if (state.Length < 32 || state.Length > 64)
        {
            throw new ArgumentException("OAuth state tiene longitud fuera del rango esperado.", nameof(state));
        }

        return Prefix + state;
    }

    private static bool IsValidBase64Url(string value)
    {
        // Base64URL characters: A-Z, a-z, 0-9, -, _
        foreach (var c in value)
        {
            if (!char.IsLetterOrDigit(c) && c != '-' && c != '_')
            {
                return false;
            }
        }
        return true;
    }
}
