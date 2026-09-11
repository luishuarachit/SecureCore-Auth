using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;
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
/// SEGURIDAD - TOCTOU (A-06):
/// El ciclo de vida de cada state (escritura y consumo) delega en <see cref="ISingleUseTokenStore"/>
/// (S2). Con la implementación por defecto (IDistributedCache) el consumo es GET + REMOVE NO
/// atómico, con una ventana residual de ~1 ms. Para operación ATÓMICA (Redis GETDEL/Lua), registre
/// una implementación propia de <see cref="ISingleUseTokenStore"/> en el contenedor DI ANTES de
/// <c>AddSecureAuth()</c> (donde se registra el default con TryAddScoped); <c>DistributedCacheOAuthStateStore</c>
/// la usa automáticamente para escribir y consumir, sin necesidad de reemplazar el IOAuthStateStore.
///
/// NOTA DE INTEGRACIÓN: la implementación registrada debe ser SIMÉTRICA (mismo backend y mismo
/// formato de clave), pues "OAuthState_" se antepone al state y el flujo completo pasa por el SPI.
///
/// Si se construye SIN <see cref="ISingleUseTokenStore"/> (parámetro opcional null), se mantiene
/// el comportamiento legado por IDistributedCache para no romper instanciaciones directas.
///
/// BACKENDS SOPORTADOS:
/// - MemoryDistributedCache (in-process)
/// - SqlServerDistributedCache
/// - Redis (con ISingleUseTokenStore distribuido)
/// </remarks>
public class DistributedCacheOAuthStateStore(
    IDistributedCache cache,
    ILogger<DistributedCacheOAuthStateStore>? logger = null,
    ISingleUseTokenStore? singleUseTokenStore = null) : IOAuthStateStore
{
    private const string Prefix = "OAuthState_";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        MaxDepth = 32,
        PropertyNameCaseInsensitive = true
    };

    public async Task SaveAsync(string state, OAuthStateEntry entry, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);

        var key = SanitizeAndValidateKey(state);

        // DIDÁCTICA (S2, A-06): El ciclo de vida completo (escritura y consumo) pasa por
        // ISingleUseTokenStore cuando está inyectado, garantizando simetría independiente del
        // backend subyacente (evita el split-brain de escribir por un camino y leer por otro).
        var json = JsonSerializer.Serialize(entry, JsonOptions);

        if (singleUseTokenStore is not null)
        {
            await singleUseTokenStore.SetAsync(key, json, ttl, cancellationToken);
        }
        else
        {
            var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
            await cache.SetStringAsync(key, json, options, cancellationToken);
        }
    }

    public async ValueTask<OAuthStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default)
    {
        var key = SanitizeAndValidateKey(state);

        // DIDÁCTICA (S2, A-06): El consumo delega en ISingleUseTokenStore (GETDEL atómico
        // si el implementador la sobrescribe). Con el default de IDistributedCache la
        // operación es GET + REMOVE no atómica (ventana TOCTOU ~1ms). Si no se inyectó un
        // ISingleUseTokenStore, se conserva el camino legado para retrocompatibilidad.
        string? json;
        if (singleUseTokenStore is not null)
        {
            json = await singleUseTokenStore.GetAndRemoveAsync(key, cancellationToken);
        }
        else
        {
            json = await cache.GetStringAsync(key, cancellationToken);
            if (json is not null)
            {
                await cache.RemoveAsync(key, cancellationToken);
            }
        }

        if (json is null)
        {
            logger?.LogWarning("OAuth state not found or expired - possible replay attack attempt: {Key}", key);
            return null;
        }

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
