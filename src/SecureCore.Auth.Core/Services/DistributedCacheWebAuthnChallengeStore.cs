using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de <see cref="IWebAuthnChallengeStore"/> sobre
/// <see cref="ISingleUseTokenStore"/> (S2).
/// </summary>
/// <remarks>
/// DIDÁCTICA: en lugar de duplicar la lógica de expiración/consumo, este store delega el
/// ciclo de vida del challenge en la primitiva single-use transversal (S2). Así se reutiliza
/// el mismo fallback sobre IDistributedCache y, si el consumidor registró un backend atómico
/// para <see cref="ISingleUseTokenStore"/> (GETDEL/Lua), la atomicidad del challenge WebAuthn
/// hereda esa garantía sin coste adicional.
///
/// Riesgo residual: el default de S2 (GET + REMOVE sobre IDistributedCache) tiene una ventana
/// TOCTOU de ~1 ms en multi-instancia. Para operación verdaderamente atómica, registre su
/// propia implementación distribuida de <see cref="ISingleUseTokenStore"/> (ver comentario
/// didáctico de <see cref="DistributedCacheSingleUseTokenStore"/>).
/// </remarks>
public sealed class DistributedCacheWebAuthnChallengeStore(
    ISingleUseTokenStore singleUseTokenStore,
    ILogger<DistributedCacheWebAuthnChallengeStore> logger) : IWebAuthnChallengeStore
{
    /// <summary>
    /// Prefijo de clave para challenges WebAuthn en el store subyacente.
    /// </summary>
    private const string KeyPrefix = "webauthn:challenge:";

    /// <inheritdoc />
    public async ValueTask CreateAsync(
        string challengeId,
        string payload,
        TimeSpan ttl,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(challengeId))
        {
            throw new ArgumentException("El identificador del challenge no puede ser nulo o vacío.", nameof(challengeId));
        }

        ArgumentNullException.ThrowIfNull(payload);

        // DIDÁCTICA: guardar la versión del payload junto al resumen evita ambigüedad al
        // deserializar (el formato puede evolucionar en versiones futuras). El propio
        // ISingleUseTokenStore valida que el TTL sea positivo.
        await singleUseTokenStore.SetAsync(
            BuildKey(challengeId),
            payload,
            ttl,
            cancellationToken);

        logger.LogDebug("Challenge WebAuthn creado. Id: {ChallengeId}, TTL: {Ttl}", challengeId, ttl);
    }

    /// <inheritdoc />
    public async ValueTask<string?> GetAndDeleteAsync(
        string challengeId,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(challengeId))
        {
            throw new ArgumentException("El identificador del challenge no puede ser nulo o vacío.", nameof(challengeId));
        }

        // DIDÁCTICA: el consumo es atómico single-use (S2). Un challenge reusado o expirado
        // devuelve null y el orquestador lo trata como error genérico de autenticación.
        var payload = await singleUseTokenStore.GetAndRemoveAsync(BuildKey(challengeId), cancellationToken);
        if (payload is null)
        {
            logger.LogWarning(
                "Challenge WebAuthn no encontrado, expirado o ya consumido. Id: {ChallengeId}",
                challengeId);
        }

        return payload;
    }

    /// <summary>
    /// Construye la clave con prefijo para evitar colisiones con otras primitivas single-use.
    /// </summary>
    private static string BuildKey(string challengeId) => $"{KeyPrefix}{challengeId}";
}