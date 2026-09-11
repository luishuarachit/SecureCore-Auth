using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de <see cref="IRecoveryCodeStore"/> sobre
/// IDistributedCache con consumo atómico vía la primitiva single-use (S2).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F5, A-20): un recovery code debe cumplir dos garantías:
///
/// 1. SINGLE-USE ATOMICO: solo puede redimirse UNA vez, incluso bajo concurrencia. Para ello el
///    "token" del código se guarda en <c>ISingleUseTokenStore</c> (S2): <see cref="RedeemAsync"/>
///    consume la entrada y exactamente una llamada recibe true. La redención se serializa además
///    con un <c>IOperationLock</c> por código (A2, auditoría): cierra la ventana TOCTOU del S2
///    por defecto (GET + REMOVE no atómico) dentro de la instancia. Para multi-instancia, use un
///    S2 atómicamente consumidor (Redis GETDEL/Lua); el lock in-memory no se comparte.
///
/// 2. DISTINCIÓN DE ESTADOS sin consumir: <see cref="GetStatusAsync"/> necesita saber si un
///    código fue emitido y si ya se usó. Como S2 no permite enumeración ni peek, este store
///    mantiene un ÍNDICE POR USUARIO en IDistributedCache (lista JSON de hashes con su estado).
///    El índice es metadatos (fuente de verdad para verify/invalidación); la garantía de
///    seguridad real (single-use) la da el token S2, indiferente del índice.
///
/// CONSISTENCIA DEL ÍNDICE (riesgo residual): <see cref="CreateAsync"/> actualiza el índice
/// con read-modify-write NO atómico. Las escrituras quedan documentadas: una interrupción a
/// mitad del lote deja el lote parcialmente pendiente (el host puede regenerar); nunca deja
/// códigos consumibles sin índice, porque el índice se escribe ANTES que los tokens S2 y así
/// no quedan códigos huérfanos redimibles tras la regeneración. La generación en sí se
/// serializa por usuario en <c>RecoveryCodeOrchestrator.GenerateAsync</c> (B2, auditoría).
///
/// CLAVES: los tokens se guardan como <c>recovery:code:{userId}|{hash}</c> y el índice como
/// <c>recovery:index:{userId}</c>. El delimitador "|" separa userId de hash; el hash es
/// siempre 64 caracteres hex (sufijo de longitud fija), por lo que la clave es inequívoca
/// aunque el userId contenga el delimitador.
///
/// TTL: cada código y el índice comparten la misma expiración
/// (<c>MfaOptions.RecoveryCodeLifetimeDays</c>, "último recurso" debe caducar).
/// </remarks>
public sealed class DistributedCacheRecoveryCodeStore(
    ISingleUseTokenStore singleUseTokenStore,
    IDistributedCache cache,
    IOperationLock operationLock,
    IOptions<MfaOptions> mfaOptions,
    ILogger<DistributedCacheRecoveryCodeStore> logger) : IRecoveryCodeStore
{
    /// <summary>
    /// Prefijo de clave del token single-use de cada código (S2).
    /// </summary>
    private const string CodeKeyPrefix = "recovery:code:";

    /// <summary>
    /// Prefijo de clave del índice por usuario (lista JSON de hashes con su estado).
    /// </summary>
    private const string IndexKeyPrefix = "recovery:index:";

    private readonly TimeSpan _lifetime = TimeSpan.FromDays(mfaOptions.Value.RecoveryCodeLifetimeDays);

    /// <summary>
    /// DIDÁCTICA (A2, auditoría): timeout del lock de redención por código. La redención es una
    /// operación corta (GETDEL + marca en índice); 5 s es holgado y no penaliza la concurrencia
    /// de códigos distintos (cada código tiene su propio lock).
    /// </summary>
    private static readonly TimeSpan _operationLockTimeout = TimeSpan.FromSeconds(5);

    /// <inheritdoc />
    public async ValueTask CreateAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(codeHash);

        // DIDÁCTICA (orden de escritura): indexar ANTES que crear el token S2 asegura que ante
        // una caída a mitad del lote no queden códigos redimibles sin índice (códigos huérfanos
        // que la invalidación posterior no podría rastrear). El coste: si falla la creación del
        // token tras indexar, el lote queda incompleto y el host debe regenerar (caso raro).
        await AppendToIndexAsync(userId, new RecoveryCodeIndexEntry(codeHash), cancellationToken);
        await singleUseTokenStore.SetAsync(
            BuildCodeKey(userId, codeHash),
            codeHash,
            _lifetime,
            cancellationToken);

        logger.LogDebug("Recovery code almacenado para usuario {UserId}, hash {Hash}", userId, codeHash);
    }

    /// <inheritdoc />
    public async ValueTask<RecoveryCodeStatus> GetStatusAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(codeHash);

        var index = await ReadIndexAsync(userId, cancellationToken);
        var entry = index.FirstOrDefault(e => e.Hash == codeHash);
        if (entry is null)
        {
            // DIDÁCTICA: el hash no figura en el índice: nunca fue emitido, expiró o su lote
            // fue invalidado. No distinguimos estas causas (anti-enumeración).
            return RecoveryCodeStatus.Invalid;
        }

        // DIDÁCTICA (single-use): el token S2 solo desaparece al redimirse (y el paso a
        // Used=true en el índice acompaña ese consumo). Si el índice dice "no usado", el
        // token sigue existiendo mientras no expire: mismo TTL para ambos.
        return entry.Used ? RecoveryCodeStatus.AlreadyUsed : RecoveryCodeStatus.Valid;
    }

    /// <inheritdoc />
    public async ValueTask<bool> RedeemAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(codeHash);

        // DIDÁCTICA (A2, auditoría): la primitiva S2 por defecto (GET + REMOVE) NO es atómica:
        // dos redemptions concurrentes del mismo código podrían leer ambas la entrada antes de
        // borrarla (TOCTOU) y las dos obtener "éxito". El lock por código serializa la redención
        // dentro de la instancia (cierra la race en single-instance). NOTA: para multi-instancia
        // sigue siendo necesario un ISingleUseTokenStore atómicamente consumidor (Redis GETDEL/Lua);
        // el lock in-memory no se comparte entre procesos.
        var codeKey = BuildCodeKey(userId, codeHash);
        using var redeemLock = await operationLock.AcquireAsync(
            $"recovery:redeem:{codeKey}",
            _operationLockTimeout,
            cancellationToken);

        var stored = await singleUseTokenStore.GetAndRemoveAsync(
            codeKey,
            cancellationToken);
        if (stored is null)
        {
            logger.LogDebug(
                "Recovery code no redimido para usuario {UserId}: inexistente, expirado o ya usado",
                userId);
            return false;
        }

        // DIDÁCTICA (best-effort): marcar Used=true en el índice alimenta el Estado AlreadyUsed
        // para la fase verify. Si esta actualización se pierde (caída) la garantía de seguridad
        // no cambia: el token S2 ya se consumió y un segundo intento de Redemption devolvería
        // false igualmente (el single-use está en S2, no en el índice).
        await MarkAsUsedAsync(userId, codeHash, cancellationToken);

        logger.LogInformation("Recovery code redimido para usuario {UserId}", userId);
        return true;
    }

    /// <inheritdoc />
    public async ValueTask InvalidatePendingAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var index = await ReadIndexAsync(userId, cancellationToken);
        if (index.Count == 0)
        {
            return;
        }

        // DIDÁCTICA: purgar los tokens de los códigos aún pendientes para que la lista vieja
        // no contenga códigos redimibles. ISingleUseTokenStore solo ofrece GETDEL, así que
        // "purgar" = consumir la entrada (el efecto de borrado es el mismo). Los ya usados no
        // tienen token que borrar. Después se elimina el índice completo.
        foreach (var entry in index.Where(e => !e.Used))
        {
            await singleUseTokenStore.GetAndRemoveAsync(
                BuildCodeKey(userId, entry.Hash),
                cancellationToken);
        }

        await cache.RemoveAsync(BuildIndexKey(userId), cancellationToken);
        logger.LogInformation(
            "Se invalidaron {Count} recovery codes del índice del usuario {UserId}",
            index.Count,
            userId);
    }

    private async ValueTask AppendToIndexAsync(
        string userId,
        RecoveryCodeIndexEntry entry,
        CancellationToken cancellationToken)
    {
        var index = await ReadIndexAsync(userId, cancellationToken);
        index.Add(entry);

        await cache.SetStringAsync(
            BuildIndexKey(userId),
            JsonSerializer.Serialize(index),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _lifetime },
            cancellationToken);
    }

    private async ValueTask MarkAsUsedAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken)
    {
        var index = await ReadIndexAsync(userId, cancellationToken);
        var entry = index.FirstOrDefault(e => e.Hash == codeHash);
        if (entry is null)
        {
            return;
        }

        entry.Used = true;
        await cache.SetStringAsync(
            BuildIndexKey(userId),
            JsonSerializer.Serialize(index),
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _lifetime },
            cancellationToken);
    }

    private async ValueTask<List<RecoveryCodeIndexEntry>> ReadIndexAsync(
        string userId,
        CancellationToken cancellationToken)
    {
        var raw = await cache.GetStringAsync(BuildIndexKey(userId), cancellationToken);
        if (string.IsNullOrEmpty(raw))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<RecoveryCodeIndexEntry>>(raw) ?? [];
        }
        catch (JsonException)
        {
            logger.LogWarning("Índice de recovery codes corrupto para usuario {UserId}; se ignora", userId);
            return [];
        }
    }

    private static string BuildCodeKey(string userId, string codeHash) =>
        $"{CodeKeyPrefix}{userId}|{codeHash}";

    private static string BuildIndexKey(string userId) => $"{IndexKeyPrefix}{userId}";

    /// <summary>
    /// Entrada del índice por usuario: hash del código + flag de uso.
    /// Está pensada para JSON (clase con setter).
    /// </summary>
    private sealed class RecoveryCodeIndexEntry
    {
        public string Hash { get; set; } = string.Empty;

        public bool Used { get; set; }

        public RecoveryCodeIndexEntry()
        {
        }

        public RecoveryCodeIndexEntry(string hash) => Hash = hash;
    }
}
