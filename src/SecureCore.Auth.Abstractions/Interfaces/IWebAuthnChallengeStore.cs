namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Almacén de challenges de WebAuthn (S4, A-23). Guarda el payload de cada ceremonia
/// (opciones de creación/asersión) para verificar después la respuesta del navegador.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El challenge de WebAuthn es la pieza anti-replay del protocolo: se genera
/// en el paso "begin", el autenticador lo firma y el servidor lo verifica en el paso
/// "complete". Para que el flujo sea seguro:
///
/// 1. SINGLE-USE: el challenge se consume exactamente una vez (una sola respuesta por
///    ceremonia). Reusar un challenge permitiría replay de la respuesta firmada.
/// 2. ASOCIADO AL FLUJO: cada challenge se identifica con un <c>challengeId</c> único
///    (típicamente un GUID CSPRNG) que el navegador devuelve junto a la respuesta.
/// 3. TTL: el challenge expira tras un tiempo corto (default 60 s en
///    <c>WebAuthnOptions.ChallengeTimeoutSeconds</c>) para acotar la ventana de ataque.
///
/// Este contrato delega la atomicidad del consumo en la primitiva SINGLE-USE transversal
/// <see cref="ISingleUseTokenStore"/> (S2): <see cref="GetAndDeleteAsync"/> consume de forma
/// atómica (GETDEL) y devuelve <c>null</c> si el challenge ya fue usado o expiró.
///
/// Es un SPI: el consumidor puede reemplazar el default sobre IDistributedCache por un
/// backend distribuido real (Redis tolerante a la primitiva atómica, etc.) sin cambiar el
/// contrato.
/// </remarks>
public interface IWebAuthnChallengeStore
{
    /// <summary>
    /// Guarda el payload de un challenge de WebAuthn con un TTL de validez.
    /// </summary>
    /// <param name="challengeId">Identificador único del challenge (generado por el servidor).</param>
    /// <param name="payload">Representación serializada de las opciones de la ceremonia.</param>
    /// <param name="ttl">Tiempo de vida del challenge. Debe ser mayor que cero.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask CreateAsync(
        string challengeId,
        string payload,
        TimeSpan ttl,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Consume el challenge de forma atómica y devuelve su payload, o <c>null</c> si no existe.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: la operación es de tipo GETDEL (leer y eliminar en un solo paso). Si el
    /// challenge ya se consumió, expiró o nunca existió, devuelve <c>null</c>: el orquestador
    /// responde con error genérico de autenticación sin distinguir los casos (anti-enumeración).
    /// </remarks>
    /// <param name="challengeId">Identificador único del challenge.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El payload del challenge, o null si no existe / ya fue consumido.</returns>
    ValueTask<string?> GetAndDeleteAsync(string challengeId, CancellationToken cancellationToken = default);
}