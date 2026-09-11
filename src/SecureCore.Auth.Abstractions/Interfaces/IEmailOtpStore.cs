namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Almacén de códigos OTP por email para step-up (S3, verificación de acciones sensibles).
/// Solo se persisten hashes del código, nunca el código en texto plano.
/// </summary>
/// <remarks>
/// DIDÁCTICA: A diferencia de <see cref="IMfaCodeStore"/> (códigos de login MFA),
/// este almacén sirve a la verificación de acciones sensibles (verify-action):
/// cambiar la contraseña, emitir credenciales, etc. El contrato es idéntico en
/// forma, pero el ciclo de vida del código es distinto y el consumo se delega en
/// <c>ISingleUseTokenStore</c> (S2) para garantizar atomicidad de "consumo exacto
/// una vez" (GETDEL) incluso sin una operación de lectura+borrado atómica en caché.
///
/// SEGURIDAD:
/// - El código se almacena como hash SHA-256 (nunca texto plano).
/// - La validación usa <c>CryptographicOperations.FixedTimeEquals</c> (anti timing).
/// - Single-use: el consumo elimina la entrada de forma atómica, éxito o fallo.
/// </remarks>
public interface IEmailOtpStore
{
    /// <summary>
    /// Almacena el hash del código de verificación con su TTL.
    /// </summary>
    /// <param name="key">Clave única del código (el orquestador decide su forma, ej: "verify_action:{userId}").</param>
    /// <param name="codeHash">Hash SHA-256 (hexadecimal minúsculas) del código.</param>
    /// <param name="ttl">Tiempo de vida del código.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task StoreCodeHashAsync(string key, string codeHash, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>
    /// Valida el código en tiempo constante y lo consume de forma atómica (single-use).
    /// </summary>
    /// <param name="key">Clave única del código.</param>
    /// <param name="code">Código en texto plano a validar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si el código coincide Y no había sido consumido/expirado.</returns>
    Task<bool> ValidateAndRemoveCodeAsync(string key, string code, CancellationToken cancellationToken = default);
}
