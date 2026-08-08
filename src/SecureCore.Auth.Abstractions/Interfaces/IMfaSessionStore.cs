namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para el store de sesión MFA.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este store gestiona tokens temporales de sesión MFA.
/// Usamos JWT de corta duración (5-10 minutos) que solo sirve para completar
/// la verificación MFA. Similar al "mfa_token" de Auth0 o "intermediate session token" de Stytch.
///
/// El JWT contiene:
/// - sub: userId
/// - mfa_method: método a verificar
/// - exp: fecha de expiración
/// - jti: identificador único (para logging/trace)
/// - purpose: "mfa_verify" (para distinguir de access token)
/// </remarks>
public interface IMfaSessionStore
{
    /// <summary>
    /// Crea un token temporal de sesión MFA.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="method">Método MFA que se verificará.</param>
    /// <param name="validMinutes">Minutos de validez (default: 5).</param>
    /// <param name="secretFingerprint">
    /// Fingerprint (hash) del secreto TOTP al momento de iniciar el enrollment.
    /// Se usa en CompleteEnrollment para verificar que el secreto no cambió
    /// entre el inicio y la completación (anti-race). Null para métodos sin secreto (email).
    /// </param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Token JWT temporal.</returns>
    Task<string> CreateMfaSessionTokenAsync(
        string userId,
        string method,
        int validMinutes = 5,
        string? secretFingerprint = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Valida un token de sesión MFA y extrae el fingerprint del secreto asociado.
    /// </summary>
    /// <param name="token">Token JWT temporal.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El fingerprint del secreto o null si no existe / token inválido.</returns>
    Task<string?> GetMfaSessionTokenFingerprintAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Valida y consume el token de sesión MFA.
    /// </summary>
    /// <param name="token">Token JWT temporal.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El userId asociado o null si inválido/expirado.</returns>
    Task<string?> ConsumeMfaSessionTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Valida el token de sesión MFA sin consumirlo (solo extrae userId).
    /// </summary>
    /// <param name="token">Token JWT temporal.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El userId asociado o null si inválido/expirado.</returns>
    /// <remarks>
    /// DIDÁCTICA: Este método es para CompleteMfaLoginAsync donde necesitamos
    /// validar el token primero y luego verificar el código MFA (que consume el token).
    /// </remarks>
    Task<string?> ValidateMfaSessionTokenAsync(
        string token,
        CancellationToken cancellationToken = default);
}
