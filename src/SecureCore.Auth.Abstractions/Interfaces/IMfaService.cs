using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el servicio principal de orquestación MFA.
/// </summary>
public interface IMfaService
{
    /// <summary>
    /// Inicia el proceso de enrollment MFA para un usuario.
    /// </summary>
    Task<MfaEnrollmentResponse> StartEnrollmentAsync(
        string userId,
        MfaMethod method,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Completa el enrollment verificando el código inicial.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="code">Código MFA de verificación.</param>
    /// <param name="mfaSessionToken">
    /// Token de sesión MFA devuelto por <see cref="StartEnrollmentAsync"/>. Se valida
    /// y consume (single-use) para garantizar que solo quien inició el enrollment
    /// puede completarlo.
    /// </param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task<bool> CompleteEnrollmentAsync(
        string userId,
        string code,
        string mfaSessionToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verifica un código MFA (para login).
    /// </summary>
    Task<MfaVerificationResult> VerifyAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deshabilita MFA para un usuario (requiere password actual).
    /// </summary>
    Task<bool> DisableAsync(
        string userId,
        string password,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene los métodos MFA disponibles para un usuario.
    /// </summary>
    Task<List<MfaMethodInfo>> GetUserMethodsAsync(
        string userId,
        CancellationToken cancellationToken = default);
}
