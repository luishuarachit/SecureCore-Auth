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
    Task<bool> CompleteEnrollmentAsync(
        string userId,
        string code,
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