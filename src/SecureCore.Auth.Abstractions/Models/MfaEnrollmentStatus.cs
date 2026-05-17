namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Estado del enrollment de autenticación multifactor (MFA).
/// </summary>
public enum MfaEnrollmentStatus
{
    /// <summary>
    /// El usuario no ha iniciado enrollment MFA.
    /// </summary>
    None = 0,

    /// <summary>
    /// Enrollment en proceso (TOTP/email no verificado).
    /// </summary>
    Pending = 1,

    /// <summary>
    /// MFA activo y verificado.
    /// </summary>
    Enrolled = 2,

    /// <summary>
    /// MFA deshabilitado por el usuario.
    /// </summary>
    Disabled = 3
}