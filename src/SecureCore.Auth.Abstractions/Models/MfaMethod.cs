namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Métodos de autenticación multifactor (MFA) disponibles.
/// </summary>
public enum MfaMethod
{
    /// <summary>
    /// Sin método MFA.
    /// </summary>
    None = 0,

    /// <summary>
    /// TOTP (Time-based One-Time Password) - Google Authenticator, Authy, etc.
    /// </summary>
    Totp = 1,

    /// <summary>
    /// Código de verificación enviado por email.
    /// </summary>
    Email = 2
}