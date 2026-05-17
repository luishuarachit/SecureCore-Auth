namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Información de un método MFA disponible para el usuario.
/// </summary>
public record MfaMethodInfo(
    /// <summary>
    /// Método MFA.
    /// </summary>
    MfaMethod Method,

    /// <summary>
    /// Nombre para mostrar del método.
    /// </summary>
    string DisplayName,

    /// <summary>
    /// Indica si el usuario ya tiene este método configurado.
    /// </summary>
    bool IsEnrolled
);

/// <summary>
/// Resultado de verificación MFA.
/// </summary>
public record MfaVerificationResult(
    /// <summary>
    /// Indica si la verificación fue exitosa.
    /// </summary>
    bool Success,

    /// <summary>
    /// Mensaje de error si la verificación falló.
    /// </summary>
    string? ErrorMessage,

    /// <summary>
    /// Método MFA verificado (para incluir en claims JWT).
    /// </summary>
    MfaMethod? VerifiedMethod
);

/// <summary>
/// Respuesta de inicio de enrollment.
/// </summary>
public record MfaEnrollmentResponse(
    /// <summary>
    /// Método MFA solicitado.
    /// </summary>
    MfaMethod Method,

    /// <summary>
    /// URI otpauth:// para TOTP (null para email).
    /// </summary>
    string? TotpAuthUri,

    /// <summary>
    /// Token de sesión MFA para completar enrollment.
    /// </summary>
    string MfaSessionToken
);