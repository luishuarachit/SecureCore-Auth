namespace SecureCore.Auth.Abstractions;

/// <summary>
/// Representa la identidad de un usuario en el sistema.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Usamos un record en lugar de una clase para garantizar inmutabilidad.
/// Un record genera automáticamente Equals, GetHashCode y ToString basados en sus propiedades.
/// Esto es ideal para DTOs (Data Transfer Objects) porque evita modificaciones accidentales.
/// </remarks>
public record UserIdentity
{
    /// <summary>
    /// Identificador único del usuario (generalmente un GUID).
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Dirección de correo electrónico del usuario.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// Hash de la contraseña del usuario (puede ser null si usa solo Passkeys u OAuth).
    /// </summary>
    public string? PasswordHash { get; init; }

    /// <summary>
    /// Sello de seguridad: un GUID que se regenera al cerrar todas las sesiones.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El SecurityStamp es el mecanismo central para la revocación global.
    /// Se incluye en cada JWT como claim "ssv" (Security Stamp Version).
    /// Al cambiar este GUID, todos los tokens emitidos con el valor anterior
    /// serán rechazados automáticamente por el middleware de validación.
    /// </remarks>
    public required string SecurityStamp { get; init; }

    /// <summary>
    /// Número de intentos fallidos de login consecutivos.
    /// </summary>
    public int FailedAccessCount { get; init; }

    /// <summary>
    /// Fecha/hora UTC en que expira el bloqueo de cuenta (null si no está bloqueada).
    /// </summary>
    public DateTimeOffset? LockoutEnd { get; init; }

    /// <summary>
    /// Indica si el usuario tiene habilitada la autenticación de dos factores.
    /// </summary>
    public bool TwoFactorEnabled { get; init; }

    /// <summary>
    /// Nombre para mostrar del usuario (opcional).
    /// </summary>
    public string? DisplayName { get; init; }

    /// <summary>
    /// Claims adicionales para incluir en el JWT.
    /// </summary>
    public Dictionary<string, string>? Claims { get; init; }

    /// <summary>
    /// Método MFA preferido del usuario ("totp" | "email").
    /// </summary>
    public string? PreferredMfaMethod { get; init; }

    /// <summary>
    /// Secreto TOTP cifrado (AES-256-GCM).
    /// </summary>
    public string? TotpSecretEncrypted { get; init; }

    /// <summary>
    /// Estado del enrollment MFA.
    /// </summary>
    public Models.MfaEnrollmentStatus MfaEnrollmentStatus { get; init; }

    /// <summary>
    /// Códigos de recuperación (hash SHA-256, un solo uso).
    /// </summary>
    public List<string>? RecoveryCodeHashes { get; init; }

    /// <summary>
    /// Fecha UTC del último uso exitoso de MFA.
    /// </summary>
    public DateTimeOffset? LastMfaVerifiedAt { get; init; }

    /// <summary>
    /// Contador de intentos fallidos de verificación MFA.
    /// Se resetea tras éxito o tras ventana de tiempo.
    /// </summary>
    public int MfaFailedAttemptsCount { get; init; }

    /// <summary>
    /// Fecha UTC en que el usuario completó el enrollment MFA.
    /// </summary>
    public DateTimeOffset? MfaEnrolledAt { get; init; }
}
