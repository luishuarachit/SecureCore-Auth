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
}
