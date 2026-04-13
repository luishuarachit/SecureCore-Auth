namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Resultado de la operación de confirmación o solicitud de restablecimiento de contraseña.
/// </summary>
public enum PasswordResetResult
{
    /// <summary>
    /// La operación se completó exitosamente (contraseña cambiada y sesiones revocadas).
    /// </summary>
    Success,

    /// <summary>
    /// El token provisto no es válido: puede que no exista, haya expirado o ya haya sido marcado como utilizado.
    /// </summary>
    InvalidToken,

    /// <summary>
    /// Se ha excedido la cantidad límite de solicitudes permitidas durante el periodo actual.
    /// Utilizado internamente para propósitos de limitación de tasa (rate limiting).
    /// En los endpoints (para evitar enumeración y fuga de información) debe ocultarse detrás de un mensaje genérico de "éxito".
    /// </summary>
    RateLimitExceeded
}
