namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Estado de entrega del email asociado a un token de restablecimiento de contraseña.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El token se persiste ANTES de enviar el email para permitir reintentos sin
/// perder el estado (consistencia transaccional). Este estado permite distinguir un token
/// cuyo email llegó (<see cref="Dispatched"/>) de uno cuyo envío falló (<see cref="Failed"/>)
/// para auditoría y limpieza, sin eliminar el token (el flujo puede reintentarse).
/// </remarks>
public enum PasswordResetDeliveryState
{
    /// <summary>
    /// El token fue persistido pero el email aún no se ha enviado correctamente.
    /// </summary>
    Pending = 0,

    /// <summary>
    /// El email con el token fue enviado exitosamente por el mailer.
    /// </summary>
    Dispatched = 1,

    /// <summary>
    /// El envío del email falló. El token permanece persistido para permitir reintentos
    /// (o limpieza manual), pero queda marcado como no entregado.
    /// </summary>
    Failed = 2
}
