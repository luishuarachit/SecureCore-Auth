namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Representa un token de restablecimiento de contraseña generado y almacenado en el sistema.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este modelo se usa en la capa de persistencia (<see cref="Interfaces.IPasswordResetStore"/>).
/// En lugar de almacenar el token en texto plano, guardamos un hash derivado del mismo.
/// Esto evita que los atacantes que obtengan acceso de solo lectura a la base de datos
/// puedan usar los tokens para restablecer contraseñas de manera no autorizada.
/// </remarks>
public record PasswordResetEntry
{
    /// <summary>
    /// Hash criptográfico (usualmente SHA-256) del token crudo en Base64Url.
    /// Funciona como la llave primaria o identificador único para buscar en la base de datos.
    /// </summary>
    public required string TokenHash { get; init; }

    /// <summary>
    /// El identificador único del usuario (por ejemplo un GUID) al cual pertenece este token.
    /// </summary>
    public required string UserId { get; init; }

    /// <summary>
    /// Fecha y hora exacta en tiempo universal coordinado (UTC) donde este token expira.
    /// Si la fecha actual supera este valor, el token se considera inválido.
    /// </summary>
    public required DateTime ExpiresAtUtc { get; init; }

    /// <summary>
    /// Indica si el token ya ha sido consumido de forma exitosa.
    /// Un token solo puede ser utilizado una vez.
    /// </summary>
    public bool IsUsed { get; init; } = false;

    /// <summary>
    /// Estado de entrega del email asociado a este token. Por defecto: <see cref="PasswordResetDeliveryState.Pending"/>.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El token se persiste con estado <c>Pending</c>. Tras un envío exitoso del
    /// email se marca <see cref="PasswordResetDeliveryState.Dispatched"/>, y si el envío falla
    /// <see cref="PasswordResetDeliveryState.Failed"/>. Esto permite auditoría y limpieza de
    /// tokens huérfanos respetando la decisión de persistir antes de enviar.
    /// </remarks>
    public PasswordResetDeliveryState DeliveryState { get; init; } = PasswordResetDeliveryState.Pending;

    /// <summary>
    /// Fecha de creación del token. Útil para auditoría y conteo en mecanismos de Limitación de Tasas (Rate Limiting).
    /// </summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Propiedad calculada que verifica si la fecha actual ha sobrepasado a <see cref="ExpiresAtUtc"/>.
    /// </summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAtUtc;
}
