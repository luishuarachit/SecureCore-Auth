using System.Collections.ObjectModel;

namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Evento de dominio del sistema de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los eventos de dominio permiten desacoplar la lógica principal de los
/// efectos secundarios. Cuando ocurre algo importante (login exitoso, rotación de token,
/// actividad sospechosa), se dispara un evento que otros componentes pueden escuchar.
/// Esto permite agregar funcionalidad (auditoría, notificaciones, métricas) sin
/// modificar el código original.
/// </remarks>
public record AuthEvent
{
    /// <summary>
    /// Tipo de evento que ocurrió.
    /// </summary>
    public required AuthEventType EventType { get; init; }

    /// <summary>
    /// ID del usuario relacionado con el evento. Null para eventos anónimos
    /// (ej. login fallido con email desconocido, rate limit excedido).
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// Fecha/hora UTC en que ocurrió el evento.
    /// </summary>
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Metadatos adicionales del evento (ej: IP, user-agent, motivo).
    /// </summary>
    public IReadOnlyDictionary<string, string> Metadata { get; init; } =
        ReadOnlyDictionary<string, string>.Empty;
}

/// <summary>
/// Tipos de eventos que puede emitir el sistema de autenticación.
/// </summary>
public enum AuthEventType
{
    /// <summary>Inicio de sesión exitoso.</summary>
    LoginSuccess,

    /// <summary>Intento de inicio de sesión fallido.</summary>
    LoginFailed,

    /// <summary>Cuenta bloqueada por exceso de intentos fallidos.</summary>
    AccountLockedOut,

    /// <summary>Refresh Token rotado exitosamente.</summary>
    TokenRotated,

    /// <summary>Cierre de sesión individual.</summary>
    Logout,

    /// <summary>
    /// Cierre de todas las sesiones (botón de pánico).
    /// </summary>
    GlobalLogout,

    /// <summary>
    /// Actividad sospechosa detectada (reuso de Refresh Token fuera del periodo de gracia).
    /// </summary>
    SuspiciousActivityDetected,

    /// <summary>Nueva credencial WebAuthn/Passkey registrada.</summary>
    PasskeyRegistered,

    /// <summary>Inicio de sesión con Passkey exitoso.</summary>
    PasskeyLoginSuccess,

    /// <summary>Token de restablecimiento de contraseña solicitado.</summary>
    PasswordResetRequested,

    /// <summary>Contraseña restablecida exitosamente.</summary>
    PasswordResetCompleted,

    /// <summary>Usuario completó el enrollment MFA.</summary>
    MfaEnrolled,

    /// <summary>Verificación MFA exitosa durante login.</summary>
    MfaVerificationSuccess,

    /// <summary>Verificación MFA fallida durante login.</summary>
    MfaVerificationFailed,

    /// <summary>Usuario deshabilitó MFA.</summary>
    MfaDisabled,

    /// <summary>Rate limit excedido (por IP o por cuenta).</summary>
    RateLimitExceeded,

    /// <summary>Intento de login anónimo fallido (email/usuario no existe).</summary>
    AnonymousLoginFailed,

    /// <summary>Verificación de Passkey fallida.</summary>
    PasskeyVerificationFailed,

    /// <summary>Security Stamp cambiado (revocación global ejecutada).</summary>
    SecurityStampChanged,

    /// <summary>Cambio de contraseña fallido (contraseña actual incorrecta).</summary>
    PasswordChangeFailed
}
