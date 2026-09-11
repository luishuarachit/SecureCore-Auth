using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de la verificación de acciones sensibles (S3, step-up / verify-action).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El step-up permite exigir una verificación temporal (OTP por email)
/// antes de mutaciones sensibles (crear contraseña, cambiar credenciales, etc.).
///
/// La sesión resultante ("verify-action verificada") se marca sobre la ventana
/// compartida <c>SecureAuthOptions.MfaVerifiedTtl</c> (S3): una vez verificado, el
/// host decide cuánto tiempo concede para completar la acción sin repetir el OTP.
/// </remarks>
public class VerifyActionOptions
{
    /// <summary>
    /// Sección del archivo de configuración: "SecureAuth:VerifyAction".
    /// </summary>
    public const string SectionName = "SecureAuth:VerifyAction";

    /// <summary>
    /// Tiempo de vida del código OTP (en minutos). Por defecto: 5 minutos.
    /// </summary>
    [Range(1, 15, ErrorMessage = "El TTL del OTP debe estar entre 1 y 15 minutos.")]
    public int TtlMinutes { get; set; } = 5;

    /// <summary>
    /// Longitud del código numérico (6-8 dígitos). Por defecto: 6.
    /// </summary>
    [Range(6, 8, ErrorMessage = "La longitud del código debe estar entre 6 y 8 dígitos.")]
    public int CodeLength { get; set; } = 6;

    /// <summary>
    /// Máximo de envíos de código por usuario dentro de la ventana (<see cref="TtlMinutes"/>).
    /// Por defecto: 3.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (H1, auditoría): este tope aplica SIEMPRE (tanto si S1 está activo
    /// como si no) y es la barrera mínima contra el brute-force del OTP: sin él, un
    /// atacante con una sesión válida podría emitir códigos sin límite (un intento
    /// de adivinación por cada envío) y agotar el espacio de 10^6 combinaciones.
    /// S1 añade lockout escalonado y reintentos limitados; el throttle dura por
    /// ventana es la red de seguridad que no depende de opt-in.
    /// </remarks>
    [Range(1, 10, ErrorMessage = "El máximo de envíos por ventana debe estar entre 1 y 10.")]
    public int MaxSendsPerWindow { get; set; } = 3;
}

/// <summary>
/// Canal de entrega soportado para la verificación de acciones sensibles.
/// </summary>
public enum VerifyActionChannel
{
    /// <summary>Correo electrónico (único canal soportado en esta versión).</summary>
    Email
}
