using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de configuración para autenticación multifactor (MFA).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El sistema MFA es completamente configurable. El implementador
/// controla si está habilitado globalmente, qué métodos permite, si es obligatorio,
/// y si los usuarios pueden activar/desactivar MFA por su cuenta.
///
/// Esta configuración sigue el principio de "defense in depth":
/// - disabled por defecto (opt-in)
/// - métodos permitidos explícitos
/// - rate limiting integrado
/// </remarks>
public class MfaOptions
{
    public const string SectionName = "SecureAuth:Mfa";

    /// <summary>
    /// Indica si MFA está habilitado globalmente. Por defecto: false.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: MFA está disabled por defecto para mantener backward compatibility.
    /// El implementador debe habilitarlo explícitamente.
    /// </remarks>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Indica si MFA es requerido por defecto para todos los usuarios.
    /// </summary>
    /// <remarks>
    /// Si true, los usuarios sin enrollment activo verán TwoFactorRegistrationRequired.
    /// </remarks>
    public bool RequiredByDefault { get; set; } = false;

    /// <summary>
    /// Lista de métodos MFA permitidos. Por defecto: ["totp", "email"].
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El implementador puede reducir esta lista. Por ejemplo,
    /// ["totp"] para solo TOTP, ["email"] para solo email codes.
    /// </remarks>
    public List<string> AllowedMethods { get; set; } = ["totp", "email"];

    /// <summary>
    /// Indica si los usuarios pueden activar MFA voluntariamente.
    /// Por defecto: true.
    /// </summary>
    public bool AllowUserEnrollment { get; set; } = true;

    /// <summary>
    /// Indica si los usuarios pueden deshabilitar su MFA activo.
    /// Por defecto: true.
    /// </summary>
    public bool AllowUserDisable { get; set; } = true;

    /// <summary>
    /// Indica si los códigos de recuperación están habilitados.
    /// Por defecto: false (no recomendado).
    /// </summary>
    /// <remarks>
    /// ⚠️ ADVERTENCIA: Los códigos de recuperación reducen la seguridad del MFA.
    /// Un atacante con acceso al email/contraseña puede usar un código de recuperación
    /// si el dispositivo principal no está disponible. Se recomienda no habilitar.
    ///
    /// Si se habilitan, los códigos deben tener ALTA ENTROPÍA (mínimo 32 caracteres
    /// aleatorios) para resistir ataques de fuerza bruta offline si la BD se compromete.
    /// Alternativamente, usar PBKDF2/Argon2id para el hash (más costoso computacionalmente).
    /// </remarks>
    public bool EnableRecoveryCodes { get; set; } = false;

    /// <summary>
    /// Número de códigos de recuperación generados.
    /// Por defecto: 10.
    /// </summary>
    [Range(1, 20)]
    public int RecoveryCodeCount { get; set; } = 10;

    /// <summary>
    /// Emisor shown en el QR code TOTP (app authenticator).
    /// Por defecto: "AuthCore".
    /// </summary>
    public string TotpIssuer { get; set; } = "AuthCore";

    /// <summary>
    /// Tiempo de vida del código de verificación por email (en minutos).
    /// Por defecto: 5 minutos.
    /// </summary>
    [Range(1, 30)]
    public int EmailCodeLifetimeMinutes { get; set; } = 5;

    /// <summary>
    /// Longitud del código numérico (6-8 dígitos).
    /// Por defecto: 6.
    /// </summary>
    [Range(6, 8)]
    public int EmailCodeLength { get; set; } = 6;

    /// <summary>
    /// Intentos máximos de verificación de código antes de bloquear temporalmente.
    /// Por defecto: 5.
    /// </summary>
    [Range(3, 10)]
    public int MaxVerificationAttempts { get; set; } = 5;

    /// <summary>
    /// Ventana de tiempo para reintentos de verificación (en minutos).
    /// Por defecto: 3 minutos.
    /// </summary>
    [Range(1, 15)]
    public int CodeRetryWindowMinutes { get; set; } = 3;

    /// <summary>
    /// Tiempo de validez del token de sesión MFA (en minutos).
    /// Por defecto: 5 minutos (estándar industria).
    /// </summary>
    [Range(1, 15)]
    public int MfaSessionTokenMinutes { get; set; } = 5;

    /// <summary>
    /// Clave de cifrado para el secreto TOTP (256 bits).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Esta clave se usa para cifrar el secreto TOTP antes de guardarlo
    /// en la base de datos. Debe ser una cadena de 64 caracteres hexadecimales
    /// (equivalente a 256 bits).
    ///
    /// Genere una clave con:
    /// <code>
    /// var key = new byte[32];
    /// RandomNumberGenerator.Fill(key);
    /// var hexKey = Convert.ToHexString(key).ToLowerInvariant();
    /// </code>
    ///
    /// IMPORTANTE: Esta clave debe mantenerse segura (variables de entorno, Azure Key Vault, etc.).
    /// Si se pierde, los secretos TOTP almacenados no podrán descifrarse.
    /// </remarks>
    [MinLength(64, ErrorMessage = "La clave de cifrado debe tener 64 caracteres (256 bits).")]
    [RegularExpression("^[a-f0-9]{64}$", ErrorMessage = "La clave debe ser formato hex de 64 caracteres.")]
    public string EncryptionKey { get; set; } = string.Empty;
}