namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de configuración para WebAuthn/Passkeys (FIDO2).
/// </summary>
/// <remarks>
/// DIDÁCTICA: WebAuthn es un estándar del W3C que permite autenticación sin contraseñas
/// usando biometría (huella, Face ID) o llaves de seguridad físicas (YubiKey).
/// El servidor (Relying Party) necesita identificarse ante el autenticador del cliente
/// con un nombre legible y un ID de dominio. El Origin es el dominio completo
/// desde donde se hace la solicitud (debe coincidir con el dominio del navegador).
/// </remarks>
public class WebAuthnOptions
{
    /// <summary>
    /// Sección del archivo de configuración.
    /// </summary>
    public const string SectionName = "SecureAuth:WebAuthn";

    /// <summary>
    /// Nombre legible del servidor (Relying Party). Se muestra al usuario en el diálogo
    /// de autenticación (ej: "Mi Aplicación").
    /// </summary>
    public string RelyingPartyName { get; set; } = string.Empty;

    /// <summary>
    /// ID del Relying Party. Generalmente el dominio sin protocolo (ej: "miapp.com").
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El RelyingPartyId debe coincidir con el dominio o un subdominio del sitio.
    /// Si tu app está en "auth.miapp.com", puedes usar "miapp.com" como RPID para que
    /// las credenciales funcionen en todos los subdominios.
    /// </remarks>
    public string RelyingPartyId { get; set; } = string.Empty;

    /// <summary>
    /// Orígenes permitidos (ej: "https://miapp.com"). Pueden ser múltiples.
    /// </summary>
    public HashSet<string> Origins { get; set; } = [];

    /// <summary>
    /// Tiempo en segundos que un challenge es válido. Por defecto: 60 segundos.
    /// </summary>
    public int ChallengeTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Tipo de autenticador preferido. "platform" para biometría integrada,
    /// "cross-platform" para llaves USB, o null para cualquiera.
    /// </summary>
    public string? AuthenticatorAttachment { get; set; }

    /// <summary>
    /// Política de verificación del usuario. "required", "preferred" o "discouraged".
    /// </summary>
    public string UserVerification { get; set; } = "preferred";

    /// <summary>
    /// Si es true, habilita Discoverable Credentials (login sin username).
    /// </summary>
    public bool RequireResidentKey { get; set; } = true;
}
