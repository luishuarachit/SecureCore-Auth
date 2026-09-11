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

    /// <summary>
    /// Si es true, el begin de login devuelve en <c>allowCredentials</c> los descriptores de las
    /// credenciales del userId indicado. Por defecto false (no se revelan; anti-enumeración).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (A-29): en WebAuthn el servidor PUEDE sugerir al autenticador qué credenciales
    /// debe considerar (<c>allowCredentials</c>). El problema de privacidad: si el usuario no
    /// existe o no tiene passkeys, el begin respondería con una lista vacía, y si existe y está
    /// enrollado, con sus descriptors → oráculo de cuentas (el atacante barre userIds y compara
    /// la forma). La guía del W3C recomienda NO devolver <c>allowCredentials</c> salvo necesidad.
    ///
    /// Con Discoverable Credentials (<see cref="RequireResidentKey"/> = true, default) el login
    /// funciona igual sin la pista: el autenticador propone sus credenciales residentes. Solo los
    /// despliegues con claves NO-residentes (RequireResidentKey=false) dependen de la pista; esos
    /// hosts pueden optar por <c>DiscloseCredentialsInLoginBegin = true</c> asumiendo la fuga de
    /// enrolamiento.
    /// </remarks>
    public bool DiscloseCredentialsInLoginBegin { get; set; } = false;

    /// <summary>
    /// Abre (o renueva) la ventana "mfa_verified" tras un login con passkey exitoso (S4/S3).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: una passkey con user verification (biometría, PIN) es un verificador
    /// autenticador de AAL2 en NIST SP 800-63B: el login por passkey prueba la posesión
    /// del factor criptográfico Y la activación por el usuario. Por eso es razonable que
    /// cuente como "verificación fuerte reciente" dentro de la ventana compartida
    /// <c>SecureAuthOptions.MfaVerifiedTtl</c> (S3).
    ///
    /// Solo tiene efecto si <c>IMfaVerifiedSessionStore</c> está registrado (AddMfa /
    /// AddVerifyAction / AddChangePassword); en caso contrario el host no consulta la
    /// ventana y la propiedad es inerte. Default true: maximiza la simetría con el login
    /// "password + mfa" (que ya abre la ventana), sin alterar ningún behavior previo
    /// porque este flujo no existía.
    /// </remarks>
    public bool OpenMfaVerifiedWindowOnPasskeyLogin { get; set; } = true;
}
