using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
    /// Opciones de configuración para la generación y validación de JWT.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Un JWT (JSON Web Token) necesita tres configuraciones clave:
    /// - Issuer ("quién lo emitió"): generalmente el dominio de tu API.
    /// - Audience ("para quién es"): generalmente el dominio del cliente.
    /// - Algoritmo de firma: HS256 (simétrico) o RS256/ES256 (asimétrico).
    ///
    /// SEGURIDAD: Recomendamos RS256 o ES256 (asimétrico) para producción:
    /// - HS256 usa la MISMA clave para firmar y validar. Si se filtra, cualquiera puede伪造 tokens.
    /// - RS256/ES256 usa una CLAVE PRIVADA para firmar y una CLAVE PÚBLICA para validar.
    ///   La clave pública puede distribuirse, pero la privada debe mantenerse en secreto.
    ///
    /// NUNCA HARDCODEES CLAVES EN EL CÓDIGO. Usa variables de entorno o Azure Key Vault.
    /// </remarks>
public class JwtOptions
{
    /// <summary>
    /// Sección del archivo de configuración.
    /// </summary>
    public const string SectionName = "SecureAuth:Jwt";

    /// <summary>
    /// Emisor del token (ej: "miapp.com").
    /// </summary>
    [Required(ErrorMessage = "El emisor (Issuer) es obligatorio.")]
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Audiencia del token (ej: "miapp-api").
    /// </summary>
    [Required(ErrorMessage = "La audiencia (Audience) es obligatoria.")]
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Clave secreta para firmar tokens con algoritmos simétricos (HS256).
    /// Mínimo 32 caracteres requeridos para HMAC-SHA256.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Solo necesario si Algorithm es "HS256". Para RS256/ES256, usar PrivateKey en su lugar.
    /// </remarks>
    [MinLength(32, ErrorMessage = "La SigningKey debe tener al menos 32 caracteres (256 bits).")]
    public string? SigningKey { get; set; }

    /// <summary>
    /// Clave privada RSA o ECDSA en formato PEM para firmar tokens (RS256/ES256).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Solo necesario si Algorithm es "RS256" o "ES256". Formato PEM esperado:
    /// -----BEGIN RSA PRIVATE KEY----- ... -----END RSA PRIVATE KEY-----
    /// </remarks>
    public string? PrivateKey { get; set; }

    /// <summary>
    /// Clave pública RSA o ECDSA en formato PEM para validar tokens (RS256/ES256).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Solo necesario si Algorithm es "RS256" o "ES256". Formato PEM esperado:
    /// -----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----
    /// La clave pública puede compartirse libremente (no es sensible).
    /// </remarks>
    public string? PublicKey { get; set; }

    /// <summary>
    /// Algoritmo de firma. Por defecto: RS256 (recomendado).
    /// </summary>
    /// <remarks>
    /// Valores válidos: "HS256", "RS256", "ES256", "ES384", "ES512".
    /// Recomendamos "RS256" o "ES256" para producción.
    /// </remarks>
    [Required]
    public string Algorithm { get; set; } = "RS256";
}
