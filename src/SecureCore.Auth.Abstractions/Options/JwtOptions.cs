using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de configuración para la generación y validación de JWT.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Un JWT (JSON Web Token) necesita tres configuraciones clave:
/// - Issuer ("quién lo emitió"): generalmente el dominio de tu API.
/// - Audience ("para quién es"): generalmente el dominio del cliente.
/// - SigningKey ("con qué se firma"): una clave secreta para garantizar integridad.
/// NUNCA HARDCODEES LA SIGNING KEY EN EL CÓDIGO. Usa variables de entorno o Azure Key Vault.
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
    /// Clave secreta para firmar los tokens. Mínimo 32 caracteres requeridos para HS256.
    /// </summary>
    [Required(ErrorMessage = "La clave de firma (SigningKey) es obligatoria.")]
    [MinLength(32, ErrorMessage = "La clave de firma debe tener al menos 32 caracteres (256 bits).")]
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>
    /// Algoritmo de firma. Por defecto: HMAC-SHA256.
    /// </summary>
    [Required]
    public string Algorithm { get; set; } = "HS256";
}
