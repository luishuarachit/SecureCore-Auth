using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de configuración para el sistema de restablecimiento de contraseñas.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Las opciones de restablecimiento permiten equilibrar seguridad y usabilidad.
/// Un tiempo de vida corto (15 min) reduce la ventana de exposición del token, 
/// mientras que el rate limiting previene el abuso del servicio de e-mail y ataques de denegación de servicio (DoS).
/// </remarks>
public class PasswordResetOptions
{
    /// <summary>
    /// Sección del archivo de configuración (appsettings.json) donde se leen estas opciones.
    /// </summary>
    public const string SectionName = "SecureAuth:PasswordReset";

    /// <summary>
    /// Tiempo de vida de un token de restablecimiento generado, en minutos.
    /// Por defecto: 15 minutos.
    /// </summary>
    [Range(1, 1440, ErrorMessage = "El tiempo de vida del token debe estar entre 1 y 1440 minutos (1 día)")]
    public int TokenLifetimeMinutes { get; set; } = 15;

    /// <summary>
    /// Longitud en bytes de la porción aleatoria que conforma el token crudo.
    /// Default: 32 bytes (256 bits de seguridad real).
    /// </summary>
    [Range(16, 64, ErrorMessage = "El tamaño del token proporcionado está fuera del rango criptográficamente seguro permitido (16-64 bytes)")]
    public int TokenSizeBytes { get; set; } = 32;

    /// <summary>
    /// Cantidad máxima permitida de solicitudes de restablecimiento por usuario durante una hora.
    /// Utilizado para evadir bombardeo en el enlace de recuperación y SPAM.
    /// Valor '0' desactiva el rate limiting integrado (requiere que <see cref="Interfaces.IPasswordResetStore.CountRecentRequestsAsync(string, DateTime, CancellationToken)"/> simplemente retorne siempre 0 o que la lógica ignore este parámetro internamente).
    /// Default: 3
    /// </summary>
    [Range(0, 100, ErrorMessage = "El máximo número de peticiones por hora debe encontrarse entre 0 y 100")]
    public int MaxRequestsPerHour { get; set; } = 3;
}
