using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones generales de configuración del sistema de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Usamos el patrón IOptions&lt;T&gt; de .NET para la configuración.
/// Esto permite configurar la librería desde appsettings.json, variables de entorno,
/// o directamente en código mediante la Fluent API. Nunca se hardcodean valores sensibles.
/// </remarks>
public class SecureAuthOptions
{
    /// <summary>
    /// Sección del archivo de configuración donde se leen estas opciones.
    /// </summary>
    public const string SectionName = "SecureAuth";

    /// <summary>
    /// Tiempo de vida del Access Token (JWT). Por defecto: 15 minutos.
    /// </summary>
    [Required]
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Tiempo de vida del Refresh Token. Por defecto: 7 días.
    /// </summary>
    [Required]
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Periodo de gracia (en segundos) para la rotación de Refresh Tokens.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Si el cliente envía el mismo Refresh Token dos veces en un periodo
    /// muy corto (ej: por una red inestable), no lo consideramos un ataque.
    /// Este valor define cuántos segundos se tolera este comportamiento.
    /// </remarks>
    [Range(0, 300, ErrorMessage = "El periodo de gracia debe estar entre 0 y 300 segundos.")]
    public int GracePeriodSeconds { get; set; } = 30;

    /// <summary>
    /// Número máximo de intentos fallidos antes de bloquear la cuenta.
    /// </summary>
    [Range(1, 100, ErrorMessage = "El máximo de intentos fallidos debe estar entre 1 y 100.")]
    public int MaxFailedAttempts { get; set; } = 5;

    /// <summary>
    /// Duraciones de bloqueo en orden ascendente (bloqueo exponencial).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El bloqueo exponencial aumenta la duración con cada bloqueo consecutivo:
    /// 1er bloqueo: 1 minuto, 2do: 5 min, 3ro: 15 min, 4to: 1 hora.
    /// Esto hace que los ataques de fuerza bruta sean impracticables.
    /// </remarks>
    [Required]
    public TimeSpan[] LockoutDurations { get; set; } =
    [
        TimeSpan.FromMinutes(1),
        TimeSpan.FromMinutes(5),
        TimeSpan.FromMinutes(15),
        TimeSpan.FromHours(1)
    ];

    /// <summary>
    /// Tolerancia de reloj para la validación de JWT (Clock Skew).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Los relojes de diferentes servidores pueden estar ligeramente
    /// desincronizados. Esta tolerancia evita que un token sea rechazado por
    /// una diferencia de segundos entre el servidor que lo emitió y el que lo valida.
    /// </remarks>
    [Required]
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Tiempo de vida de la caché del SecurityStamp. Por defecto: 5 minutos.
    /// </summary>
    [Required]
    public TimeSpan SecurityStampCacheDuration { get; set; } = TimeSpan.FromMinutes(5);
}
