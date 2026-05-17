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
    /// <remarks>
    /// DIDÁCTICA: Guía completa para elegir el tiempo de vida adecuado de los Access Tokens.
    ///
    /// CONSIDERACIONES DE SEGURIDAD:
    /// - Un Access Token corto limita la ventana de ataque si el token es robado
    /// - Un Access Token largo mejora la UX pero aumenta el riesgo si es comprometido
    /// - El Refresh Token se usa para obtener nuevos Access Tokens sin re-autenticar
    ///
    /// ESCENARIOS RECOMENDADOS:
    ///
    /// --- 5-15 minutos (RECOMENDADO para apps sensibles) ---
    /// * Finanzas, banking, aplicaciones con datos médicos
    /// * Admin panels, sistemas de gestión
    /// * Cualquier app donde un token robado tiene alto impacto
    /// * Ventana de ataque pequeña: si roban el token, máximo 15 min de acceso
    /// * Requiere refresh token activo para renovación automática
    ///
    /// --- 15-30 minutos (DEFAULT - Balance UX/Seguridad) ---
    /// * Aplicaciones web normales
    /// * APIs con requisitos moderado de seguridad
    /// * Balance entre experiencia de usuario y protección
    /// * Recomendado para la mayoría de aplicaciones comerciales
    ///
    /// --- 1+ hora (NO RECOMENDADO - Solo casos especiales) ---
    /// * APIs internas detrás de firewall robusto
    /// * Microservicios en entorno seguro (no exposición directa a internet)
    /// * Aplicaciones donde el refresco causa problemas significativos de UX
    /// * ADVERTENCIA: El token robado tiene ventana de ataque extendida
    ///
    /// OPERACIONES SENSIBLES - RECOMENDACIONES:
    ///
    /// Para tareas administrativas críticas (pagos, eliminación de datos, cambios de
    /// configuración), considere implementar verificación adicional:
    ///
    /// 1. RE-AUTENTICACIÓN EXPLÍCITA: Para acciones críticas, solicite al usuario
    ///    confirmar su identidad con contraseña reciente o segundo factor.
    ///
    /// 2. SHORT-LIVED TOKENS PARA OPERACIONES: Cree tokens específicos con lifetime
    ///    reducido (ej: 5 min) solo para operaciones sensibles.
    ///
    /// 3. MACHINE LEARNING DE ANOMALÍAS: Monitoree patrones de uso para detectar
    ///    comportamiento sospechoso y forzar re-autenticación.
    ///
    /// EJEMPLO DE CONFIGURACIÓN:
    /// <code>
    /// // Para app bancaria - seguridad máxima
    /// options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
    /// options.RefreshTokenLifetime = TimeSpan.FromHours(24);  // Refresh frecuente
    ///
    /// // Para app web normal - balance
    /// options.AccessTokenLifetime = TimeSpan.FromMinutes(15);
    /// options.RefreshTokenLifetime = TimeSpan.FromDays(7);
    /// </code>
    ///
    /// NOTA SOBRE BLACKLIST: No implementamos blacklist de tokens por defecto.
    /// El Refresh Token Rotation junto con el SecurityStamp proporcionan mecanismos
    /// efectivos de revocación. Si necesita blacklist (ej: logout forzado por IP),
    /// impleméntelo manualmente con Redis u otro store.
    /// </remarks>
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
    ///
    /// Valor por defecto: 30 segundos. Con NTP moderno, los servidores tienen
    /// sincronización sub-segundo. Reducir de 5 minutos a 30 segundos reduce la
    /// ventana de ataque de 20 minutos (5min + 15min token) a 15.5 minutos.
    /// </remarks>
    [Required]
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Tiempo de vida de la caché del SecurityStamp. Por defecto: 1 minuto.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El SecurityStamp es un GUID que cambia cuando el usuario modifica
    /// su contraseña o revoca todas las sesiones. El claim "ssv" en el JWT permite
    /// invalidar todos los tokens activos instantáneamente.
    ///
    /// Valor por defecto: 1 minuto (reducido de 5 min). Con caché de 5 min, un token
    /// robado seguiría siendo válido hasta 5 minutos después de cambiar la contraseña.
    /// Con 1 minuto, la ventana de ataque se reduce significativamente.
    /// </remarks>
    [Required]
    public TimeSpan SecurityStampCacheDuration { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Número máximo de intentos de login permitidos por IP en la ventana de tiempo.
    /// Por defecto: 10 intentos por minuto.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Esta configuración complementa el bloqueo por cuenta (LockoutManager).
    /// Mientras LockoutManager protege cuentas individuales, IRateLimiter protege
    /// contra ataques distribuidos donde el atacante prueba muchas cuentas diferentes
    /// desde la misma IP.
    ///
    /// EJEMPLOS DE CONFIGURACIÓN:
    /// <code>
    /// // Seguridad estricta (5 intentos/min)
    /// options.RateLimiter.MaxAttempts = 5;
    /// options.RateLimiter.Window = TimeSpan.FromMinutes(1);
    ///
    /// // Balance (default: 10 intentos/min)
    /// options.RateLimiter.MaxAttempts = 10;
    /// options.RateLimiter.Window = TimeSpan.FromMinutes(1);
    ///
    /// // Permisivo (20 intentos/min) - solo para APIs internas
    /// options.RateLimiter.MaxAttempts = 20;
    /// options.RateLimiter.Window = TimeSpan.FromMinutes(1);
    /// </code>
    ///
    /// [OBSOLETO]: Use RateLimiter.MaxAttempts en su lugar. Esta propiedad se mantiene
    /// por compatibilidad hacia atrás pero será removida en una versión futura.
    /// </remarks>
    [Obsolete("Use RateLimiter.MaxAttempts instead. This property will be removed in a future version.")]
    [Range(1, 1000, ErrorMessage = "El máximo de intentos debe estar entre 1 y 1000.")]
    public int LoginRateLimitMaxAttempts { get; set; } = 10;

    /// <summary>
    /// Ventana de tiempo para el rate limiting de login. Por defecto: 1 minuto.
    /// </summary>
    /// <remarks>
    /// [OBSOLETO]: Use RateLimiter.Window en su lugar. Esta propiedad se mantiene
    /// por compatibilidad hacia atrás pero será removida en una versión futura.
    /// </remarks>
    [Obsolete("Use RateLimiter.Window instead. This property will be removed in a future version.")]
    [Required]
    public TimeSpan LoginRateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Configuración del mecanismo de locks para operaciones críticas.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Los locks se utilizan en operaciones como la rotación de Refresh Tokens
    /// para prevenir condiciones de carrera (race conditions) cuando múltiples solicitudes
    /// llegan simultáneamente.
    ///
    /// CONFIGURACIÓN RECOMENDADA:
    ///
    /// --- SINGLE-INSTANCE (default) ---
    /// No es necesario configurar nada. La librería usa InMemoryOperationLock
    /// internamente, que funciona perfectamente en despliegues con un solo servidor.
    ///
    /// --- MULTI-INSTANCIA / DISTRIBUIDO ---
    /// Para arquitecturas con múltiples servidores (load balancer), DEBE implementar
    /// su propio IOperationLock usando Redis, SQL Server, o cualquier store distribuido.
    ///
    /// EJEMPLO CON REDIS:
    /// <code>
    /// // Su implementación personalizada (no incluida en la librería)
    /// public class RedisOperationLock : IOperationLock
    /// {
    ///     private readonly IConnectionMultiplexer _redis;
    ///     public async Task&lt;IDisposable&gt; AcquireAsync(string key, TimeSpan timeout, CancellationToken ct)
    ///     {
    ///         var db = _redis.GetDatabase();
    ///         var acquired = await db.StringSetAsync($"lock:{key}", 1, timeout, When.NotExists);
    ///         if (!acquired) throw new TimeoutException($"No se pudo acquire lock: {key}");
    ///         return new RedisLockReleaser(db, $"lock:{key}");
    ///     }
    /// }
    ///
    /// // En su Program.cs:
    /// services.AddSingleton&lt;IOperationLock&gt;(new RedisOperationLock(redisConnection));
    /// </code>
    ///
    /// ADVERTENCIA:
    /// Si usa la implementación por defecto (InMemoryOperationLock) en un entorno
    /// distribuido, NO tendrá protección contra race conditions. Documente esta
    /// limitación claramente para sus operaciones de producción.
    /// </remarks>
    public OperationLockOptions OperationLock { get; set; } = new();

    /// <summary>
    /// Configuración del sistema de rate limiting.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El rate limiting complementa el bloqueo por cuenta (LockoutManager).
    /// Mientras LockoutManager protege cuentas individuales, RateLimiter protege
    /// contra ataques distribuidos donde el atacante prueba muchas cuentas/IPs.
    /// </remarks>
    public RateLimiterOptions RateLimiter { get; set; } = new();
}

/// <summary>
/// Opciones de configuración para el sistema de locks.
/// </summary>
public class OperationLockOptions
{
    /// <summary>
    /// Timeout por defecto para adquirir un lock. Por defecto: 5 segundos.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este timeout determina cuánto tiempo una solicitud esperará
    /// para adquirir un lock antes de fallar. En condiciones normales, el lock
    /// se adquiere en milisegundos. Un timeout excesivo puede indicar un problema
    /// más profundo (como un proceso bloqueado o un deadlock).
    ///
    /// Consideraciones:
    /// - 5 segundos es suficiente para la mayoría de casos (operaciones de BD típicas < 100ms)
    /// - Si las operaciones de su store son lentas (ej: bases de datos remotas), incremente el timeout
    /// - Si el timeout es muy corto, puede haber falsos positivos en situaciones de alta carga
    /// </remarks>
    [Range(1, 60, ErrorMessage = "El timeout del lock debe estar entre 1 y 60 segundos.")]
    public int TimeoutSeconds { get; set; } = 5;
}

/// <summary>
/// Opciones de configuración para el sistema de rate limiting.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El rate limiting protege contra ataques de fuerza bruta y DDoS.
/// Al igual que OperationLock, la implementación por defecto (InMemory) funciona
/// en single-instance pero NO en arquitecturas distribuidas.
///
/// CONFIGURACIÓN:
///
/// --- SINGLE-INSTANCE ---
/// La implementación por defecto (InMemoryRateLimiter) funciona correctamente.
/// Solo ajuste MaxAttempts y Window según sus necesidades.
///
/// --- MULTI-INSTANCIA ---
/// Para arquitecturas con múltiples servidores, debe implementar IRateLimiter
/// con un store distribuido (Redis, etc.) o usar middleware como AspNetCoreRateLimiter.
///
/// EJEMPLO CON REDIS:
/// <code>
/// public class RedisRateLimiter : IRateLimiter
/// {
///     private readonly IConnectionMultiplexer _redis;
///     private readonly int _maxAttempts;
///     private readonly TimeSpan _window;
///
///     public RedisRateLimiter(IConnectionMultiplexer redis, int maxAttempts, TimeSpan window)
///     {
///         _redis = redis;
///         _maxAttempts = maxAttempts;
///         _window = window;
///     }
///
///     public bool IsAllowed(string key)
///     {
///         var db = _redis.GetDatabase();
///         var current = db.StringIncrementAsync($"ratelimit:{key}").Result;
///         if (current == 1)
///             db.KeyExpireAsync($"ratelimit:{key}", _window);
///         return current <= _maxAttempts;
///     }
///     
///     // ... Reset y GetRemainingAttempts implementados similarly
/// }
/// 
/// // En Program.cs:
/// services.AddSingleton&lt;IRateLimiter&gt;(new RedisRateLimiter(redis, 10, TimeSpan.FromMinutes(1)));
/// </code>
///
/// ADVERTENCIA:
/// Si usa InMemoryRateLimiter en producción distribuida, los atacantes pueden
/// evadir los límites distribuyendo requests entre servidores. Documente esta
/// limitación y considere usar Redis o middleware de rate limiting.
/// </remarks>
public class RateLimiterOptions
{
    /// <summary>
    /// Número máximo de intentos permitidos en la ventana de tiempo.
    /// Por defecto: 10.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este valor determina cuántos intentos se permiten antes de
    /// bloquear. Valores comunes:
    /// - 5: Estricto, para APIs sensibles (banca, salud)
    /// - 10: Balance (recomendado para la mayoría)
    /// - 20-50: Permisivo, solo para APIs internas
    /// </remarks>
    [Range(1, 1000, ErrorMessage = "El máximo de intentos debe estar entre 1 y 1000.")]
    public int MaxAttempts { get; set; } = 10;

    /// <summary>
    /// Ventana de tiempo para contar los intentos. Por defecto: 1 minuto.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: La ventana de tiempo define el periodo de conteo.
    /// - 1 minuto: Estándar, buena detección de ataques rápidos
    /// - 5-15 minutos: Para APIs con mayor tolerancia
    /// - 1 hora+: Solo para operaciones muy costosas (no recomendado)
    /// </remarks>
    [Required]
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}
