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

    /// <summary>
    /// Configuración del rate limiting por IP para el endpoint anónimo de /forgot-password.
    /// Por defecto: 5 solicitudes por hora por IP.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (Nº5): /forgot-password es un endpoint anónimo (sin autenticación), vector
    /// clásico de abuso: enumeración masiva de emails, bombardeo de correos de reset y
    /// costes de almacenamiento. El throttling aquí debe ser SILENCIOSO: al superarse el
    /// límite el endpoint sigue devolviendo el 200 ciego habitual, sin 429 ni mensajes
    /// distintos, para no dar al atacante feedback sobre cuándo se le limita ni abrir un
    /// oráculo adicional.
    ///
    /// Se implementa con un limiter dedicado (keyed DI "forgot-password") para NO compartir
    /// el presupuesto con el de login. Al igual que <see cref="RateLimiter"/>, la
    /// implementación por defecto (InMemory) funciona en single-instance; en arquitecturas
    /// distribuidas reemplázala por una implementación con Redis u otro store:
    /// <code>
    /// services.AddKeyedSingleton&lt;IRateLimiter&gt;("forgot-password",
    ///     (sp, _) =&gt; new RedisRateLimiter(...));
    /// </code>
    /// </remarks>
    public RateLimiterOptions? ForgotPasswordRateLimiter { get; set; } =
        new() { MaxAttempts = 5, Window = TimeSpan.FromHours(1) };

    /// <summary>
    /// Configuración del rate limiting por IP para el paso "begin" de los endpoints anónimos
    /// WebAuthn (A-29). Por defecto: 30 solicitudes por minuto por IP.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (A-29): /webauthn/login/begin es anónimo y barato para el atacante (genera un
    /// challenge aleatorio y lo persiste), pero un flood puede saturar el almacén de challenges
    /// (Storage DoS). Sin embargo, es más barato que una verificación criptográfica, por eso el
    /// presupuesto "begin" es más holgado que el de "complete". Se registra como un limiter
    /// keyed ("webauthn-begin") independiente del de login para no compartir presupuesto.
    /// </remarks>
    public RateLimiterOptions? WebAuthnBeginRateLimiter { get; set; } =
        new() { MaxAttempts = 30, Window = TimeSpan.FromMinutes(1) };

    /// <summary>
    /// Configuración del rate limiting por IP para el paso "complete" de los endpoints anónimos
    /// WebAuthn (A-29). Por defecto: 10 solicitudes por minuto por IP.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (A-29): /webauthn/login/complete consume el challenge y ejecuta verificación
    /// criptográfica (firma ECDSA/RSA) → CPU DoS si no se limita. Además cada assertion fallida
    /// de una credencial conocida consume el presupuesto del scope Passkey (S1). Se registra como
    /// un limiter keyed ("webauthn-complete") con presupuesto estricto.
    /// </remarks>
    public RateLimiterOptions? WebAuthnCompleteRateLimiter { get; set; } =
        new() { MaxAttempts = 10, Window = TimeSpan.FromMinutes(1) };

    /// <summary>
    /// Configuración del rate limiting por IP para <c>/auth/recovery-codes/verify</c>
    /// (anónimo). Por defecto: 10 solicitudes por minuto por IP.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (B1, auditoría F5): verify es ANÓNIMO y cada intento ejecuta validación JWT del
    /// <c>mfaSessionToken</c> (RS256/ES256, costosa) + lecturas al caché. Sin límite por IP, un
    /// atacante amplifica CPU/caché con payloads mínimos, incluso sin tocar el presupuesto S1 por
    /// cuenta (que es opt-in). El limiter es keyed ("recovery-verify"), independiente del de login.
    /// </remarks>
    public RateLimiterOptions? RecoveryVerifyRateLimiter { get; set; } =
        new() { MaxAttempts = 10, Window = TimeSpan.FromMinutes(1) };

    /// <summary>
    /// Configuración del rate limiting por IP para <c>/auth/recovery-codes/use</c>
    /// (anónimo). Por defecto: 5 solicitudes por minuto por IP.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (B1, auditoría F5): use consume el código (single-use vía S2) y, si falla, el
    /// presupuesto S1 del scope Recovery. Es el endpoint más sensible del flujo: presupuesto por
    /// IP más estricto que verify (5/min) para acotar el brute-force distribuido y la carga al
    /// caché/BD. El limiter es keyed ("recovery-use"). En éxito se resetea para no penalizar al
    /// usuario legítimo (mismo patrón que /auth/login).
    /// </remarks>
    public RateLimiterOptions? RecoveryUseRateLimiter { get; set; } =
        new() { MaxAttempts = 5, Window = TimeSpan.FromMinutes(1) };

    /// <summary>
    /// Límite máximo (en bytes) del cuerpo de las solicitudes a los endpoints WebAuthn
    /// (/…/webauthn/*). Por defecto: 65536 bytes (64 KB).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (A-29): los payloads FIDO2 (clientDataJSON + attestationObject/authenticatorData
    /// en Base64URL) superan el límite de credenciales (<see cref="MaxAuthRequestBodySize"/>,
    /// 2048 B, pensado para /login y friends), pero NO deben quedar sin tope: una attestation
    /// legítima de packed/TPM ronda los 1-8 KB. 64 KB es holgado y acota el buffer en memoria
    /// frente a payloads arbitrarios. Lo aplica <c>UseSecureAuthRequestSizeLimit</c> en la rama
    /// de ruta /…/webauthn/* (defensa de capa física, A-10).
    /// </remarks>
    [Range(4096, 1048576, ErrorMessage = "El límite de tamaño del cuerpo WebAuthn debe estar entre 4096 y 1048576 bytes.")]
    public int MaxWebAuthnRequestBodySize { get; set; } = 65536;

    /// <summary>
    /// Límite máximo (en bytes) del cuerpo de las solicitudes a los endpoints de
    /// autenticación anónimos (login, refresh, forgot-password, reset-password).
    /// Por defecto: 2048 bytes (2 KB).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Los endpoints de autenticación son objetivos comunes de ataques DoS
    /// mediante payloads enormes. Casi ninguna solicitud legítima supera 1 KB
    /// (email + contraseña + metadata), por lo que 2 KB es un límite seguro.
    ///
    /// Este límite se aplica en DOS capas complementarias:
    ///
    /// 1. MIDDLEWARE (protección REAL): <c>UseSecureAuthRequestSizeLimit</c> asigna
    ///    <c>IHttpMaxRequestBodySizeFeature.MaxRequestBodySize</c> ANTES de que el binder
    ///    lea el cuerpo, por lo que Kestrel rechaza con 413 cualquier cuerpo mayor,
    ///    incluidos los chunked sin Content-Length. Un endpoint filter no puede hacer
    ///    esto porque en Minimal APIs se ejecuta DESPUÉS del binding.
    ///
    /// 2. ENDPOINT FILTER (defensa en profundidad): <c>EnforceAnonymousRequestSizeLimit</c>
    ///    descarta rápido por Content-Length con 413 JSON a nivel de aplicación y además es
    ///    verificable en TestServer.
    ///
    /// Recomendado: usar ambas. No reemplaza la configuración global de tu servidor
    /// (<c>Kestrel.MaxRequestBodySize</c>) para el resto de la aplicación.
    /// </remarks>
    [Range(256, 8192, ErrorMessage = "El límite de tamaño del cuerpo debe estar entre 256 y 8192 bytes.")]
    public int MaxAuthRequestBodySize { get; set; } = 2048;

    /// <summary>
    /// Provider opcional para calcular el TTL del Access Token por usuario.
    /// Si es null o devuelve null, se usa <see cref="AccessTokenLifetime"/> global.
    /// </summary>
    /// <remarks>
    /// Útil para defensa en profundidad con TTL por rol (superadmin 15m, admin 30m,
    /// support 1h). Requiere que el claim necesario (ej. "role") fluya al token
    /// vía <c>JwtOptions.AllowedSystemClaims</c>.
    ///
    /// Ejemplo:
    /// <code>
    /// options.AccessTokenLifetimeProvider = user =>
    ///     user.Claims?.GetValueOrDefault("role") switch
    ///     {
    ///         "superadmin" => TimeSpan.FromMinutes(15),
    ///         "admin"      => TimeSpan.FromMinutes(30),
    ///         _            => null // usa el TTL global
    ///     };
    /// </code>
    /// </remarks>
    public Func<UserIdentity, TimeSpan?>? AccessTokenLifetimeProvider { get; set; }

    /// <summary>
    /// TTL de la ventana "sesión MFA-verificada" (S3, A-21). Por defecto: 8 horas.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Durante esta ventana, <c>IMfaVerifiedSessionStore.IsVerifiedAsync(userId)</c>
    /// devuelve true. La marca blinda el step-up: un usuario que verificó un factor (login MFA
    /// o verify-action) puede completar mutaciones sensibles dentro de la ventana sin repetir
    /// el código. Los tokens JWT no dependen de esta ventana; es un estado de aplicación
    /// consultable por el host (middleware, endpoints propios, etc.).
    /// </remarks>
    public TimeSpan MfaVerifiedTtl { get; set; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Emite el claim "acr" (Authentication Context Class Reference) en los tokens (S3, A-14).
    /// Por defecto: false (opt-in, D-03).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: <c>acr</c> expresa el nivel de confianza de la autenticación (NIST SP 800-63B
    /// AAL: "1" = single-factor, "2" = MFA). Está desactivado por defecto para no imponer una
    /// semántica; al activarlo se emite el valor de <see cref="AcrLevel"/> en todos los tokens,
    /// o el que el implementador inyecte vía <c>UserIdentity.Claims["acr"]</c> (gana el claim
    /// explícito). Se respeta así el comentario de JwtTokenService que deja acr a discreción
    /// del implementador, con un camino cómodo para habilitarlo.
    /// </remarks>
    public bool EmitAcr { get; set; } = false;

    /// <summary>
    /// Valor del claim "acr" emitido cuando <see cref="EmitAcr"/> está activo. Por defecto: "1".
    /// </summary>
    public string AcrLevel { get; set; } = "1";

    /// <summary>
    /// Emite el claim "amr" (Authentication Methods References, RFC 8176) de forma consistente en
    /// todos los métodos de login (F6, A-25). Por defecto: false (opt-in, D-03).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (RFC 8176): <c>amr</c> describe CÓMO se autenticó el sujeto. Hoy la librería ya lo
    /// emite en los flujos MFA (<c>amr=mfa</c> + <c>mfa_method</c>) y WebAuthn (<c>amr=webauthn</c>),
    /// pero el login por contraseña NO. Al activar esta opción:
    /// <list type="bullet">
    /// <item><description>Login por contraseña → <c>amr=pwd</c>.</description></item>
    /// <item><description>Login WebAuthn → además <c>mfa_method=webauthn</c>.</description></item>
    /// <item><description>MFA → ya emite <c>amr=mfa</c> + <c>mfa_method</c>.</description></item>
    /// </list>
    /// Con <c>false</c> el comportamiento actual se conserva intacto (opt-in, no-breaking): añadir
    /// un claim nuevo al JWT podría romper consumidores con validación estricta de claims, por eso
    /// no es el default. <c>amr</c> sigue protegido en el blocklist de system claims
    /// (solo los orquestadores lo inyectan).
    /// </remarks>
    public bool EmitAmr { get; set; } = false;
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
