using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.AspNetCore.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Configuración combinada para la Fluent API de SecureCore Auth.
/// </summary>
public class SecureAuthConfiguration
{
    /// <summary>
    /// Opciones generales de autenticación.
    /// </summary>
    public SecureAuthOptions Auth { get; set; } = new();

    /// <summary>
    /// Opciones de JWT.
    /// </summary>
    public JwtOptions Jwt { get; set; } = new();

    /// <summary>
    /// Opciones de Argon2id para hashing de contraseñas.
    /// </summary>
    public Argon2Options Argon2 { get; set; } = new();

    /// <summary>
    /// Opciones de MFA (Autenticación Multifactor).
    /// </summary>
    public MfaOptions Mfa { get; set; } = new();
}

/// <summary>
/// Builder que permite configurar SecureCore Auth de forma fluida (Fluent API).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El "Builder Pattern" combinado con una "Fluent API" permite una
/// configuración legible y encadenable. Cada método retorna el builder mismo,
/// permitiendo llamadas como: services.AddSecureAuth(...).AddPasswordAuthentication().AddWebAuthn(...)
/// </remarks>
public class SecureAuthBuilder(IServiceCollection services)
{
    /// <summary>
    /// La colección de servicios donde se registran las dependencias.
    /// </summary>
    public IServiceCollection Services { get; } = services;

    /// <summary>
    /// Habilita la autenticación por contraseña (Argon2id).
    /// </summary>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddPasswordAuthentication()
    {
        Services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();

        Services.AddSingleton<ITotpService, TotpService>();
        Services.AddMemoryCache();
        Services.AddSingleton<IMfaSessionStore, JwtMfaSessionService>();
        Services.AddSingleton<IMfaEncryptionService, AesMfaEncryptionService>();
        Services.AddScoped<IEmailMfaService, EmailMfaService>();

        // DIDÁCTICA: IEmailService (transporte de email) es responsabilidad del
        // implementador. Se registra un default NullEmailService que lanza al usarse;
        // si el consumidor registra el suyo ANTES, TryAdd lo respeta.
        AddEmailServiceDefault(Services);

        // DIDÁCTICA: IMfaCodeStore con IDistributedCache es la implementación
        // por defecto para almacenar códigos MFA temporales. Si necesitas un
        // backend diferente (ej. base de datos), implementa IMfaCodeStore y
        // regístralo ANTES de llamar a AddPasswordAuthentication().
        Services.TryAddScoped<IMfaCodeStore, DistributedCacheMfaCodeStore>();

        // DIDÁCTICA (S3): ventana "mfa_verified" (post-verificación, TTL MfaVerifiedTtl).
        // Registrado aquí para que IdentityOrchestrator.CompleteMfaLoginAsync pueda marcarla
        // al completar el login MFA. Si el consumidor implementa su propio store, lo registra
        // ANTES (TryAdd lo respeta).
        Services.TryAddScoped<IMfaVerifiedSessionStore, DistributedCacheMfaVerifiedSessionStore>();

        Services.AddScoped<IMfaService, MfaOrchestrator>();

        Services.AddScoped<IdentityOrchestrator>();
        return this;
    }

    /// <summary>
    /// Habilita la autenticación con WebAuthn/Passkeys.
    /// </summary>
    /// <param name="configure">Acción para configurar WebAuthn.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddWebAuthn(Action<WebAuthnOptions>? configure = null)
    {
        if (configure is not null)
        {
            Services.Configure(configure);
        }

        Services.AddScoped<SecureCore.Auth.WebAuthn.PasskeyService>();
        return this;
    }

    /// <summary>
    /// Habilita la funcionalidad de recuperación y restablecimiento de contraseña.
    /// Registra las configuraciones y el orquestador principal.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método registra el sistema de reset de forma opcional (Opt-in).
    /// Si el desarrollador no llama a este método, los servicios de reset no se inyectan
    /// y los endpoints correspondientes responderán 503, manteniendo la superficie de
    /// ataque al mínimo si la funcionalidad no es requerida.
    /// </remarks>
    /// <param name="configure">Acción opcional para sobrescribir las opciones por defecto.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddPasswordReset(Action<PasswordResetOptions>? configure = null)
    {
        Services.AddOptions<PasswordResetOptions>()
            .BindConfiguration(PasswordResetOptions.SectionName)
            .PostConfigure(opt =>
            {
                if (configure is not null)
                {
                    var overrides = new PasswordResetOptions();
                    configure(overrides);
                    opt.TokenLifetimeMinutes = overrides.TokenLifetimeMinutes;
                    opt.TokenSizeBytes = overrides.TokenSizeBytes;
                    opt.MaxRequestsPerHour = overrides.MaxRequestsPerHour;
                }
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        Services.AddScoped<PasswordResetOrchestrator>();
        return this;
    }

    /// <summary>
    /// Habilita la autenticación multifactor (MFA).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método registra los servicios de MFA (TOTP, Email, etc.).
    /// MFA está disabled por defecto para mantener backward compatibility.
    /// El implementador debe habilitarlo explícitamente en las opciones.
    ///
    /// Servicios registrados:
    /// - ITotpService (TotpService)
    /// - IMfaSessionStore (JwtMfaSessionService)
    /// - IMfaEncryptionService (AesMfaEncryptionService)
    /// - IEmailMfaService (EmailMfaService)
    /// - IMfaService (MfaOrchestrator)
    /// </remarks>
    /// <param name="configure">Acción opcional para configurar opciones MFA.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddMfa(Action<MfaOptions>? configure = null)
    {
        Services.AddOptions<MfaOptions>()
            .BindConfiguration(MfaOptions.SectionName)
            .PostConfigure(opt =>
            {
                if (configure is not null)
                {
                    var overrides = new MfaOptions();
                    configure(overrides);
                    opt.Enabled = overrides.Enabled;
                    opt.RequiredByDefault = overrides.RequiredByDefault;
                    opt.AllowedMethods = overrides.AllowedMethods;
                    opt.AllowUserEnrollment = overrides.AllowUserEnrollment;
                    opt.AllowUserDisable = overrides.AllowUserDisable;
                    opt.EnableRecoveryCodes = overrides.EnableRecoveryCodes;
                    opt.TotpIssuer = overrides.TotpIssuer;
                    opt.EncryptionKey = overrides.EncryptionKey;
                }
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        Services.AddSingleton<ITotpService, TotpService>();
        Services.AddMemoryCache();
        Services.AddSingleton<IMfaSessionStore, JwtMfaSessionService>();
        Services.AddSingleton<IMfaEncryptionService, AesMfaEncryptionService>();
        Services.AddScoped<IEmailMfaService, EmailMfaService>();
        AddEmailServiceDefault(Services);
        Services.TryAddScoped<IMfaCodeStore, DistributedCacheMfaCodeStore>();
        Services.TryAddScoped<IMfaVerifiedSessionStore, DistributedCacheMfaVerifiedSessionStore>();
        Services.AddScoped<IMfaService, MfaOrchestrator>();

        return this;
    }

    /// <summary>
    /// Habilita el subsistema de anti-abuso por cuenta (S1): lockout multi-scope,
    /// temporal y escalonado.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Consolida el lockout por cuenta (contraseña, MFA, passkey, recovery,
    /// verify-action) en un único subsistema distribuible por SPI. Opt-in (D-03): hasta
    /// que <c>AccountProtectionOptions.Enabled = true</c>, los orquestadores conservan su
    /// comportamiento actual (LockoutManager en DB / ventana MFA fija).
    ///
    /// Default in-memory (InMemoryAccountProtectionService): válido en single-instance.
    /// En multi-instancia, registre su propia implementación de IAccountProtectionService
    /// ANTES de esta llamada (TryAdd) con un store compartido (Redis INCR+EXPIRE, SQL…):
    ///   services.AddScoped&lt;IAccountProtectionService, MyRedisAccountProtectionService&gt;();
    /// También puede sobrescribir el default aquí registrando después de esta llamada.
    ///
    /// PRECEDENCIA (configuración): el configure por código aplicado aquí sobrescribe, en
    /// bloque, las propiedades de la sección <c>SecureAuth:AccountProtection</c> de
    /// appsettings (values del objeto <c>AccountProtectionOptions</c>, no solo las tocadas).
    /// Si combina ambas, fije en configure TODAS las propiedades que quiera activas, o use
    /// solo appsettings. La validación (Window &gt; 0, MaxLockDuration &gt; 0, duraciones &gt; 0)
    /// ocurre al arrancar y NO es anulable.
    /// </remarks>
    /// <param name="configure">Acción opcional para sobrescribir las opciones por defecto.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddSecureAuthAccountProtection(Action<AccountProtectionOptions>? configure = null)
    {
        Services.AddOptions<AccountProtectionOptions>()
            .BindConfiguration(AccountProtectionOptions.SectionName)
            .PostConfigure(opt =>
            {
                if (configure is not null)
                {
                    var overrides = new AccountProtectionOptions();
                    configure(overrides);
                    opt.Enabled = overrides.Enabled;
                    opt.Window = overrides.Window;
                    opt.MaxAttempts = overrides.MaxAttempts;
                    opt.EscalationDurations = overrides.EscalationDurations;
                    opt.MaxLockDuration = overrides.MaxLockDuration;
                }
            })
            .Validate(options =>
            {
                if (options.Enabled && options.Window <= TimeSpan.Zero)
                {
                    throw new OptionsValidationException(
                        nameof(AccountProtectionOptions),
                        typeof(AccountProtectionOptions),
                        ["AccountProtectionOptions.Window debe ser mayor que TimeSpan.Zero (una ventana de 0 revive el fail-open del lockout)."]);
                }

                if (options.Enabled && options.MaxLockDuration <= TimeSpan.Zero)
                {
                    throw new OptionsValidationException(
                        nameof(AccountProtectionOptions),
                        typeof(AccountProtectionOptions),
                        ["AccountProtectionOptions.MaxLockDuration debe ser mayor que TimeSpan.Zero (una duración de 0 hace inofensivos los lockouts)."]);
                }

                if (options.Enabled && options.EscalationDurations.Count == 0)
                {
                    throw new OptionsValidationException(
                        nameof(AccountProtectionOptions),
                        typeof(AccountProtectionOptions),
                        ["AccountProtectionOptions.EscalationDurations no puede estar vacío."]);
                }

                if (options.Enabled && options.EscalationDurations.Any(d => d <= TimeSpan.Zero))
                {
                    throw new OptionsValidationException(
                        nameof(AccountProtectionOptions),
                        typeof(AccountProtectionOptions),
                        ["AccountProtectionOptions.EscalationDurations no puede contener duraciones menores o iguales a TimeSpan.Zero."]);
                }

                if (options.Enabled && options.MaxAttempts.Any(kvp => kvp.Value < 1))
                {
                    throw new OptionsValidationException(
                        nameof(AccountProtectionOptions),
                        typeof(AccountProtectionOptions),
                        ["AccountProtectionOptions.MaxAttempts no puede contener valores menores que 1."]);
                }

                return true;
            })
            .ValidateOnStart();

        Services.TryAddScoped<IAccountProtectionService, InMemoryAccountProtectionService>();
        return this;
    }

    /// <summary>
    /// Habilita el step-up genérico (S3, verify-action): OTP por email para mutaciones sensibles.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: registra el orquestador <c>VerifyActionOrchestrator</c>, el store de OTP
    /// (single-use atómico vía S2), la ventana mfa_verified compartida y el adaptador de envío
    /// por defecto sobre IEmailService. Opt-in: sin este registro, los endpoints
    /// /verify-action/* responden 503.
    ///
    /// ENVÍO: el adaptador por defecto delega en IEmailService; si no registró una
    /// implementación real, el envío falla con mensaje genérico (nunca 500 con detalles).
    /// Sobrescritura: registre <c>IEmailOtpSender</c> (o <c>IEmailService</c>) ANTES de esta
    /// llamada (TryAdd los respeta). También puede registrar su <c>IEmailOtpStore</c> propio
    /// con un backend real si no quiere el default sobre IDistributedCache.
    /// </remarks>
    /// <param name="configure">Acción opcional para sobrescribir las opciones por defecto.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddVerifyAction(Action<VerifyActionOptions>? configure = null)
    {
        Services.AddOptions<VerifyActionOptions>()
            .BindConfiguration(VerifyActionOptions.SectionName)
            .PostConfigure(opt =>
            {
                if (configure is not null)
                {
                    var overrides = new VerifyActionOptions();
                    configure(overrides);
                    opt.TtlMinutes = overrides.TtlMinutes;
                    opt.CodeLength = overrides.CodeLength;
                }
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // DIDÁCTICA (S3): el store de OTP consume su entrada con la primitiva single-use
        // atómica (S2). Garantizamos el default aquí por si AddSecureAuth no lo registró.
        Services.TryAddScoped<ISingleUseTokenStore, DistributedCacheSingleUseTokenStore>();
        Services.TryAddScoped<IEmailOtpStore, DistributedCacheEmailOtpStore>();
        Services.TryAddScoped<IEmailOtpSender, EmailServiceEmailOtpSender>();
        Services.TryAddScoped<IMfaVerifiedSessionStore, DistributedCacheMfaVerifiedSessionStore>();
        Services.AddScoped<VerifyActionOrchestrator>();

        return this;
    }

    /// <summary>
    /// Habilita el flujo de creación/cambio de contraseña (S3, A-22).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: registra <c>ChangePasswordOrchestrator</c>. Opt-in: sin este registro los
    /// endpoints /create-password y /change-password responden 503 (patrón de forgot/reset).
    ///
    /// El orquestador exige ITokenService, ISessionStore y SecurityStampValidator: asegúrese de
    /// haber llamado a AddVerifyAction (o registrado sus propios stores) ANTES de cambiar
    /// contraseñas. Para el flujo de CREACIÓN necesita además la ventana mfa_verified
    /// (IMfaVerifiedSessionStore) que abre el paso previo verify-action (M1, auditoría): el OTP
    /// se consume en VerifyActionAsync; crear la contraseña solo comprueba que la ventana siga
    /// abierta (fail-closed si AddVerifyAction no se registró y la ventana nunca se abre).
    /// </remarks>
    /// <returns>El builder para encadenamiento.</returns>
    public SecureAuthBuilder AddChangePassword()
    {
        // DIDÁCTICA (M1): el flujo de creación depende de la ventana mfa_verified. Garantizamos
        // el default por si AddSecureAuth/AddVerifyAction no lo registró (TryAdd respeta el host).
        Services.TryAddScoped<IMfaVerifiedSessionStore, DistributedCacheMfaVerifiedSessionStore>();
        Services.AddScoped<ChangePasswordOrchestrator>();
        return this;
    }

    /// <summary>
    /// Registra una implementación por defecto de IEmailService si el consumidor
    /// no proporcionó la suya. NullEmailService lanza al intentar enviar.
    /// </summary>
    private static void AddEmailServiceDefault(IServiceCollection services)
    {
        services.TryAddScoped<IEmailService, NullEmailService>();
    }
}

/// <summary>
/// Implementación por defecto de IEmailService usada cuando el consumidor
/// no registra una implementación real.
/// </summary>
/// <remarks>
/// DIDÁCTICA: A diferencia de NullExternalTokenStore (donde el no-op es un modo
/// legítimo "identity-only"), un envío de email silencioso sería catastrófico para
/// MFA: el factor parecería activo y los códigos nunca llegarían. Por eso este
/// default LANZA InvalidOperationException al intentar enviar, forzando al
/// implementador a registrar su propio IEmailService ANTES de AddMfa().
/// </remarks>
internal sealed class NullEmailService(ILogger<NullEmailService> logger) : IEmailService
{
    private readonly ILogger<NullEmailService> _logger = logger;

    public Task SendAsync(
        string to,
        string subject,
        string? htmlBody = null,
        string? textBody = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogWarning(
            "NullEmailService: intento de envío a {To} sin IEmailService registrado. " +
            "El MFA por email no puede funcionar sin un servicio de envío real. " +
            "Registra tu implementación de IEmailService ANTES de AddMfa()/AddPasswordAuthentication().",
            to);

        throw new InvalidOperationException(
            "No se ha registrado una implementación de IEmailService. " +
            "El envío de emails (requerido por EmailMfaService) necesita un servicio real. " +
            "Registra tu implementación antes de AddMfa()/AddPasswordAuthentication(): " +
            "services.AddScoped<IEmailService, MyEmailService>();");
    }
}

/// <summary>
/// Métodos de extensión para registrar SecureCore Auth en ASP.NET Core.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los métodos de extensión sobre IServiceCollection son el patrón estándar
/// en ASP.NET Core para registrar servicios de una librería. Permiten que el usuario
/// configure todo en una sola línea legible en su Program.cs.
///
/// Ejemplo de uso:
/// <code>
/// builder.Services.AddSecureAuth(options =&gt;
/// {
///     options.Jwt.Issuer = "miapp.com";
///     options.Jwt.SigningKey = builder.Configuration["Jwt:Key"]!;
/// })
/// .AddPasswordAuthentication()
/// .AddWebAuthn();
/// </code>
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra los servicios base de SecureCore Auth Framework.
    /// </summary>
    /// <param name="services">La colección de servicios de DI.</param>
    /// <param name="configure">Acción para configurar las opciones de autenticación.</param>
    /// <returns>Un builder para agregar funcionalidades opcionales (contraseña, passkeys).</returns>
    public static SecureAuthBuilder AddSecureAuth(
        this IServiceCollection services,
        Action<SecureAuthConfiguration> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        // Aplicar la configuración del usuario
        var config = new SecureAuthConfiguration();
        configure(config);

        // Registrar las opciones en el sistema de IOptions<T>
        services.Configure<SecureAuthOptions>(opt =>
        {
            opt.AccessTokenLifetime = config.Auth.AccessTokenLifetime;
            opt.RefreshTokenLifetime = config.Auth.RefreshTokenLifetime;
            opt.GracePeriodSeconds = config.Auth.GracePeriodSeconds;
            opt.MaxFailedAttempts = config.Auth.MaxFailedAttempts;
            opt.LockoutDurations = config.Auth.LockoutDurations;
            opt.ClockSkew = config.Auth.ClockSkew;
            opt.SecurityStampCacheDuration = config.Auth.SecurityStampCacheDuration;
            opt.ForgotPasswordRateLimiter = config.Auth.ForgotPasswordRateLimiter;
        });

        // Registrar y validar opciones de JWT
        services.AddOptions<JwtOptions>()
            .BindConfiguration(JwtOptions.SectionName) // Permitir bind desde appsettings
            .PostConfigure(opt =>
            {
                // Sobrescribir con lo configurado en la Fluent API si se proporcionó
                if (!string.IsNullOrEmpty(config.Jwt.Issuer)) opt.Issuer = config.Jwt.Issuer;
                if (!string.IsNullOrEmpty(config.Jwt.Audience)) opt.Audience = config.Jwt.Audience;
                if (!string.IsNullOrEmpty(config.Jwt.SigningKey)) opt.SigningKey = config.Jwt.SigningKey;
                if (!string.IsNullOrEmpty(config.Jwt.Algorithm)) opt.Algorithm = config.Jwt.Algorithm;
                if (!string.IsNullOrEmpty(config.Jwt.PrivateKey)) opt.PrivateKey = config.Jwt.PrivateKey;
                if (!string.IsNullOrEmpty(config.Jwt.PublicKey)) opt.PublicKey = config.Jwt.PublicKey;
                if (config.Jwt.AllowedSystemClaims.Count > 0)
                    opt.AllowedSystemClaims = new HashSet<string>(config.Jwt.AllowedSystemClaims);
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // DIDÁCTICA: Registrar validadores personalizados para detección temprana de errores
        // Esto asegura que cualquier problema de configuración se detecte en startup, no en runtime
        services.AddSingleton<IValidateOptions<JwtOptions>>(new JwtOptionsValidator());
        // El segundo validador solo da warnings en producción, no falla
        services.AddSingleton<IValidateOptions<JwtOptions>>(new JwtProductionSecurityValidator("Development"));

        // Registrar y validar opciones de Argon2
        services.AddOptions<Argon2Options>()
            .PostConfigure(opt =>
            {
                opt.MemorySize = config.Argon2.MemorySize;
                opt.Iterations = config.Argon2.Iterations;
                opt.Parallelism = config.Argon2.Parallelism;
                opt.SaltSize = config.Argon2.SaltSize;
                opt.HashSize = config.Argon2.HashSize;
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Registrar y validar opciones generales
        services.AddOptions<SecureAuthOptions>()
            .PostConfigure(opt =>
            {
                opt.AccessTokenLifetime = config.Auth.AccessTokenLifetime;
                opt.RefreshTokenLifetime = config.Auth.RefreshTokenLifetime;
                opt.GracePeriodSeconds = config.Auth.GracePeriodSeconds;
                opt.MaxFailedAttempts = config.Auth.MaxFailedAttempts;
                opt.LockoutDurations = config.Auth.LockoutDurations;
                opt.ClockSkew = config.Auth.ClockSkew;
                opt.SecurityStampCacheDuration = config.Auth.SecurityStampCacheDuration;
                opt.ForgotPasswordRateLimiter = config.Auth.ForgotPasswordRateLimiter;
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

        // Registrar servicios Core
        services.AddSingleton<ITokenService, JwtTokenService>();

        // DIDÁCTICA: Registro del sistema de rate limiting.
        // Por defecto usamos InMemoryRateLimiter que funciona en single-instance.
        // Para arquitecturas distribuidas (múltiples servidores), el implementador
        // debe sobrescribir este registro con una implementación distribuida (Redis, etc.)
        // La implementación por defecto es ideal para desarrollo y single-server production.
        services.AddSingleton<IRateLimiter>(sp =>
        {
            var authOptions = sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value;
            var rateLimiterOptions = authOptions.RateLimiter;
            return new InMemoryRateLimiter(
                rateLimiterOptions?.MaxAttempts ?? 10,
                rateLimiterOptions?.Window ?? TimeSpan.FromMinutes(1));
        });

        // DIDÁCTICA (Nº5): Rate limiter DEDICADO para /forgot-password. Usa keyed DI para
        // tener un presupuesto independiente del de login sin romper la sobreescritura de
        // IRateLimiter global. En multi-instancia, el implementador puede reemplazarlo con
        // una implementación distribuida:
        //   services.AddKeyedSingleton<IRateLimiter>("forgot-password", (sp, _) => new RedisRateLimiter(...));
        services.AddKeyedSingleton<IRateLimiter>("forgot-password", (sp, _) =>
        {
            var authOptions = sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value;
            var forgotOptions = authOptions.ForgotPasswordRateLimiter;
            return new InMemoryRateLimiter(
                forgotOptions?.MaxAttempts ?? 5,
                forgotOptions?.Window ?? TimeSpan.FromHours(1));
        });

        // DIDÁCTICA: Registro del mecanismo de locks para operaciones críticas.
        // Por defecto usamos InMemoryOperationLock que funciona en single-instance.
        // Para arquitecturas distribuidas (múltiples servidores), el implementador
        // debe sobrescribir este registro con una implementación distribuida (Redis, etc.)
        // Si el usuario no provee una implementación, usamos el fallback in-memory.
        services.AddSingleton<IOperationLock>(sp =>
        {
            var authOptions = sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value;
            var timeout = TimeSpan.FromSeconds(authOptions.OperationLock?.TimeoutSeconds ?? 5);
            return new InMemoryOperationLock(timeout);
        });

        services.AddScoped<SessionOrchestrator>();
        services.AddScoped<SecurityStampValidator>();
        services.AddScoped<LockoutManager>();

        // DIDÁCTICA (S2, A-06): Primitiva transversal "consumir exactamente una vez".
        // Base para OAuth state (A-06), challenge WebAuthn (Fase 4) y recovery codes (Fase 5).
        // Default con IDistributedCache (GET + REMOVE, no atómico). En multi-instancia,
        // el implementador puede sobrescribirla con una implementación GETDEL/Lua distribuida:
        //   services.AddScoped<ISingleUseTokenStore, MyRedisSingleUseTokenStore>();
        services.TryAddScoped<ISingleUseTokenStore, DistributedCacheSingleUseTokenStore>();

        // Registrar el despachador de eventos con enriquecimiento de contexto HTTP
        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddScoped<AuthEventDispatcher>();
        services.AddScoped<IAuthEventDispatcher>(sp =>
            new AuthEventContextEnricher(
                sp.GetRequiredService<IHttpContextAccessor>(),
                sp.GetRequiredService<AuthEventDispatcher>()));

        // Configurar autenticación JWT Bearer
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = config.Jwt.Issuer,
                    ValidAudience = config.Jwt.Audience,
                    IssuerSigningKey = CreateIssuerSigningKey(config.Jwt),
                    ClockSkew = config.Auth.ClockSkew
                };
            });

        services.AddAuthorization();

        return new SecureAuthBuilder(services);
    }

    /// <summary>
    /// Agrega el middleware de validación de Security Stamp al pipeline de ASP.NET Core.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este middleware DEBE agregarse DESPUÉS de UseAuthentication()
    /// y ANTES de UseAuthorization() en el pipeline. El orden es crucial:
    ///
    /// app.UseAuthentication();       // 1. Decodifica el JWT
    /// app.UseSecureAuthValidation(); // 2. Valida el Security Stamp
    /// app.UseAuthorization();        // 3. Verifica permisos
    /// </remarks>
    /// <param name="app">El builder de la aplicación web.</param>
    /// <returns>El builder para encadenamiento.</returns>
    public static IApplicationBuilder UseSecureAuthValidation(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SecurityStampMiddleware>();
    }

    /// <summary>
    /// Aplica el límite de tamaño de cuerpo (<c>SecureAuthOptions.MaxAuthRequestBodySize</c>)
    /// a las solicitudes bajo el prefijo de los endpoints de autenticación.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este middleware asigna <c>IHttpMaxRequestBodySizeFeature.MaxRequestBodySize</c>
    /// ANTES del binding del cuerpo, por lo que Kestrel rechaza con 413 los payloads que
    /// superen el límite (incluidos cuerpos chunked sin Content-Length). Es complementario
    /// al endpoint filter del grupo: el filter descarta rápido por Content-Length y es
    /// verificable en TestServer, mientras que este middleware es la barrera física real.
    ///
    /// Debe llamarse con el mismo prefijo usado en <c>MapSecureAuthEndpoints</c>:
    /// <code>
    /// app.MapSecureAuthEndpoints("/auth");
    /// app.UseSecureAuthRequestSizeLimit("/auth");
    /// </code>
    /// </remarks>
    /// <param name="app">El builder de la aplicación web.</param>
    /// <param name="pathPrefix">Prefijo de ruta de los endpoints de autenticación (por defecto "/auth").</param>
    /// <returns>El builder para encadenamiento.</returns>
    public static IApplicationBuilder UseSecureAuthRequestSizeLimit(
        this IApplicationBuilder app,
        string pathPrefix = "/auth")
    {
        ArgumentNullException.ThrowIfNull(app);

        if (string.IsNullOrWhiteSpace(pathPrefix))
        {
            throw new ArgumentException(
                "El prefijo de ruta no puede estar vacío.", nameof(pathPrefix));
        }

        return app.UseMiddleware<RequestSizeLimitMiddleware>(new PathString(pathPrefix));
    }

    /// <summary>
    /// Crea la clave de validación de firma según el algoritmo configurado.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Para RS256/ES256, usamos la CLAVE PÚBLICA para validar.
    /// La clave pública puede distribuirse libremente (no es sensible).
    /// Para HS256, usamos la misma SigningKey (simétrica).
    /// </remarks>
    private static SecurityKey CreateIssuerSigningKey(JwtOptions jwtOptions)
    {
        var algorithm = jwtOptions.Algorithm.ToUpperInvariant();

        return algorithm switch
        {
            "RS256" or "ES256" or "ES384" or "ES512" => CreateAsymmetricSecurityKey(jwtOptions),
            _ => new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                jwtOptions.SigningKey ?? throw new InvalidOperationException(
                    "JWT Algorithm es HS256 pero no se ha configurado SigningKey.")))
        };
    }

    private static SecurityKey CreateAsymmetricSecurityKey(JwtOptions jwtOptions)
    {
        if (string.IsNullOrEmpty(jwtOptions.PublicKey))
        {
            throw new InvalidOperationException(
                $"JWT Algorithm es {jwtOptions.Algorithm} pero no se ha configurado Jwt:PublicKey. " +
                "La clave pública RSA/ECDSA en formato PEM es requerida para validación.");
        }

        var algorithm = jwtOptions.Algorithm.ToUpperInvariant();

        // IMPORTANTE: No usar 'using' aquí porque la instancia de RSA debe
        // permanecer viva mientras exista la RsaSecurityKey que la referencia.
        // Si se dispone, las operaciones de validación JWT posteriores
        // lanzarán ObjectDisposedException.
        if (algorithm.StartsWith("RS"))
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(jwtOptions.PublicKey);
            return new RsaSecurityKey(rsa);
        }

        // ES256, ES384, ES512
        // IMPORTANTE: No usar 'using' aquí — misma razón que RSA.
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(jwtOptions.PublicKey);
        return new ECDsaSecurityKey(ecdsa);
    }
}
