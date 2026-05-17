using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
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
        Services.AddSingleton<IMfaSessionStore, JwtMfaSessionService>();
        Services.AddSingleton<IMfaEncryptionService, AesMfaEncryptionService>();
        Services.AddScoped<IEmailMfaService, EmailMfaService>();
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
        Services.AddSingleton<IMfaSessionStore, JwtMfaSessionService>();
        Services.AddSingleton<IMfaEncryptionService, AesMfaEncryptionService>();
        Services.AddScoped<IEmailMfaService, EmailMfaService>();
        Services.AddScoped<IMfaService, MfaOrchestrator>();

        return this;
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

        // Registrar el despachador de eventos (con handlers extensibles)
        services.AddScoped<IAuthEventDispatcher, AuthEventDispatcher>();

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

        if (algorithm.StartsWith("RS"))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(jwtOptions.PublicKey);
            return new RsaSecurityKey(rsa);
        }

        // ES256, ES384, ES512
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(jwtOptions.PublicKey);
        return new ECDsaSecurityKey(ecdsa);
    }
}
