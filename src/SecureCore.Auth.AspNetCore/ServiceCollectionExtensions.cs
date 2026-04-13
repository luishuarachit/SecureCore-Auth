using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
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
            })
            .ValidateDataAnnotations()
            .ValidateOnStart();

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
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(config.Jwt.SigningKey)),
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
}
