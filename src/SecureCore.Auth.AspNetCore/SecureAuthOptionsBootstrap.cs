using Microsoft.Extensions.Configuration;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Orquesta la materialización de las opciones de SecureCore Auth (F8, solución estructural al
/// merge appsettings ↔ Fluent).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F8): el patrón estándar de ASP.NET es <c>BindConfiguration(...).Configure(hostAction)</c>
/// donde la acción del host muta la instancia YA vinculada de appsettings. Aquí el host configura un
/// <see cref="SecureAuthConfiguration"/> (que contiene <c>Auth</c>, <c>Jwt</c>, <c>Argon2</c>); para
/// que sus valores convivan con appsettings, este bootstrap:
/// 1. Vincula las secciones <c>SecureAuth:</c>, <c>SecureAuth:Jwt:</c> y <c>SecureAuth:Argon2:</c>
///    desde <c>IConfiguration</c> sobre las instancias del <see cref="SecureAuthConfiguration"/>.
/// 2. Ejecuta el <c>configure</c> del host UNA VEZ sobre esas instancias (Fluent = overlay).
/// 3. Cachea el resultado (thread-safe).
///
/// Resultado: appsettings es la BASE y Fluent el overlay. Los valores solo-appsettings sobreviven,
/// los solo-Fluent se aplican, y los de ambos ganan Fluent. Antes, la copia Fluent usaba un
/// <c>SecureAuthOptions</c> pre-cargado con defaults del framework que sobrescribía appsettings.
///
/// El <c>configure</c> queda diferido a la primera materialización de cualquiera de las opciones;
/// es transparente porque el host no accede al <c>SecureAuthConfiguration</c> después de
/// <c>AddSecureAuth</c>. Requiere <c>IConfiguration</c> (los hosts ASP.NET lo tienen; ya era
/// requisito efectivo de <c>BindConfiguration</c> para Jwt/Mfa).
/// </remarks>
public sealed class SecureAuthOptionsBootstrap(Action<SecureAuthConfiguration> configure)
{
    private readonly object _gate = new();
    private SecureAuthConfiguration? _config;

    /// <summary>
    /// Devuelve la configuración vinculada + aplicada (appsettings + Fluent), creándola la primera vez.
    /// </summary>
    public SecureAuthConfiguration GetOrCreate(IConfiguration configuration)
    {
        if (_config is not null)
        {
            return _config;
        }

        lock (_gate)
        {
            if (_config is not null)
            {
                return _config;
            }

            var config = new SecureAuthConfiguration();
            configuration.Bind(SecureAuthOptions.SectionName, config.Auth);
            configuration.Bind(JwtOptions.SectionName, config.Jwt);
            configuration.Bind(Argon2Options.SectionName, config.Argon2);
            configure(config);
            _config = config;
        }

        return _config;
    }
}
