using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.Apple.Extensions;

/// <summary>
/// Extensiones para registrar el proveedor de Apple en el ecosistema OAuth de SecureCore.
/// </summary>
public static class AppleOAuthExtensions
{
    /// <summary>
    /// Añade el soporte para 'Sign in with Apple'.
    /// </summary>
    /// <param name="builder">El constructor de OAuth.</param>
    /// <param name="configure">Acción para configurar las credenciales de Apple.</param>
    /// <returns>El mismo constructor para encadenar llamadas.</returns>
    /// <exception cref="ArgumentException">Se lanza si falta alguna configuración requerida.</exception>
    public static OAuthBuilder AddApple(this OAuthBuilder builder, Action<AppleOAuthOptions> configure)
    {
        var options = new AppleOAuthOptions 
        { 
            ClientId = "", 
            TeamId = "", 
            KeyId = "", 
            PrivateKey = "" 
        };
        configure(options);

        // DIDÁCTICA: Apple es el proveedor más estricto. Requiere 4 piezas de información
        // a diferencia de otros que solo requieren ClientId y ClientSecret.
        if (string.IsNullOrEmpty(options.ClientId) || 
            string.IsNullOrEmpty(options.TeamId) || 
            string.IsNullOrEmpty(options.KeyId) || 
            string.IsNullOrEmpty(options.PrivateKey))
        {
            throw new ArgumentException("ClientId, TeamId, KeyId and PrivateKey are required for Apple OAuth.");
        }

        builder.Services.AddSingleton(options);
        
        // Registramos el validador como una instancia de HttpClient para manejo eficiente de sockets
        builder.Services.AddHttpClient<IOAuthProviderValidator, AppleOAuthValidator>();
        
        return builder;
    }
}
