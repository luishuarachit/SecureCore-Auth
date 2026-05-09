using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.Google.Extensions;

public static class GoogleOAuthExtensions
{
    public static OAuthBuilder AddGoogle(this OAuthBuilder builder, Action<GoogleOAuthOptions> configure)
    {
        var options = new GoogleOAuthOptions { ClientId = "", ClientSecret = "" };
        configure(options);

        // Validar opciones en runtime temprano
        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientId and ClientSecret are required for Google OAuth.");
        }

        builder.Services.AddSingleton(options);
        
        builder.Services.AddHttpClient<IOAuthProviderValidator, GoogleOAuthValidator>();
        
        return builder;
    }
}
