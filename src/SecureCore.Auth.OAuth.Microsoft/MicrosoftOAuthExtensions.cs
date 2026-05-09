using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.Microsoft.Extensions;

public static class MicrosoftOAuthExtensions
{
    public static OAuthBuilder AddMicrosoft(this OAuthBuilder builder, Action<MicrosoftOAuthOptions> configure)
    {
        var options = new MicrosoftOAuthOptions { ClientId = "", ClientSecret = "" };
        configure(options);

        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientId and ClientSecret are required for Microsoft OAuth.");
        }

        builder.Services.AddSingleton(options);
        builder.Services.AddHttpClient<IOAuthProviderValidator, MicrosoftOAuthValidator>();
        
        return builder;
    }
}
