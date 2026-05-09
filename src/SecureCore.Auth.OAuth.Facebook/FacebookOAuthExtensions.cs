using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.Facebook.Extensions;

public static class FacebookOAuthExtensions
{
    public static OAuthBuilder AddFacebook(this OAuthBuilder builder, Action<FacebookOAuthOptions> configure)
    {
        var options = new FacebookOAuthOptions { ClientId = "", ClientSecret = "" };
        configure(options);

        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientId and ClientSecret are required for Facebook OAuth.");
        }

        builder.Services.AddSingleton(options);
        builder.Services.AddHttpClient<IOAuthProviderValidator, FacebookOAuthValidator>();
        
        return builder;
    }
}
