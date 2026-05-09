using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.LinkedIn.Extensions;

public static class LinkedInOAuthExtensions
{
    public static OAuthBuilder AddLinkedIn(this OAuthBuilder builder, Action<LinkedInOAuthOptions> configure)
    {
        var options = new LinkedInOAuthOptions { ClientId = "", ClientSecret = "" };
        configure(options);

        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientId and ClientSecret are required for LinkedIn OAuth.");
        }

        builder.Services.AddSingleton(options);
        builder.Services.AddHttpClient<IOAuthProviderValidator, LinkedInOAuthValidator>();
        
        return builder;
    }
}
