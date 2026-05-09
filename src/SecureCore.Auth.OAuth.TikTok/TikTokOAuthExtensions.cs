using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.TikTok.Extensions;

public static class TikTokOAuthExtensions
{
    public static OAuthBuilder AddTikTok(this OAuthBuilder builder, Action<TikTokOAuthOptions> configure)
    {
        var options = new TikTokOAuthOptions { ClientKey = "", ClientSecret = "" };
        configure(options);

        if (string.IsNullOrEmpty(options.ClientKey) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientKey and ClientSecret are required for TikTok OAuth.");
        }

        builder.Services.AddSingleton(options);
        builder.Services.AddHttpClient<IOAuthProviderValidator, TikTokOAuthValidator>();
        
        return builder;
    }
}
