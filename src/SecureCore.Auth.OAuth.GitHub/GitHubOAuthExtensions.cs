using System;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.OAuth.Extensions;

namespace SecureCore.Auth.OAuth.GitHub.Extensions;

public static class GitHubOAuthExtensions
{
    public static OAuthBuilder AddGitHub(this OAuthBuilder builder, Action<GitHubOAuthOptions> configure)
    {
        var options = new GitHubOAuthOptions { ClientId = "", ClientSecret = "" };
        configure(options);

        if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
        {
            throw new ArgumentException("ClientId and ClientSecret are required for GitHub OAuth.");
        }

        builder.Services.AddSingleton(options);
        
        builder.Services.AddHttpClient<IOAuthProviderValidator, GitHubOAuthValidator>();
        
        return builder;
    }
}
