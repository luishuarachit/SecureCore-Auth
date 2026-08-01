using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.AspNetCore;

namespace SecureCore.Auth.AspNetCore.Tests;

public class JwtOptionsPropagationTests
{
    [Fact]
    public void FluentApi_AllowedSystemClaims_PropagatesToJwtOptions()
    {
        using var app = BuildHost(options =>
        {
            options.Jwt.Issuer = "test";
            options.Jwt.Audience = "test";
            options.Jwt.Algorithm = "HS256";
            options.Jwt.SigningKey = "0123456789abcdef0123456789abcdef";
            options.Jwt.AllowedSystemClaims = new HashSet<string> { "role", "roles" };
        });

        var jwtOptions = app.Services.GetRequiredService<IOptions<JwtOptions>>().Value;

        Assert.Contains("role", jwtOptions.AllowedSystemClaims);
        Assert.Contains("roles", jwtOptions.AllowedSystemClaims);
    }

    [Fact]
    public void FluentApi_WithoutAllowedSystemClaims_JwtOptionsHasEmptySet()
    {
        using var app = BuildHost();

        var jwtOptions = app.Services.GetRequiredService<IOptions<JwtOptions>>().Value;

        Assert.Empty(jwtOptions.AllowedSystemClaims);
    }

    private static WebApplication BuildHost(Action<SecureAuthConfiguration>? configure = null)
    {
        var builder = WebApplication.CreateBuilder(["--ENVIRONMENT=Development"]);
        builder.WebHost.UseTestServer();
        builder.WebHost.UseDefaultServiceProvider(options => options.ValidateOnBuild = true);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddScoped(_ => Substitute.For<IUserStore>());
        builder.Services.AddScoped(_ => Substitute.For<ISessionStore>());
        builder.Services.AddSecureAuth(options =>
        {
            options.Jwt.Algorithm = "HS256";
            options.Jwt.SigningKey = "0123456789abcdef0123456789abcdef";
            options.Jwt.Issuer = "test";
            options.Jwt.Audience = "test";
            configure?.Invoke(options);
        }).AddPasswordAuthentication();

        return builder.Build();
    }
}
