using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.AspNetCore;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests del registro por defecto de IEmailService (NullEmailService).
/// </summary>
public class EmailServiceRegistrationTests
{
    [Fact]
    public void AddMfa_WithoutCustomEmailService_HostBuildsWithValidateOnBuild()
    {
        using var app = BuildHost();

        // ValidateOnBuild=true en StartHostAsync lanzaría aquí si IEmailService
        // no fuera resoluble (el bug reportado). Debe construir sin error.
        var mfa = app.Services.GetRequiredService<IEmailMfaService>();

        Assert.NotNull(mfa);
    }

    [Fact]
    public async Task AddMfa_WithoutCustomEmailService_SendCodeAsync_Throws()
    {
        using var app = BuildHost();

        var mfa = app.Services.GetRequiredService<IEmailMfaService>();

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => mfa.SendCodeAsync("user@example.com", "123456"));
    }

    [Fact]
    public async Task AddMfa_WithCustomEmailServiceRegisteredFirst_PreservesOverride()
    {
        var fake = new FakeEmailService();

        using var app = BuildHost(services =>
            services.AddScoped<IEmailService>(_ => fake));

        Assert.Same(fake, app.Services.GetRequiredService<IEmailService>());

        var mfa = app.Services.GetRequiredService<IEmailMfaService>();
        await mfa.SendCodeAsync("user@example.com", "123456");

        Assert.True(fake.Called);
    }

    private static WebApplication BuildHost(Action<IServiceCollection>? configure = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.WebHost.UseDefaultServiceProvider(options => options.ValidateOnBuild = true);
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddScoped(_ => Substitute.For<IUserStore>());
        builder.Services.AddScoped(_ => Substitute.For<ISessionStore>());
        configure?.Invoke(builder.Services);
        builder.Services.AddSecureAuth(options =>
        {
            options.Jwt.Algorithm = "HS256";
            options.Jwt.SigningKey = "0123456789abcdef0123456789abcdef";
            options.Jwt.Issuer = "test";
            options.Jwt.Audience = "test";
        }).AddPasswordAuthentication().AddMfa(o =>
        {
            o.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        });

        var app = builder.Build();

        // Forzar la construcción del provider: aquí corre ValidateOnBuild.
        _ = app.Services;

        return app;
    }

    private sealed class FakeEmailService : IEmailService
    {
        public bool Called { get; private set; }

        public Task SendAsync(
            string to,
            string subject,
            string? htmlBody = null,
            string? textBody = null,
            CancellationToken cancellationToken = default)
        {
            Called = true;
            return Task.CompletedTask;
        }
    }
}
