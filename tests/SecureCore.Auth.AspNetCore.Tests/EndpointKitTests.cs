using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.AspNetCore;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests del kit HTTP componible (F7, A-26): mappers por grupo, handlers públicos re-ruteables,
/// filtro de tamaño público y wiring uniforme (Fluent + appsettings + TryAdd).
/// </summary>
public class EndpointKitTests
{
    // ─────────────────────────────────────────────
    //  F7.1 — Kit HTTP
    // ─────────────────────────────────────────────

    [Fact]
    public async Task SessionMapper_ExposesMe_ButNotChangePassword()
    {
        // DIDÁCTICA (A-26): el host mapea solo sesión → /me existe, /change-password NO (404).
        var host = await HttpKitHost.CreateAsync(configure: app => app.MapSecureAuthSessionEndpoints("/auth"));

        Assert.Equal(HttpStatusCode.OK, (await host.Client.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.Client.GetAsync("/auth/change-password")).StatusCode);
    }

    [Fact]
    public async Task FullMapper_ExposesAllFeatures()
    {
        var host = await HttpKitHost.CreateAsync(configure: app => app.MapSecureAuthEndpoints("/auth"));

        Assert.Equal(HttpStatusCode.OK, (await host.Client.GetAsync("/auth/me")).StatusCode);
        // /change-password está mapeado (llega al handler) pero sin ChangePasswordOrchestrator → 503.
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await host.Client.PostAsync("/auth/change-password",
            new StringContent("{}", System.Text.Encoding.UTF8, "application/json"))).StatusCode);
    }

    [Fact]
    public async Task StandaloneHandler_CanBeRoutedByHost()
    {
        // DIDÁCTICA (F7): el host re-rutea un handler público a su propia ruta/verbo.
        var host = await HttpKitHost.CreateAsync(configure: app => app.MapPost("/custom/entry", SecureAuthEndpoints.LoginHandler));

        var response = await host.Client.PostAsync("/custom/entry",
            new StringContent("""{"email":"test@example.com","password":"correct"}""",
                System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task StandaloneAnonymousHandler_RejectsOversizedBodyWithPublicFilter()
    {
        // DIDÁCTICA (F7): el filtro de tamaño es PÚBLICO; el host lo reutiliza en su superficie propia.
        var host = await HttpKitHost.CreateAsync(configure: app =>
            app.MapPost("/custom/entry", SecureAuthEndpoints.LoginHandler)
               .AddEndpointFilter(SecureAuthEndpoints.EnforceAnonymousRequestSizeLimit));

        var big = new string('x', 4096);
        var response = await host.Client.PostAsync("/custom/entry",
            new StringContent($$"""{"email":"a@b.c","password":"{{big}}"}""",
                System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    // ─────────────────────────────────────────────
    //  F7.2 — Wiring uniforme
    // ─────────────────────────────────────────────

    [Fact]
    public void FluentRateLimiter_FlowsToRegisteredLimiter()
    {
        // DIDÁCTICA (F7): antes, config.Auth.RateLimiter se ignoraba (copia parcial); ahora el
        // limiter global lee IOptions<SecureAuthOptions> con la Fluent API aplicada.
        var sp = WiringHost.Build(options =>
            options.Auth.RateLimiter = new RateLimiterOptions { MaxAttempts = 2, Window = TimeSpan.FromMinutes(1) });

        var limiter = sp.GetRequiredService<IRateLimiter>();

        Assert.True(limiter.IsAllowed("ip-1"));
        Assert.True(limiter.IsAllowed("ip-1"));
        Assert.False(limiter.IsAllowed("ip-1"), "Tras 2 intentos con MaxAttempts=2, el 3º se deniega");
    }

    [Fact]
    public void FluentMaxAuthRequestBodySize_IsHonored()
    {
        var sp = WiringHost.Build(options => options.Auth.MaxAuthRequestBodySize = 4096);

        Assert.Equal(4096, sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value.MaxAuthRequestBodySize);
    }

    [Fact]
    public void FluentMfaOverrides_AreHonored()
    {
        var sp = WiringHost.Build(
            options => { },
            mfa =>
            {
                mfa.EmailCodeLifetimeMinutes = 12;
                mfa.EncryptionKey = new string('a', 64);
            });

        Assert.Equal(12, sp.GetRequiredService<IOptions<MfaOptions>>().Value.EmailCodeLifetimeMinutes);
    }

    [Fact]
    public void JwtValidation_IsAlignedWithEmission_SameOptionsSource()
    {
        // DIDÁCTICA (F7): la VALIDACIÓN Bearer se configura desde IOptions<JwtOptions> (la MISMA
        // fuente que la emisión). Antes usaba config.Jwt (objeto Fluent), pudiendo desincronizarse
        // de appsettings. La garantía: ValidIssuer/ValidAudience del Bearer == los de JwtOptions.
        var sp = WiringHost.Build(options => { });

        var jwt = sp.GetRequiredService<IOptions<JwtOptions>>().Value;
        var bearer = sp.GetRequiredService<IOptions<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>>().Value;

        Assert.Equal(jwt.Issuer, bearer.TokenValidationParameters.ValidIssuer);
        Assert.Equal(jwt.Audience, bearer.TokenValidationParameters.ValidAudience);
    }

    [Fact]
    public void HostPasswordHasherOverride_IsRespected()
    {
        var myHasher = Substitute.For<IPasswordHasher>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(Substitute.For<IHostEnvironment>());
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton<IPasswordHasher>(myHasher);
        var builder = services.AddSecureAuth(options => { });
        builder.AddPasswordAuthentication();

        var sp = services.BuildServiceProvider();
        var resolved = sp.GetRequiredService<IPasswordHasher>();

        Assert.Same(myHasher, resolved);
    }

    // ─────────────────────────────────────────────
    //  F8 — Merge estructural appsettings ↔ Fluent
    // ─────────────────────────────────────────────

    [Fact]
    public void AppSettingsOnly_SecureAuthBodyLimit_IsHonored()
    {
        // DIDÁCTICA (F8): antes la copia Fluent sobrescribía appsettings con defaults; ahora
        // appsettings es la base y solo lo que el host toca por Fluent lo pisa.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["SecureAuth:MaxAuthRequestBodySize"] = "4096" })
            .Build();

        var sp = WiringHost.Build(_ => { }, config: config);

        Assert.Equal(4096, sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value.MaxAuthRequestBodySize);
    }

    [Fact]
    public void AppSettingsOnly_JwtAlgorithm_IsHonored()
    {
        // DIDÁCTICA (F8): JWT solo por appsettings ya no cae al default Fluent (RS256).
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SecureAuth:Jwt:Issuer"] = "appsettings-issuer",
                ["SecureAuth:Jwt:Audience"] = "appsettings-audience",
                ["SecureAuth:Jwt:Algorithm"] = "HS256",
                ["SecureAuth:Jwt:SigningKey"] = "appsettings-signing-key-at-least-32-chars!!"
            })
            .Build();

        var sp = WiringHost.Build(_ => { }, config: config, fluentJwt: false);

        Assert.Equal("HS256", sp.GetRequiredService<IOptions<JwtOptions>>().Value.Algorithm);
    }

    [Fact]
    public void AppSettingsOnly_MfaOptions_IsHonored()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["SecureAuth:Mfa:EmailCodeLifetimeMinutes"] = "10" })
            .Build();

        var sp = WiringHost.Build(
            _ => { },
            mfa => mfa.EncryptionKey = new string('a', 64),
            config: config);

        Assert.Equal(10, sp.GetRequiredService<IOptions<MfaOptions>>().Value.EmailCodeLifetimeMinutes);
    }

    [Fact]
    public void Fluent_WinsOverAppSettings()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["SecureAuth:MaxFailedAttempts"] = "3" })
            .Build();

        var sp = WiringHost.Build(options => options.Auth.MaxFailedAttempts = 7, config: config);

        Assert.Equal(7, sp.GetRequiredService<IOptions<SecureAuthOptions>>().Value.MaxFailedAttempts);
    }

    [Fact]
    public async Task ReroutedAnonymousHandler_RejectsOversizedBody_WithoutFilter()
    {
        // DIDÁCTICA (F8, limitación C): la protección de tamaño es INTRÍNSECA al handler — al
        // re-rutearlo a una ruta propia (sin el filter público) sigue devolviendo 413.
        var host = await HttpKitHost.CreateAsync(configure: app => app.MapPost("/custom/entry", SecureAuthEndpoints.LoginHandler));

        var big = new string('x', 4096);
        var response = await host.Client.PostAsync("/custom/entry",
            new StringContent($$"""{"email":"a@b.c","password":"{{big}}"}""",
                System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }
}

internal static class WiringHost
{
    public static ServiceProvider Build(
        Action<SecureAuthConfiguration> configure,
        Action<MfaOptions>? mfa = null,
        IConfiguration? config = null,
        bool fluentJwt = true)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(Substitute.For<IHostEnvironment>());
        services.AddSingleton<IConfiguration>(config ?? new ConfigurationBuilder().Build());

        var builder = services.AddSecureAuth(options =>
        {
            if (fluentJwt)
            {
                options.Jwt.Issuer = "test-issuer";
                options.Jwt.Audience = "test-audience";
                options.Jwt.Algorithm = "HS256";
                options.Jwt.SigningKey = "test-signing-key-at-least-32-characters!";
            }

            configure(options);
        });
        builder.AddPasswordAuthentication();
        if (mfa is not null)
        {
            builder.AddMfa(mfa);
        }

        return services.BuildServiceProvider();
    }
}

internal static class HttpKitHost
{
    public static async Task<HttpTestHost> CreateAsync(Action<WebApplication> configure)
    {
        var userStore = Substitute.For<IUserStore>();
        userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
            {
                Id = "u1",
                Email = "user@example.com",
                PasswordHash = "h",
                SecurityStamp = "s"
            }));
        userStore.FindByEmailAsync("test@example.com", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
            {
                Id = "u1",
                Email = "test@example.com",
                PasswordHash = "h",
                SecurityStamp = "s"
            }));

        var passwordHasher = Substitute.For<IPasswordHasher>();
        passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);

        var tokenService = Substitute.For<ITokenService>();
        tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1))));
        tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");

        var sessionStore = Substitute.For<ISessionStore>();
        var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions());
        var mfaOptions = Microsoft.Extensions.Options.Options.Create(new MfaOptions());
        var mfaSessionStore = Substitute.For<IMfaSessionStore>();
        var mfaService = Substitute.For<IMfaService>();

        var lockoutManager = new LockoutManager(userStore, authOptions, NullLogger<LockoutManager>.Instance);
        var orchestrator = new IdentityOrchestrator(
            userStore, passwordHasher, tokenService, sessionStore, lockoutManager, eventDispatcher,
            authOptions, mfaOptions, mfaSessionStore, mfaService, NullLogger<IdentityOrchestrator>.Instance);

        var stampValidator = new SecurityStampValidator(
            userStore, Substitute.For<IDistributedCache>(), authOptions, NullLogger<SecurityStampValidator>.Instance);
        var operationLock = Substitute.For<IOperationLock>();
        operationLock.AcquireAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IDisposable>(new LockHolder()));
        var sessionOrchestrator = new SessionOrchestrator(
            sessionStore, userStore, tokenService, stampValidator, eventDispatcher,
            authOptions, operationLock, NullLogger<SessionOrchestrator>.Instance);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(authOptions);
        builder.Services.AddSingleton(mfaOptions);
        builder.Services.AddSingleton<IUserStore>(userStore);
        builder.Services.AddSingleton(orchestrator);
        builder.Services.AddSingleton(sessionOrchestrator);
        builder.Services.AddSingleton(sessionStore);
        builder.Services.AddSingleton((ITokenService)tokenService);
        var rateLimiter = Substitute.For<IRateLimiter>();
        rateLimiter.IsAllowed(Arg.Any<string>()).Returns(true);
        builder.Services.AddSingleton(rateLimiter);
        builder.Services.AddSingleton(eventDispatcher);

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Test";
                options.DefaultChallengeScheme = "Test";
            })
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
        builder.Services.AddAuthorization();

        var app = builder.Build();

        app.Use(async (context, next) =>
        {
            context.User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "u1")], authenticationType: "test"));
            await next(context);
        });

        app.UseAuthorization();
        configure(app);
        await app.StartAsync();

        return new HttpTestHost { Client = app.GetTestClient() };
    }

    private sealed class LockHolder : IDisposable
    {
        public void Dispose() { }
    }
}

internal sealed class HttpTestHost
{
    public required HttpClient Client { get; init; }
}

internal sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    Microsoft.Extensions.Logging.ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        => Task.FromResult(AuthenticateResult.NoResult());
}
