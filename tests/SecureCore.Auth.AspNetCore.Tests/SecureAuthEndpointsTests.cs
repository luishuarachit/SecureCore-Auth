using System.Net;
using System.Net.Http;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests para SecureAuthEndpoints — límite de tamaño de payload (A-10) y comportamiento HTTP.
/// </summary>
public class SecureAuthEndpointsTests
{
    [Fact]
    public void MaxAuthRequestBodySize_HasSecureDefaultOf2Kb()
    {
        var options = new SecureAuthOptions();

        Assert.Equal(2048, options.MaxAuthRequestBodySize);
    }

    [Fact]
    public async Task Login_LargeContentLength_Returns413()
    {
        var client = StartServer();

        // Cuerpo JSON VÁLIDO pero superior a MaxAuthRequestBodySize (2048).
        // (Un JSON malformado sería rechazado antes con 400 por el binder; también
        // queda bloqueado, pero el caso representativo del filtro es el cuerpo válido).
        var content = new StringContent(
            "{\"email\":\"a@a.com\",\"password\":\"" + new string('a', 4090) + "\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/login", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task Login_SmallBody_PassesThroughToHandler()
    {
        var client = StartServer();

        var content = new StringContent(
            "{\"email\":\"test@example.com\",\"password\":\"pass\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/login", content);

        // El filtro de tamaño no debe interferir con payloads legítimos: el handler
        // autentica con éxito y responde 200 con los tokens.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_WithMiddlewareRegistered_SmallBodyStillPasses()
    {
        var client = StartServer(registerSizeLimitMiddleware: true);

        var content = new StringContent(
            "{\"email\":\"test@example.com\",\"password\":\"pass\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/login", content);

        // El middleware UseSecureAuthRequestSizeLimit no debe interferir con payloads legítimos
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Refresh_LargeContentLength_Returns413()
    {
        var client = StartServer();

        var content = new StringContent(
            "{\"refreshToken\":\"" + new string('b', 4090) + "\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/refresh", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_LargeContentLength_Returns413()
    {
        var client = StartServer();

        var content = new StringContent(
            "{\"email\":\"" + new string('c', 4090) + "\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/forgot-password", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_ExceedingPerIpLimit_StaysBlind200AndSkipsStore()
    {
        var (client, resetStore) = StartResetServer(limiterMaxAttempts: 2);

        var content = new StringContent(
            "{\"email\":\"user@example.com\"}",
            Encoding.UTF8,
            "application/json");

        var first = await client.PostAsync("/auth/forgot-password", content);
        var second = await client.PostAsync("/auth/forgot-password", content);
        var third = await client.PostAsync("/auth/forgot-password", content);

        // El throttling es SILENCIOSO (Nº5): las tres respuestas son 200 ciego,
        // pero solo las dos primeras llegaron al orquestador/store.
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.OK, third.StatusCode);
        await resetStore.Received(2).StoreAsync(Arg.Any<PasswordResetEntry>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ForgotPassword_ValidSmallBody_Returns200Blind()
    {
        var (client, resetStore) = StartResetServer(limiterMaxAttempts: 5);

        var content = new StringContent(
            "{\"email\":\"user@example.com\"}",
            Encoding.UTF8,
            "application/json");

        var response = await client.PostAsync("/auth/forgot-password", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await resetStore.Received(1).StoreAsync(Arg.Any<PasswordResetEntry>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResetPassword_LargeContentLength_Returns413()
    {
        var client = StartServer();

        var content = new StringContent(
            "{\"token\":\"" + new string('d', 4090) + "\",\"newPassword\":\"x\"}",
            Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/auth/reset-password", content);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    // ─────────────────────────────────────────────
    //  Test host
    // ─────────────────────────────────────────────

    private static HttpClient StartServer(
        Action<SecureAuthOptions>? configureOptions = null,
        bool registerSizeLimitMiddleware = false)
    {
        var userStore = Substitute.For<IUserStore>();
        userStore.FindByEmailAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
            {
                Id = "u1",
                Email = "test@example.com",
                PasswordHash = "hashed",
                SecurityStamp = "stamp"
            }));

        var passwordHasher = Substitute.For<IPasswordHasher>();
        passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>())
            .Returns(PasswordVerificationResult.Success);
        passwordHasher.VerifyPasswordAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(PasswordVerificationResult.Success);

        var tokenService = Substitute.For<ITokenService>();
        tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1)));
        tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var sessionStore = Substitute.For<ISessionStore>();
        var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var mfaSessionStore = Substitute.For<IMfaSessionStore>();
        var mfaService = Substitute.For<IMfaService>();

        var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions());
        configureOptions?.Invoke(authOptions.Value);
        var mfaOptions = Microsoft.Extensions.Options.Options.Create(new MfaOptions());

        var lockoutManager = new LockoutManager(
            userStore, authOptions, NullLogger<LockoutManager>.Instance);

        var orchestrator = new IdentityOrchestrator(
            userStore,
            passwordHasher,
            tokenService,
            sessionStore,
            lockoutManager,
            eventDispatcher,
            authOptions,
            mfaOptions,
            mfaSessionStore,
            mfaService,
            NullLogger<IdentityOrchestrator>.Instance);

        // Los endpoints /auth/refresh, /auth/logout y /auth/revoke-all reciben
        // SessionOrchestrator por DI, así que hay que registrarlo de forma real.
        var stampValidator = new SecurityStampValidator(
            userStore,
            Substitute.For<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            authOptions,
            NullLogger<SecurityStampValidator>.Instance);

        var operationLock = Substitute.For<IOperationLock>();
        operationLock.AcquireAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IDisposable>(new MockOperationLock()));

        var sessionOrchestrator = new SessionOrchestrator(
            sessionStore,
            userStore,
            tokenService,
            stampValidator,
            eventDispatcher,
            authOptions,
            operationLock,
            NullLogger<SessionOrchestrator>.Instance);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(authOptions);
        builder.Services.AddSingleton(mfaOptions);
        builder.Services.AddSingleton(orchestrator);
        builder.Services.AddSingleton(sessionOrchestrator);
        builder.Services.AddSingleton(sessionStore);
        builder.Services.AddSingleton((ITokenService)tokenService);
        var rateLimiter = Substitute.For<IRateLimiter>();
        rateLimiter.IsAllowed(Arg.Any<string>()).Returns(true);
        builder.Services.AddSingleton(rateLimiter);
        builder.Services.AddSingleton(eventDispatcher);

        var app = builder.Build();
        app.MapSecureAuthEndpoints();

        if (registerSizeLimitMiddleware)
        {
            app.UseSecureAuthRequestSizeLimit();
        }

        app.StartAsync().GetAwaiter().GetResult();

        return app.GetTestClient();
    }

    private static (HttpClient Client, IPasswordResetStore ResetStore) StartResetServer(
        int limiterMaxAttempts = 5)
    {
        var userStore = Substitute.For<IUserStore>();
        userStore.FindByEmailAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
            {
                Id = "u1",
                Email = "user@example.com",
                PasswordHash = "hashed",
                SecurityStamp = "stamp"
            }));

        var resetStore = Substitute.For<IPasswordResetStore>();
        resetStore.CountRecentRequestsAsync(Arg.Any<string>(), Arg.Any<DateTime>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(0));
        resetStore.UpdateDeliveryStateAsync(
            Arg.Any<string>(), Arg.Any<PasswordResetDeliveryState>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var mailer = Substitute.For<IResetTokenMailer>();
        mailer.SendResetEmailAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var passwordHasher = Substitute.For<IPasswordHasher>();
        var tokenService = Substitute.For<ITokenService>();
        var sessionStore = Substitute.For<ISessionStore>();
        var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions());
        var mfaOptions = Microsoft.Extensions.Options.Options.Create(new MfaOptions());

        var mfaSessionStore = Substitute.For<IMfaSessionStore>();
        var mfaService = Substitute.For<IMfaService>();

        var lockoutManager = new LockoutManager(
            userStore, authOptions, NullLogger<LockoutManager>.Instance);

        var identityOrchestrator = new IdentityOrchestrator(
            userStore,
            passwordHasher,
            tokenService,
            sessionStore,
            lockoutManager,
            eventDispatcher,
            authOptions,
            mfaOptions,
            mfaSessionStore,
            mfaService,
            NullLogger<IdentityOrchestrator>.Instance);

        var stampValidator = new SecurityStampValidator(
            userStore,
            Substitute.For<Microsoft.Extensions.Caching.Distributed.IDistributedCache>(),
            authOptions,
            NullLogger<SecurityStampValidator>.Instance);

        var operationLock = Substitute.For<IOperationLock>();
        operationLock.AcquireAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IDisposable>(new MockOperationLock()));

        var sessionOrchestrator = new SessionOrchestrator(
            sessionStore,
            userStore,
            tokenService,
            stampValidator,
            eventDispatcher,
            authOptions,
            operationLock,
            NullLogger<SessionOrchestrator>.Instance);

        var resetOrchestrator = new PasswordResetOrchestrator(
            userStore,
            resetStore,
            mailer,
            passwordHasher,
            sessionOrchestrator,
            eventDispatcher,
            Microsoft.Extensions.Options.Options.Create(new PasswordResetOptions()),
            NullLogger<PasswordResetOrchestrator>.Instance);

        var forgotRateLimiter = Substitute.For<IRateLimiter>();
        var attempts = 0;
        forgotRateLimiter.IsAllowed(Arg.Any<string>()).Returns(_ => ++attempts <= limiterMaxAttempts);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(authOptions);
        builder.Services.AddSingleton(mfaOptions);
        builder.Services.AddSingleton(identityOrchestrator);
        builder.Services.AddSingleton(sessionOrchestrator);
        builder.Services.AddSingleton(sessionStore);
        builder.Services.AddSingleton((ITokenService)tokenService);
        var loginRateLimiter = Substitute.For<IRateLimiter>();
        loginRateLimiter.IsAllowed(Arg.Any<string>()).Returns(true);
        builder.Services.AddSingleton(loginRateLimiter);
        builder.Services.AddSingleton(resetOrchestrator);
        builder.Services.AddSingleton(resetStore);
        builder.Services.AddSingleton((IResetTokenMailer)mailer);
        builder.Services.AddSingleton(eventDispatcher);
        builder.Services.AddKeyedSingleton<IRateLimiter>("forgot-password", (_, _) => forgotRateLimiter);

        var app = builder.Build();
        app.MapSecureAuthEndpoints();
        app.StartAsync().GetAwaiter().GetResult();

        return (app.GetTestClient(), resetStore);
    }

    private sealed class MockOperationLock : IDisposable
    {
        public void Dispose() { }
    }
}
