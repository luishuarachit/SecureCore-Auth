using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests de <c>GET /auth/me</c> (F6, A-25) — perfil del usuario autenticado: hasPassword fresco
/// (leído del store, nunca de un claim) y estado MFA.
/// </summary>
/// <remarks>
/// DIDÁCTICA: <c>/me</c> es AUTENTICADO (solo la cuenta del token, sin riesgo de enumeración).
/// <c>hasPassword</c> no va en claims porque un token emitido antes de crear la contraseña
/// mentiría tras el cambio; aquí se lee del store en cada llamada.
/// </remarks>
public class SecureAuthMeEndpointsTests
{
    [Fact]
    public async Task Me_NotAuthenticated_Returns401()
    {
        var host = await MeHostBuilder.CreateAsync(authenticated: false);

        var response = await host.Client.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_Authenticated_WithPassword_ReturnsHasPasswordTrue()
    {
        var host = await MeHostBuilder.CreateAsync(authenticated: true);

        var response = await host.Client.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("u1", body.RootElement.GetProperty("id").GetString());
        Assert.Equal("user@example.com", body.RootElement.GetProperty("email").GetString());
        Assert.True(body.RootElement.GetProperty("hasPassword").GetBoolean());
        Assert.Equal("Enrolled", body.RootElement.GetProperty("mfaEnrollmentStatus").GetString());
        Assert.Equal("totp", body.RootElement.GetProperty("preferredMfaMethod").GetString());
    }

    [Fact]
    public async Task Me_Authenticated_WithoutPassword_ReturnsHasPasswordFalse()
    {
        var host = await MeHostBuilder.CreateAsync(authenticated: true, withPassword: false);

        var response = await host.Client.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(body.RootElement.GetProperty("hasPassword").GetBoolean());
    }

    [Fact]
    public async Task Me_Authenticated_UserNotFound_Returns401()
    {
        var host = await MeHostBuilder.CreateAsync(authenticated: true, userFound: false);

        var response = await host.Client.GetAsync("/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private sealed class MeHost
    {
        public required HttpClient Client { get; init; }
    }

    private static class MeHostBuilder
    {
        public static async Task<MeHost> CreateAsync(bool authenticated, bool withPassword = true, bool userFound = true)
        {
            var userStore = Substitute.For<IUserStore>();
            if (userFound)
            {
                userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
                    .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
                    {
                        Id = "u1",
                        Email = "user@example.com",
                        PasswordHash = withPassword ? "hashed" : null,
                        SecurityStamp = "stamp",
                        TwoFactorEnabled = true,
                        MfaEnrollmentStatus = MfaEnrollmentStatus.Enrolled,
                        PreferredMfaMethod = "totp"
                    }));
            }

            var passwordHasher = Substitute.For<IPasswordHasher>();
            var tokenService = Substitute.For<ITokenService>();
            tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
                .Returns(new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1)));
            tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

            var sessionStore = Substitute.For<ISessionStore>();
            var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
            eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
                .Returns(Task.CompletedTask);

            var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions());
            var mfaOptions = Microsoft.Extensions.Options.Options.Create(new MfaOptions());

            var lockoutManager = new LockoutManager(userStore, authOptions, NullLogger<LockoutManager>.Instance);
            var orchestrator = new IdentityOrchestrator(
                userStore, passwordHasher, tokenService, sessionStore, lockoutManager,
                eventDispatcher, authOptions, mfaOptions,
                Substitute.For<IMfaSessionStore>(), Substitute.For<IMfaService>(),
                NullLogger<IdentityOrchestrator>.Instance);

            var stampValidator = new SecurityStampValidator(
                userStore, Substitute.For<IDistributedCache>(), authOptions,
                NullLogger<SecurityStampValidator>.Instance);
            var operationLock = Substitute.For<IOperationLock>();
            operationLock.AcquireAsync(Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<IDisposable>(new MockOperationLock()));
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

            // DIDÁCTICA: el handler de test devuelve NoResult (nunca autentica); el usuario se
            // inyecta con un middleware cuando el test lo pide (mismo patrón que los tests de
            // recovery codes). En producción la autenticación la hace el JWT bearer real.
            if (authenticated)
            {
                app.Use(async (context, next) =>
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim("sub", "u1")],
                        authenticationType: "test"));
                    await next(context);
                });
            }

            app.UseAuthorization();
            app.MapSecureAuthEndpoints("/auth");
            await app.StartAsync();

            return new MeHost { Client = app.GetTestClient() };
        }
    }

    private sealed class TestAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class MockOperationLock : IDisposable
    {
        public void Dispose() { }
    }
}
