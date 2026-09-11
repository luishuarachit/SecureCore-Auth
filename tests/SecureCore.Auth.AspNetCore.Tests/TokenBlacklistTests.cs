using System.Net;
using System.Security.Claims;
using System.Text;
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
/// Tests de A-24 — blacklist de access tokens (jti) SPI opt-in: el logout blacklistea el jti
/// del access token actual con TTL = vida restante (el default NoOpTokenBlacklist es no-op).
/// </summary>
public class TokenBlacklistTests
{
    [Fact]
    public async Task Logout_WithRegisteredBlacklist_BlacklistsAccessTokenJti()
    {
        var host = await HostBuilder.CreateAsync();

        var response = await host.Client.PostAsync("/auth/logout",
            new StringContent("""{"refreshToken":"rt-1"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.Blacklist.Received(1).AddAsync(
            "test-jti", Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Logout_WithoutAuthorizationHeader_DoesNotBlacklist()
    {
        var host = await HostBuilder.CreateAsync(noAuthorizationHeader: true);

        var response = await host.Client.PostAsync("/auth/logout",
            new StringContent("""{"refreshToken":"rt-1"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.Blacklist.DidNotReceiveWithAnyArgs().AddAsync(
            Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Logout_ExpiredAccessToken_DoesNotBlacklist()
    {
        var host = await HostBuilder.CreateAsync(expired: true);

        var response = await host.Client.PostAsync("/auth/logout",
            new StringContent("""{"refreshToken":"rt-1"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await host.Blacklist.DidNotReceiveWithAnyArgs().AddAsync(
            Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    private sealed class Host
    {
        public required HttpClient Client { get; init; }
        public required ITokenBlacklist Blacklist { get; init; }
    }

    private static class HostBuilder
    {
        public static async Task<Host> CreateAsync(bool noAuthorizationHeader = false, bool expired = false)
        {
            var blacklist = Substitute.For<ITokenBlacklist>();
            blacklist.IsBlacklistedAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(ValueTask.FromResult(false));

            var userStore = Substitute.For<IUserStore>();
            userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
                .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
                {
                    Id = "u1",
                    Email = "user@example.com",
                    PasswordHash = "h",
                    SecurityStamp = "s"
                }));

            var sessionStore = Substitute.For<ISessionStore>();
            sessionStore.FindByTokenHashAsync("rt-hash", Arg.Any<CancellationToken>())
                .Returns(ValueTask.FromResult<RefreshTokenEntry?>(new RefreshTokenEntry
                {
                    TokenHash = "rt-hash",
                    FamilyId = "f1",
                    UserId = "u1",
                    ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
                }));

            var tokenService = Substitute.For<ITokenService>();
            tokenService.HashRefreshToken("rt-1").Returns("rt-hash");
            tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddMinutes(15))));
            tokenService.HashRefreshToken(Arg.Any<string>()).Returns("rt-hash");

            var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
            eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
                .Returns(Task.CompletedTask);

            var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions());
            var mfaOptions = Microsoft.Extensions.Options.Options.Create(new MfaOptions());
            var passwordHasher = Substitute.For<IPasswordHasher>();
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
                .Returns(Task.FromResult<IDisposable>(new MockLock()));
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
            builder.Services.AddSingleton<ITokenBlacklist>(blacklist);

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
            app.MapSecureAuthEndpoints("/auth");
            await app.StartAsync();

            var client = app.GetTestClient();
            client.DefaultRequestHeaders.Add("Authorization",
                $"Bearer {BuildJwt(expired)}");

            if (noAuthorizationHeader)
            {
                client.DefaultRequestHeaders.Remove("Authorization");
            }

            return new Host { Client = client, Blacklist = blacklist };
        }

        /// <summary>Construye un JWT sintácticamente válido con un jti (sin firma real: el endpoint
        /// solo lo parsea con ReadJwtToken, sin validar).</summary>
        private static string BuildJwt(bool expired)
        {
            static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            var header = B64("""{"alg":"none","typ":"JWT"}""");
            var exp = (expired ? DateTimeOffset.UtcNow.AddMinutes(-5) : DateTimeOffset.UtcNow.AddMinutes(15))
                .ToUnixTimeSeconds();
            var payload = B64($$"""{"jti":"test-jti","sub":"u1","exp":{{exp}}}""");
            return $"{header}.{payload}.c2lnbmF0dXJl";
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

    private sealed class MockLock : IDisposable
    {
        public void Dispose() { }
    }
}
