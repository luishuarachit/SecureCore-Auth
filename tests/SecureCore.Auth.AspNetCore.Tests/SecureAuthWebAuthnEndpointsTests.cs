using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;
using SecureCore.Auth.WebAuthn;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests de SecureAuthWebAuthnEndpoints — ceremonias S4: rutas, 503/401/400 sin fuga de
/// información, validación de payload y emisión de tokens en login/complete.
/// </summary>
public class SecureAuthWebAuthnEndpointsTests
{
    private const string AllowedOrigin = "https://test.example.com";
    private const string EvilOrigin = "https://evil.example.com";

    private const string AssertionOptionsJson = """
        {"challenge":"AQIDBAUGBwgJ","rpId":"test.example.com","timeout":60000,"userVerification":"preferred","allowCredentials":[]}
        """;

    private const string AssertionResponseBody = """
        {"origin":"%ORIGIN%","challengeId":"ch1","assertionResponse":{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"AQI=","authenticatorData":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signature":"AAAA","userHandle":"AQID"}}}
        """;

    private const string OriginBody = """{"origin":"%ORIGIN%"}""";

    private const string OriginAndChallengeBody = """{"origin":"%ORIGIN%","challengeId":"ch1"}""";

    // ─────────────────────────────────────────────
    //  Registro (endpoints autenticados)
    // ─────────────────────────────────────────────

    [Fact]
    public async Task RegisterBegin_NotAuthenticated_Returns401()
    {
        var host = new WebAuthnHostBuilder().Build();

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/register/begin", content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await host.ChallengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RegisterComplete_NotAuthenticated_Returns401()
    {
        var host = new WebAuthnHostBuilder().Build();

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/register/complete", content);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RegisterBegin_NotConfigured_Returns503()
    {
        // DIDÁCTICA: sin AddWebAuthn el orquestador no está registrado → 503 explícito
        // para que el host detecte una configuración incompleta en lugar de un 500 opaco.
        var host = new WebAuthnHostBuilder { RegisterOrchestrator = false, AuthenticatedRequests = true }.Build();

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/register/begin", content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("webauthn_not_configured", body);
    }

    [Fact]
    public async Task RegisterComplete_NotConfigured_Returns503()
    {
        var host = new WebAuthnHostBuilder { RegisterOrchestrator = false, AuthenticatedRequests = true }.Build();

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/register/complete", content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    // ─────────────────────────────────────────────
    //  Login (endpoints anónimos)
    // ─────────────────────────────────────────────

    [Fact]
    public async Task LoginBegin_NotConfigured_Returns503()
    {
        var host = new WebAuthnHostBuilder { RegisterOrchestrator = false }.Build();

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/begin", content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task LoginComplete_NotConfigured_Returns503()
    {
        var host = new WebAuthnHostBuilder { RegisterOrchestrator = false }.Build();

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/complete", content);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task LoginBegin_ValidOrigin_Returns200WithChallengeAndOptions()
    {
        var host = new WebAuthnHostBuilder().Build();
        host.Fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));
        host.ChallengeStore.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/begin", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("challengeId").GetString()));
        var challenge = doc.RootElement.GetProperty("options").GetProperty("challenge");
        if (challenge.ValueKind == JsonValueKind.String)
        {
            Assert.False(string.IsNullOrEmpty(challenge.GetString()));
        }
        else
        {
            Assert.True(challenge.GetArrayLength() > 0);
        }
        await host.ChallengeStore.Received(1).CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), TimeSpan.FromSeconds(60), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginBegin_DisallowedOrigin_Returns400_WithoutEchoingOrigin()
    {
        var host = new WebAuthnHostBuilder().Build();

        var content = PostJson(OriginBody.Replace("%ORIGIN%", EvilOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/begin", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("webauthn_origin_not_allowed", body);
        // DIDÁCTICA: el origin rechazado NUNCA se devuelve en el response (anti-enumeración).
        Assert.DoesNotContain(EvilOrigin, body);
        await host.ChallengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginBegin_MissingOrigin_Returns400Validation()
    {
        var host = new WebAuthnHostBuilder().Build();

        var content = PostJson("""{"userId":"u1"}""");
        var response = await host.Client.PostAsync("/auth/webauthn/login/begin", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await host.ChallengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginComplete_ValidAssertion_ReturnsTokens()
    {
        var host = new WebAuthnHostBuilder().Build();
        StubSuccessfulLogin(host);
        host.TokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("access-token", "refresh-token", DateTimeOffset.UtcNow.AddHours(1)));
        host.TokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/complete", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("access-token", doc.RootElement.GetProperty("accessToken").GetString());
        Assert.Equal("refresh-token", doc.RootElement.GetProperty("refreshToken").GetString());
        await host.SessionStore.Received(1).CreateAsync(Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginComplete_MissingAssertionResponse_Returns400()
    {
        var host = new WebAuthnHostBuilder().Build();

        var content = PostJson(OriginAndChallengeBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/complete", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("invalid_payload", body);
        await host.ChallengeStore.DidNotReceiveWithAnyArgs().GetAndDeleteAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginComplete_ReusedChallenge_Returns400Generic()
    {
        // DIDÁCTICA (S2): challenge ya usado/expirado → error genérico, indistinguible de
        // credencial no encontrada o firma inválida (anti-enumeración).
        var host = new WebAuthnHostBuilder().Build();
        host.ChallengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/complete", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("authentication_failed", body);
        await host.TokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginComplete_FailedAssertion_WithLockout_Returns423()
    {
        var host = new WebAuthnHostBuilder { EnableProtection = true }.Build();
        host.ChallengeStore.GetAndDeleteAsync("login:ch1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(AssertionOptionsJson));
        host.CredentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(NewStoredCredential("u1")));
        host.UserStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(NewUser("u1")));
        host.Fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<Fido2NetLib.Objects.VerifyAssertionResult>(
                new Fido2VerificationException("firma inválida (mock)")));
        host.Protection.CheckAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(
                Allowed: false, RemainingAttempts: 0, LockEnd: DateTimeOffset.UtcNow.AddMinutes(10), EscalationLevel: 1)));

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/complete", content);

        Assert.Equal(HttpStatusCode.Locked, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("authentication_failed", body);
        await host.Protection.Received(1).RecordFailureAsync(
            AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginBegin_RateLimited_Returns429_NoChallengeCreated()
    {
        // DIDÁCTICA (A-29): el begin anónimo se limita por IP ANTES de generar el challenge.
        var host = new WebAuthnHostBuilder { RegisterWebAuthnRateLimiters = true }.Build();
        host.Fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));
        host.ChallengeStore.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var first = await host.Client.PostAsync("/auth/webauthn/login/begin", content);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        var second = await host.Client.PostAsync("/auth/webauthn/login/begin", content);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);

        // Solo el primer intento llegó a crear challenge.
        await host.ChallengeStore.Received(1).CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LoginBegin_NoRateLimiterRegistered_WorksNormally()
    {
        // DIDÁCTICA (A-29): si el host no registró el limiter keyed (ej. Mini API sin
        // AddSecureAuth), el endpoint degrada con gracia: sin límite, pero sin 500.
        var host = new WebAuthnHostBuilder().Build();
        host.Fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));
        host.ChallengeStore.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var content = PostJson(OriginBody.Replace("%ORIGIN%", AllowedOrigin));
        var response = await host.Client.PostAsync("/auth/webauthn/login/begin", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task LoginComplete_RateLimited_Returns429_NoChallengeConsumed()
    {
        // DIDÁCTICA (A-29): el complete anónimo se limita por IP ANTES de consumir el challenge.
        var host = new WebAuthnHostBuilder { RegisterWebAuthnRateLimiters = true }.Build();
        host.ChallengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        var content = PostJson(AssertionResponseBody.Replace("%ORIGIN%", AllowedOrigin));
        var first = await host.Client.PostAsync("/auth/webauthn/login/complete", content);
        Assert.Equal(HttpStatusCode.BadRequest, first.StatusCode);

        var second = await host.Client.PostAsync("/auth/webauthn/login/complete", content);
        Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode);

        // Solo el primer intento llegó a consumir (reusado → 400 genérico).
        await host.ChallengeStore.Received(1).GetAndDeleteAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
        await host.TokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
    }

    // ─────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────

    private static StringContent PostJson(string body)
    {
        return new StringContent(body, Encoding.UTF8, "application/json");
    }

    private static UserIdentity NewUser(string id = "u1")
    {
        return new UserIdentity { Id = id, Email = $"{id}@example.com", SecurityStamp = "stamp" };
    }

    private static StoredCredential NewStoredCredential(string userId)
    {
        return new StoredCredential
        {
            CredentialId = [1, 2, 3],
            PublicKey = [9, 9, 9],
            UserId = userId,
            SignatureCount = 5
        };
    }

    private static void StubSuccessfulLogin(WebAuthnHostBuilderHost host)
    {
        host.ChallengeStore.GetAndDeleteAsync("login:ch1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(AssertionOptionsJson));
        host.CredentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(NewStoredCredential("u1")));
        host.Fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new Fido2NetLib.Objects.VerifyAssertionResult { CredentialId = [1, 2, 3], SignCount = 6 });
        host.UserStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(NewUser("u1")));
    }

    private sealed class WebAuthnHostBuilderHost
    {
        public required HttpClient Client { get; init; }
        public required IFido2 Fido2 { get; init; }
        public required ICredentialStore CredentialStore { get; init; }
        public required IUserStore UserStore { get; init; }
        public required IWebAuthnChallengeStore ChallengeStore { get; init; }
        public required ITokenService TokenService { get; init; }
        public required ISessionStore SessionStore { get; init; }
        public required IAccountProtectionService Protection { get; init; }
    }

    private sealed class WebAuthnHostBuilder
    {
        public bool RegisterOrchestrator { get; init; } = true;
        public bool AuthenticatedRequests { get; init; } = false;
        public bool EnableProtection { get; init; } = false;
        public bool RegisterWebAuthnRateLimiters { get; init; } = false;

        public WebAuthnHostBuilderHost Build()
        {
            var fido2 = Substitute.For<IFido2>();
            var credentialStore = Substitute.For<ICredentialStore>();
            var userStore = Substitute.For<IUserStore>();
            var challengeStore = Substitute.For<IWebAuthnChallengeStore>();
            var tokenService = Substitute.For<ITokenService>();
            var sessionStore = Substitute.For<ISessionStore>();
            var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
            var protection = Substitute.For<IAccountProtectionService>();
            var mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();
            eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
                .Returns(Task.CompletedTask);

            var webAuthnOptions = Microsoft.Extensions.Options.Options.Create(new WebAuthnOptions
            {
                RelyingPartyName = "Test RP",
                RelyingPartyId = "test.example.com",
                Origins = [AllowedOrigin],
                ChallengeTimeoutSeconds = 60
            });

            var passkeyService = new PasskeyService(
                fido2,
                credentialStore,
                userStore,
                eventDispatcher,
                webAuthnOptions,
                NullLogger<PasskeyService>.Instance);

            var orchestrator = new WebAuthnOrchestrator(
                passkeyService,
                challengeStore,
                userStore,
                tokenService,
                sessionStore,
                eventDispatcher,
                webAuthnOptions,
                Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions()),
                NullLogger<WebAuthnOrchestrator>.Instance,
                EnableProtection ? protection : null,
                EnableProtection ? Microsoft.Extensions.Options.Options.Create(new AccountProtectionOptions { Enabled = true }) : null,
                mfaVerified);

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();
            // DIDÁCTICA: `RequireAuthorization` sin servicios de autenticación hace que el
            // challenge (401) falle con InvalidOperationException y se traduzca en un 500,
            // porque ningún AuthenticationHandler atiende la petición. En producción SecureCore
            // registra JWT; aquí registramos un esquema "test" cuyo handler responde NoResult(),
            // de modo que el pipeline se comporta igual: anónimo -> deny -> challenge -> 401.
            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                })
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
            builder.Services.AddAuthorization();
            if (RegisterOrchestrator)
            {
                builder.Services.AddSingleton(orchestrator);
            }

            if (RegisterWebAuthnRateLimiters)
            {
                // DIDÁCTICA: limiter keyed de 1 intento/ventana para probar el corte 429.
                builder.Services.AddKeyedSingleton<IRateLimiter>("webauthn-begin",
                    (_, _) => new InMemoryRateLimiter(1, TimeSpan.FromMinutes(1)));
                builder.Services.AddKeyedSingleton<IRateLimiter>("webauthn-complete",
                    (_, _) => new InMemoryRateLimiter(1, TimeSpan.FromMinutes(1)));
            }

            var app = builder.Build();

            if (AuthenticatedRequests)
            {
                app.Use(async (HttpContext context, RequestDelegate next) =>
                {
                    context.User = new ClaimsPrincipal(new ClaimsIdentity(
                        [new Claim("sub", "u1")],
                        authenticationType: "test"));
                    await next(context);
                });
            }
            app.UseAuthorization();
            app.MapSecureAuthWebAuthnEndpoints("/auth/webauthn");
            app.StartAsync().GetAwaiter().GetResult();

            return new WebAuthnHostBuilderHost
            {
                Client = app.GetTestClient(),
                Fido2 = fido2,
                CredentialStore = credentialStore,
                UserStore = userStore,
                ChallengeStore = challengeStore,
                TokenService = tokenService,
                SessionStore = sessionStore,
                Protection = protection
            };
        }
    }

    private sealed class TestAuthHandler(
        Microsoft.Extensions.Options.IOptionsMonitor<AuthenticationSchemeOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {

        // DIDÁCTICA: NoResult() => identidad anónima. La autenticación "real" en tests se
        // simula con el middleware de requests autenticados, no con el scheme.
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
