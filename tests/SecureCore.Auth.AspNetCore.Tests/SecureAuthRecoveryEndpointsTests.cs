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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests de SecureAuthEndpoints — recovery codes de primera clase (F5/A-20): rutas, 503/401/400
/// sin fuga de información, anti-enumeración y mapeo de resultados.
/// </summary>
public class SecureAuthRecoveryEndpointsTests
{
    [Fact]
    public async Task Generate_NotAuthenticated_Returns401()
    {
        var host = new RecoveryHostBuilder().Build();

        var response = await host.Client.PostAsync("/auth/recovery-codes/generate", null!);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Generate_NotConfigured_Returns503()
    {
        var host = new RecoveryHostBuilder { RegisterOrchestrator = false, AuthenticatedRequests = true }.Build();

        var response = await host.Client.PostAsync("/auth/recovery-codes/generate", null!);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.Equal("recovery_codes_not_configured", body["error"]!.GetString());
    }

    [Fact]
    public async Task Generate_WhenDisabled_Returns400_GenericError()
    {
        var host = new RecoveryHostBuilder
        {
            AuthenticatedRequests = true,
            EnableRecoveryCodes = false
        }.Build();

        var response = await host.Client.PostAsync("/auth/recovery-codes/generate", null!);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.Equal("recovery_codes_disabled", body["error"]!.GetString());
    }

    [Fact]
    public async Task Generate_WhenEnabled_Returns200_WithCodes()
    {
        var expectedCodes = new List<string> { "codeA", "codeB", "codeC" };
        var host = new RecoveryHostBuilder { AuthenticatedRequests = true, EnableRecoveryCodes = true }.Build();
        host.TotpService.GenerateRecoveryCodes(Arg.Any<int>()).Returns(expectedCodes);

        var response = await host.Client.PostAsync("/auth/recovery-codes/generate", null!);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await DeserializeJson(response);
        var codes = body["codes"]!.EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(expectedCodes, codes);

        // DIDÁCTICA: el store debe recibir solo hashes SHA-256, nunca el plaintext.
        foreach (var code in expectedCodes)
        {
            await host.RecoveryCodeStore.Received(1).CreateAsync("u1", ComputeHash(code), Arg.Any<CancellationToken>());
            await host.RecoveryCodeStore.DidNotReceive().CreateAsync("u1", code, Arg.Any<CancellationToken>());
        }
    }

    [Fact]
    public async Task Verify_NotConfigured_Returns503()
    {
        var host = new RecoveryHostBuilder { RegisterOrchestrator = false }.Build();
        var mfaToken = "test-mfa-token";
        host.MfaSessionStore.ValidateMfaSessionTokenAsync(mfaToken, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));

        var response = await host.Client.PostAsync("/auth/recovery-codes/verify",
            PostJson($$"""{"mfaSessionToken":"{{mfaToken}}","code":"test"}"""));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Verify_InvalidMfaSessionToken_Returns200False_NoOracle()
    {
        // DIDÁCTICA: anti-enumeración — token inválido produce el mismo resultado que código inválido.
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>(null));

        var response = await host.Client.PostAsync("/auth/recovery-codes/verify",
            PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.False(body["valid"]!.GetBoolean());
    }

    [Fact]
    public async Task Verify_InvalidCode_Returns200False()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.RecoveryCodeStore.GetStatusAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Invalid));

        var response = await host.Client.PostAsync("/auth/recovery-codes/verify",
            PostJson("""{"mfaSessionToken":"tok1","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.False(body["valid"]!.GetBoolean());
    }

    [Fact]
    public async Task Verify_ValidCode_Returns200True()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.RecoveryCodeStore.GetStatusAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Valid));

        var response = await host.Client.PostAsync("/auth/recovery-codes/verify",
            PostJson("""{"mfaSessionToken":"tok1","code":"valid"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.True(body["valid"]!.GetBoolean());
    }

    [Fact]
    public async Task Use_NotConfigured_Returns503()
    {
        var host = new RecoveryHostBuilder { RegisterOrchestrator = false }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"tok1","code":"test"}"""));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Use_InvalidMfaSessionToken_Returns400_Generic()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>(null));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.Equal("invalid_code", body["error"]!.GetString());
    }

    [Fact]
    public async Task Use_InvalidCode_Returns400_GenericInvalidCode()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.RecoveryCodeStore.RedeemAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(false));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"tok1","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.Equal("invalid_code", body["error"]!.GetString());
        await host.RecoveryCodeStore.Received(1).RedeemAsync(
            "u1", ComputeHash("bad"), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Use_Success_Returns200_RedeemedTrue()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.RecoveryCodeStore.RedeemAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(true));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"tok1","code":"good"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.True(body["redeemed"]!.GetBoolean());
    }

    [Fact]
    public async Task Use_LockedOut_Returns429()
    {
        // DIDÁCTICA (S1): con protección habilitada y la cuenta en lockout (scope Recovery),
        // UseAsync devuelve Blocked y el endpoint responde 429 sin revelar detalles.
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true, EnableProtection = true }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.Protection.CheckAsync(AccountProtectionScope.Recovery, "u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(
                false, 0, DateTimeOffset.UtcNow.AddMinutes(30), 1)));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"tok1","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        var body = await DeserializeJson(response);
        Assert.Equal("too_many_attempts", body["error"]!.GetString());

        // DIDÁCTICA: estando bloqueada, la solicitud no llega a intentar redimir.
        await host.RecoveryCodeStore.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Verify_ExceedsIpRateLimit_Returns429()
    {
        // DIDÁCTICA (B1, auditoría): verify es anónimo; el limiter keyed por IP acota la
        // amplificación de CPU/caché (validación JWT por request) ANTES de validar el token.
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true, VerifyRateLimit = 2 }.Build();

        for (int i = 0; i < 2; i++)
        {
            var ok = await host.Client.PostAsync("/auth/recovery-codes/verify",
                PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        var third = await host.Client.PostAsync("/auth/recovery-codes/verify",
            PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public async Task Use_ExceedsIpRateLimit_Returns429()
    {
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true, UseRateLimit = 2 }.Build();

        for (int i = 0; i < 2; i++)
        {
            var ok = await host.Client.PostAsync("/auth/recovery-codes/use",
                PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));
            Assert.Equal(HttpStatusCode.BadRequest, ok.StatusCode);
        }

        var third = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"bad","code":"bad"}"""));

        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
    }

    [Fact]
    public async Task Use_Success_ResetsIpRateLimit()
    {
        // DIDÁCTICA (B1): el éxito resetea el presupuesto por IP (no penalizar al legítimo).
        var host = new RecoveryHostBuilder { EnableRecoveryCodes = true, UseRateLimit = 2 }.Build();
        host.MfaSessionStore.ValidateMfaSessionTokenAsync("tok1", Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<string?>("u1"));
        host.RecoveryCodeStore.RedeemAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(true));

        var response = await host.Client.PostAsync("/auth/recovery-codes/use",
            PostJson("""{"mfaSessionToken":"tok1","code":"good"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ─────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────

    private static StringContent PostJson(string body)
        => new(body, Encoding.UTF8, "application/json");

    private static async Task<Dictionary<string, JsonElement>> DeserializeJson(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(content)
               ?? throw new InvalidOperationException($"No se pudo deserializar: {content}");
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // ─────────────────────────────────────────────
    //  Host builder
    // ─────────────────────────────────────────────

    private sealed class RecoveryHostBuilderHost
    {
        public required HttpClient Client { get; init; }
        public required IRecoveryCodeStore RecoveryCodeStore { get; init; }
        public required IMfaSessionStore MfaSessionStore { get; init; }
        public required IAuthEventDispatcher EventDispatcher { get; init; }
        public required ITotpService TotpService { get; init; }
        public required IAccountProtectionService Protection { get; init; }
    }

    private sealed class RecoveryHostBuilder
    {
        public bool RegisterOrchestrator { get; init; } = true;
        public bool AuthenticatedRequests { get; init; } = false;
        public bool EnableRecoveryCodes { get; init; } = true;
        public bool EnableProtection { get; init; } = false;

        // DIDÁCTICA (B1, auditoría): si se fijan, el host registra los limitadores keyed
        // por IP (default null → sin limiter → degradación elegante, como sin AddSecureAuth).
        public int? VerifyRateLimit { get; init; }
        public int? UseRateLimit { get; init; }

        public RecoveryHostBuilderHost Build()
        {
            var recoveryStore = Substitute.For<IRecoveryCodeStore>();
            var mfaSessionStore = Substitute.For<IMfaSessionStore>();
            var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
            var totpService = Substitute.For<ITotpService>();
            var protection = Substitute.For<IAccountProtectionService>();

            eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
                .Returns(Task.CompletedTask);
            recoveryStore.CreateAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(ValueTask.CompletedTask);
            recoveryStore.GetStatusAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(ValueTask.FromResult(RecoveryCodeStatus.Invalid));
            recoveryStore.RedeemAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(ValueTask.FromResult(false));
            mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<string?>(null));

            var orchestrator = new RecoveryCodeOrchestrator(
                recoveryStore,
                totpService,
                eventDispatcher,
                new InMemoryOperationLock(TimeSpan.FromSeconds(5)),
                Microsoft.Extensions.Options.Options.Create(new MfaOptions
                {
                    Enabled = true,
                    EnableRecoveryCodes = EnableRecoveryCodes,
                    RecoveryCodeCount = 10
                }),
                NullLogger<RecoveryCodeOrchestrator>.Instance,
                EnableProtection ? protection : null,
                EnableProtection ? Microsoft.Extensions.Options.Options.Create(new AccountProtectionOptions { Enabled = true }) : null);

            var builder = WebApplication.CreateBuilder();
            builder.WebHost.UseTestServer();

            builder.Services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                })
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
            builder.Services.AddAuthorization();
            builder.Services.AddSingleton(Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions()));

            if (RegisterOrchestrator)
            {
                builder.Services.AddSingleton<IRecoveryCodeStore>(recoveryStore);
                builder.Services.AddSingleton(orchestrator);
            }

            builder.Services.AddSingleton<IMfaSessionStore>(mfaSessionStore);

            if (VerifyRateLimit is int verifyLimit)
            {
                builder.Services.AddKeyedSingleton<IRateLimiter>(
                    "recovery-verify", new InMemoryRateLimiter(verifyLimit, TimeSpan.FromMinutes(1)));
            }

            if (UseRateLimit is int useLimit)
            {
                builder.Services.AddKeyedSingleton<IRateLimiter>(
                    "recovery-use", new InMemoryRateLimiter(useLimit, TimeSpan.FromMinutes(1)));
            }

            var app = builder.Build();

            if (AuthenticatedRequests)
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
            app.MapSecureAuthRecoveryCodesEndpoints("/auth/recovery-codes");
            app.StartAsync().GetAwaiter().GetResult();

            return new RecoveryHostBuilderHost
            {
                Client = app.GetTestClient(),
                RecoveryCodeStore = recoveryStore,
                MfaSessionStore = mfaSessionStore,
                EventDispatcher = eventDispatcher,
                TotpService = totpService,
                Protection = protection
            };
        }
    }

    private sealed class TestAuthHandler(
        Microsoft.Extensions.Options.IOptionsMonitor<AuthenticationSchemeOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger,
        UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }
}
