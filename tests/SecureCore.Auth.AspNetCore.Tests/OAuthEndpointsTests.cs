using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;
using SecureCore.Auth.OAuth.Abstractions;
using SecureCore.Auth.OAuth.Services;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests para OAuthEndpoints — el redirect_uri del proveedor debe ser el callback
/// de la API (no la URL del SPA) y el destino post-login debe validarse (open redirect).
/// </summary>
public class OAuthEndpointsTests
{
    private const string ApiCallback = "http://localhost/auth/oauth/Google/callback";

    private readonly FakeOAuthStateStore _stateStore = new();
    private readonly IOAuthProviderValidator _validator = Substitute.For<IOAuthProviderValidator>();
    private string? _capturedAuthRedirectUri;
    private string? _capturedState;
    private string? _capturedExchangeRedirectUri;

    // ─────────────────────────────────────────────
    //  BuildCallbackUrl (unit)
    // ─────────────────────────────────────────────

    [Fact]
    public void BuildCallbackUrl_DerivedFromRequest_UsesSchemeHostAndPrefix()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.textea.me");

        var url = OAuthEndpoints.BuildCallbackUrl("/auth/oauth", "Google", new OAuthSignInOptions(), context);

        Assert.Equal("https://api.textea.me/auth/oauth/Google/callback", url);
    }

    [Fact]
    public void BuildCallbackUrl_WithPublicBaseUrl_OverridesRequest()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "http";
        context.Request.Host = new HostString("localhost");

        var url = OAuthEndpoints.BuildCallbackUrl("/auth/oauth", "Google",
            new OAuthSignInOptions { PublicBaseUrl = "https://api.textea.me" }, context);

        Assert.Equal("https://api.textea.me/auth/oauth/Google/callback", url);
    }

    [Fact]
    public void BuildCallbackUrl_WithCustomPrefix_UsesIt()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("api.textea.me");

        var url = OAuthEndpoints.BuildCallbackUrl("/api/auth/oauth", "Microsoft",
            new OAuthSignInOptions { PublicBaseUrl = "https://api.textea.me" }, context);

        Assert.Equal("https://api.textea.me/api/auth/oauth/Microsoft/callback", url);
    }

    [Fact]
    public void BuildCallbackUrl_WithWwwHost_NormalizesToBaseDomain()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("www.api.textea.me");

        var url = OAuthEndpoints.BuildCallbackUrl("/auth/oauth", "Google", new OAuthSignInOptions(), context);

        Assert.Equal("https://api.textea.me/auth/oauth/Google/callback", url);
    }

    // ─────────────────────────────────────────────
    //  IsSafePostLoginTarget (unit)
    // ─────────────────────────────────────────────

    [Fact]
    public void IsSafePostLoginTarget_HttpUrl_Rejected()
    {
        var options = new OAuthSignInOptions { AllowedPostLoginHosts = ["app.textea.me"] };
        Assert.False(OAuthEndpoints.IsSafePostLoginTarget("http://app.textea.me/home", options));
    }

    [Fact]
    public void IsSafePostLoginTarget_DisallowedHost_Rejected()
    {
        var options = new OAuthSignInOptions { AllowedPostLoginHosts = ["app.textea.me"] };
        Assert.False(OAuthEndpoints.IsSafePostLoginTarget("https://evil.com/home", options));
    }

    [Fact]
    public void IsSafePostLoginTarget_AllowedHost_Accepted()
    {
        var options = new OAuthSignInOptions { AllowedPostLoginHosts = ["app.textea.me"] };
        Assert.True(OAuthEndpoints.IsSafePostLoginTarget("https://app.textea.me/dashboard", options));
    }

    [Fact]
    public void IsSafePostLoginTarget_PostLoginRedirectUrlHost_Accepted()
    {
        var options = new OAuthSignInOptions { PostLoginRedirectUrl = "https://app.textea.me" };
        Assert.True(OAuthEndpoints.IsSafePostLoginTarget("https://app.textea.me/deep-link", options));
    }

    [Fact]
    public void IsSafePostLoginTarget_NullOrEmpty_Rejected()
    {
        var options = new OAuthSignInOptions { AllowedPostLoginHosts = ["app.textea.me"] };
        Assert.False(OAuthEndpoints.IsSafePostLoginTarget(null, options));
        Assert.False(OAuthEndpoints.IsSafePostLoginTarget("", options));
    }

    // ─────────────────────────────────────────────
    //  Endpoints (integration via TestServer)
    // ─────────────────────────────────────────────

    [Fact]
    public async Task Authorize_UsesApiCallbackAsRedirectUri_AndStoresSpaTarget()
    {
        var client = await StartAsync(o => o.AllowedPostLoginHosts = ["app.textea.me"]);

        var response = await client.GetAsync(
            "/auth/oauth/Google/authorize?redirectUri=" + Uri.EscapeDataString("https://app.textea.me/home"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(ApiCallback, _capturedAuthRedirectUri);
        Assert.Single(_stateStore.SavedEntries);
        Assert.Equal(ApiCallback, _stateStore.SavedEntries[0].CallbackUri);
        Assert.Equal("https://app.textea.me/home", _stateStore.SavedEntries[0].RedirectUri);
    }

    [Fact]
    public async Task Authorize_WithPublicBaseUrl_UsesConfiguredCallback()
    {
        var client = await StartAsync(o =>
        {
            o.PublicBaseUrl = "https://api.textea.me";
            o.AllowedPostLoginHosts = ["app.textea.me"];
        });

        var response = await client.GetAsync(
            "/auth/oauth/Google/authorize?redirectUri=" + Uri.EscapeDataString("https://app.textea.me/home"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("https://api.textea.me/auth/oauth/Google/callback", _capturedAuthRedirectUri);
    }

    [Fact]
    public async Task Authorize_UnsafeRedirectUri_Returns400()
    {
        var client = await StartAsync(o => o.AllowedPostLoginHosts = ["app.textea.me"]);

        var response = await client.GetAsync(
            "/auth/oauth/Google/authorize?redirectUri=" + Uri.EscapeDataString("http://evil.com/cb"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_stateStore.SavedEntries);
    }

    [Fact]
    public async Task Authorize_WithoutRedirectUri_FallsBackToPostLoginRedirectUrl()
    {
        var client = await StartAsync(o =>
        {
            o.PostLoginRedirectUrl = "https://app.textea.me/dashboard";
            o.AllowedPostLoginHosts = ["app.textea.me"];
        });

        var response = await client.GetAsync("/auth/oauth/Google/authorize");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("https://app.textea.me/dashboard", _stateStore.SavedEntries[0].RedirectUri);
        Assert.Equal(ApiCallback, _stateStore.SavedEntries[0].CallbackUri);
    }

    [Fact]
    public async Task Callback_UsesStoredCallbackUriForTokenExchange_NotSpaUrl()
    {
        var client = await StartAsync(o => o.AllowedPostLoginHosts = ["app.textea.me"]);

        await client.GetAsync(
            "/auth/oauth/Google/authorize?redirectUri=" + Uri.EscapeDataString("https://app.textea.me/home"));

        var response = await client.GetAsync(
            $"/auth/oauth/Google/callback?code=auth-code-123&state={Uri.EscapeDataString(_capturedState!)}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // EL punto del bug: el exchange usa el callback de la API, nunca la URL del SPA.
        Assert.Equal(ApiCallback, _capturedExchangeRedirectUri);
    }

    // ─────────────────────────────────────────────
    //  Test host
    // ─────────────────────────────────────────────

    private async Task<HttpClient> StartAsync(Action<OAuthSignInOptions>? configureOptions = null)
    {
        var userStore = Substitute.For<IUserStore>();
        userStore.FindByExternalProviderAsync("Google", "ext-1", Arg.Any<CancellationToken>())
            .Returns(new UserIdentity
            {
                Id = "u1",
                Email = "test@example.com",
                SecurityStamp = "stamp"
            });

        var sessionStore = Substitute.For<ISessionStore>();
        sessionStore.CreateAsync(Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var tokenService = Substitute.For<ITokenService>();
        tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1)));
        tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var authOptions = Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) });
        var lockoutManager = new LockoutManager(userStore, authOptions, NullLogger<LockoutManager>.Instance);

        _validator.ProviderName.Returns("Google");
        _validator.BuildAuthorizationUrl(Arg.Any<string>(), Arg.Any<string[]>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(ci =>
            {
                _capturedAuthRedirectUri = ci.ArgAt<string>(0);
                _capturedState = ci.ArgAt<string>(2);
                return new OAuthAuthorizationUrl(
                    "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=" +
                    Uri.EscapeDataString(ci.ArgAt<string>(0)) +
                    "&state=" + Uri.EscapeDataString(ci.ArgAt<string>(2)));
            });
        _validator.ExchangeCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                _capturedExchangeRedirectUri = ci.ArgAt<string>(1);
                return new OAuthIdentityResult
                {
                    Succeeded = true,
                    ProviderKey = "ext-1",
                    Email = "test@example.com"
                };
            });

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<IOAuthStateStore>(_stateStore);
        builder.Services.AddSingleton<IOAuthProviderValidator>(_validator);
        builder.Services.AddSingleton<IExternalTokenStore>(Substitute.For<IExternalTokenStore>());
        builder.Services.AddScoped<OAuthOrchestrator>(sp => new OAuthOrchestrator(
            userStore,
            null,
            sessionStore,
            tokenService,
            lockoutManager,
            eventDispatcher,
            sp,
            authOptions,
            new[] { _validator },
            NullLogger<OAuthOrchestrator>.Instance));
        builder.Services.Configure<OAuthSignInOptions>(o => configureOptions?.Invoke(o));

        var app = builder.Build();
        app.MapSecureOAuthEndpoints();
        await app.StartAsync();

        _app = app;
        return app.GetTestClient();
    }

    private WebApplication? _app;

    private sealed class FakeOAuthStateStore : IOAuthStateStore
    {
        private readonly Dictionary<string, (OAuthStateEntry Entry, DateTimeOffset Expires)> _entries = new();

        public List<OAuthStateEntry> SavedEntries { get; } = new();

        public Task SaveAsync(string state, OAuthStateEntry entry, TimeSpan ttl, CancellationToken cancellationToken = default)
        {
            _entries[state] = (entry, DateTimeOffset.UtcNow + ttl);
            SavedEntries.Add(entry);
            return Task.CompletedTask;
        }

        public ValueTask<OAuthStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default)
        {
            if (_entries.Remove(state, out var item) && item.Expires > DateTimeOffset.UtcNow)
            {
                return ValueTask.FromResult<OAuthStateEntry?>(item.Entry);
            }

            return ValueTask.FromResult<OAuthStateEntry?>(null);
        }
    }
}
