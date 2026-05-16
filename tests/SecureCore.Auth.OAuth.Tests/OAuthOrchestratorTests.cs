using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;
using SecureCore.Auth.OAuth.Services;

namespace SecureCore.Auth.OAuth.Tests;

public class OAuthOrchestratorTests
{
    private readonly IUserStore _userStore;
    private readonly IExternalTokenStore _externalTokenStore;
    private readonly ISessionStore _sessionStore;
    private readonly ITokenService _tokenService;
    private readonly IAuthEventDispatcher _eventDispatcher;
    private readonly IServiceProvider _serviceProvider;
    private readonly IOptions<SecureAuthOptions> _options;
    private readonly OAuthOrchestrator _orchestrator;
    private readonly IOAuthProviderValidator _mockValidator;
    private readonly UserIdentity _existingUser;

    public OAuthOrchestratorTests()
    {
        _userStore = Substitute.For<IUserStore>();
        _externalTokenStore = Substitute.For<IExternalTokenStore>();
        _sessionStore = Substitute.For<ISessionStore>();
        _tokenService = Substitute.For<ITokenService>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
        _serviceProvider = Substitute.For<IServiceProvider>();

        _options = Options.Create(new SecureAuthOptions
        {
            MaxFailedAttempts = 5,
            LockoutDurations = [TimeSpan.FromMinutes(1)],
            AccessTokenLifetime = TimeSpan.FromMinutes(15),
            RefreshTokenLifetime = TimeSpan.FromDays(7)
        });

        var lockoutManager = new LockoutManager(
            _userStore, _options, NullLogger<LockoutManager>.Instance);

        _mockValidator = Substitute.For<IOAuthProviderValidator>();
        _mockValidator.ProviderName.Returns("MockProvider");

        _orchestrator = new OAuthOrchestrator(
            _userStore,
            _externalTokenStore,
            _sessionStore,
            _tokenService,
            lockoutManager,
            _eventDispatcher,
            _serviceProvider,
            _options,
            [_mockValidator],
            NullLogger<OAuthOrchestrator>.Instance);

        _existingUser = new UserIdentity
        {
            Id = "user-1",
            Email = "test@example.com",
            SecurityStamp = "stamp-1"
        };
    }

    [Fact]
    public async Task SignInOrRegisterAsync_UnconfiguredProvider_ReturnsProviderNotConfigured()
    {
        var result = await _orchestrator.SignInOrRegisterAsync(
            "NonexistentProvider",
            new OAuthValidationRequest { IdToken = "token" },
            new OAuthSignInOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_provider_not_configured", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_InvalidRequest_ReturnsFailure()
    {
        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest(),
            new OAuthSignInOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_invalid_request", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_IdTokenValidationFails_ReturnsFailure()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(OAuthIdentityResult.Failure("bad_token", "Invalid signature"));

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "invalid-token" },
            new OAuthSignInOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_validation_failed", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_UserNotFoundAndImplicitDisabled_ReturnsUserNotFound()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "test@example.com"
            });
        _userStore.FindByExternalProviderAsync(default!, default!, default)
            .ReturnsForAnyArgs((UserIdentity?)null);

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "valid-token" },
            new OAuthSignInOptions { AllowImplicitRegistration = false });

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_user_not_found", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_UserLockedOut_ReturnsLockedOut()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "test@example.com"
            });
        _userStore.FindByExternalProviderAsync(default!, default!, default)
            .ReturnsForAnyArgs(_existingUser with
            {
                LockoutEnd = DateTimeOffset.UtcNow.AddHours(1)
            });

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "valid-token" },
            new OAuthSignInOptions());

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_account_locked", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_ExistingUser_Success()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "test@example.com"
            });
        _userStore.FindByExternalProviderAsync("MockProvider", "ext-1", default)
            .ReturnsForAnyArgs(_existingUser);

        var tokens = new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1));
        _tokenService.GenerateTokenPairAsync(_existingUser, default)
            .ReturnsForAnyArgs(tokens);

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "valid-token" },
            new OAuthSignInOptions());

        Assert.True(result.Succeeded);
        Assert.Equal(_existingUser.Id, result.UserId);
        Assert.Same(tokens, result.Tokens);
        Assert.False(result.IsNewUser);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_ImplicitRegistration_CreatesUser()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "newuser@example.com"
            });
        _userStore.FindByExternalProviderAsync(default!, default!, default)
            .ReturnsForAnyArgs((UserIdentity?)null);

        var factory = Substitute.For<IExternalUserFactory>();
        var newUser = new UserIdentity
        {
            Id = "new-user-1",
            Email = "newuser@example.com",
            SecurityStamp = "stamp-new"
        };
        factory.CreateFromOAuthAsync(default!, default!, default)
            .ReturnsForAnyArgs(newUser);
        _serviceProvider.GetService(typeof(IExternalUserFactory))
            .Returns(factory);

        var tokens = new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1));
        _tokenService.GenerateTokenPairAsync(newUser, default)
            .ReturnsForAnyArgs(tokens);

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "valid-token" },
            new OAuthSignInOptions { AllowImplicitRegistration = true });

        Assert.True(result.Succeeded);
        Assert.Equal("new-user-1", result.UserId);
        Assert.True(result.IsNewUser);
        await factory.Received(1).CreateFromOAuthAsync(
            Arg.Is<OAuthIdentityResult>(r => r.ProviderKey == "ext-1"),
            "MockProvider",
            default);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_ImplicitRegistrationWithoutFactory_ReturnsFailure()
    {
        _mockValidator.ValidateIdTokenAsync(default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "newuser@example.com"
            });
        _userStore.FindByExternalProviderAsync(default!, default!, default)
            .ReturnsForAnyArgs((UserIdentity?)null);
        _serviceProvider.GetService(typeof(IExternalUserFactory))
            .Returns(null);

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest { IdToken = "valid-token" },
            new OAuthSignInOptions { AllowImplicitRegistration = true });

        Assert.False(result.Succeeded);
        Assert.Equal("oauth_factory_not_registered", result.ErrorCode);
    }

    [Fact]
    public async Task SignInOrRegisterAsync_CodeFlow_Success()
    {
        _mockValidator.ExchangeCodeAsync(default!, default!, default, default)
            .ReturnsForAnyArgs(new OAuthIdentityResult
            {
                Succeeded = true,
                ProviderKey = "ext-1",
                Email = "test@example.com"
            });
        _userStore.FindByExternalProviderAsync("MockProvider", "ext-1", default)
            .ReturnsForAnyArgs(_existingUser);

        var tokens = new TokenResponse("access", "refresh", DateTimeOffset.UtcNow.AddHours(1));
        _tokenService.GenerateTokenPairAsync(_existingUser, default)
            .ReturnsForAnyArgs(tokens);

        var result = await _orchestrator.SignInOrRegisterAsync(
            "MockProvider",
            new OAuthValidationRequest
            {
                Code = "auth-code-123",
                RedirectUri = "https://app.com/callback",
                Nonce = "nonce-123"
            },
            new OAuthSignInOptions());

        Assert.True(result.Succeeded);
        Assert.Equal(_existingUser.Id, result.UserId);
    }
}
