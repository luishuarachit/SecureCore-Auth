using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.AspNetCore;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests para SecurityStampMiddleware — validación de JWT en el pipeline HTTP.
/// </summary>
public class SecurityStampMiddlewareTests
{
    private readonly Core.Services.SecurityStampValidator _stampValidator;

    public SecurityStampMiddlewareTests()
    {
        var userStore = Substitute.For<IUserStore>();
        var cache = Substitute.For<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
        var options = Microsoft.Extensions.Options.Options.Create(
            new Abstractions.Options.SecureAuthOptions
            {
                SecurityStampCacheDuration = TimeSpan.FromMinutes(5)
            });

        _stampValidator = new Core.Services.SecurityStampValidator(
            userStore, cache, options, NullLogger<Core.Services.SecurityStampValidator>.Instance);
    }

    [Fact]
    public async Task InvokeAsync_UnauthenticatedRequest_CallsNext()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var middleware = new SecurityStampMiddleware(
            next, _stampValidator, NullLogger<SecurityStampMiddleware>.Instance);

        // Act
        await middleware.InvokeAsync(context);

        // Assert — request no autenticado pasa sin validación
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_AuthenticatedWithoutSsvClaim_CallsNext()
    {
        // Arrange — usuario autenticado pero sin claim "ssv"
        var context = new DefaultHttpContext();
        var identity = new ClaimsIdentity([
            new Claim("sub", "u1"),
            new Claim("email", "test@ex.com")
        ], "Bearer");
        context.User = new ClaimsPrincipal(identity);

        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var middleware = new SecurityStampMiddleware(
            next, _stampValidator, NullLogger<SecurityStampMiddleware>.Instance);

        // Act
        await middleware.InvokeAsync(context);

        // Assert — sin claim ssv, pasa sin validación
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_AuthenticatedWithSsvClaim_InvalidStamp_Returns401()
    {
        // Arrange — usuario autenticado con ssv inválido
        var userStore = Substitute.For<IUserStore>();
        var cache = Substitute.For<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();

        // Caché retorna un stamp diferente al del token
        cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(System.Text.Encoding.UTF8.GetBytes("current-stamp"));

        var options = Microsoft.Extensions.Options.Options.Create(
            new Abstractions.Options.SecureAuthOptions
            {
                SecurityStampCacheDuration = TimeSpan.FromMinutes(5)
            });

        var validator = new Core.Services.SecurityStampValidator(
            userStore, cache, options, NullLogger<Core.Services.SecurityStampValidator>.Instance);

        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream(); // necesario para WriteAsJsonAsync
        var identity = new ClaimsIdentity([
            new Claim("sub", "u1"),
            new Claim("ssv", "old-stamp")
        ], "Bearer");
        context.User = new ClaimsPrincipal(identity);

        var nextCalled = false;
        RequestDelegate next = _ => { nextCalled = true; return Task.CompletedTask; };

        var middleware = new SecurityStampMiddleware(
            next, validator, NullLogger<SecurityStampMiddleware>.Instance);

        // Act
        await middleware.InvokeAsync(context);

        // Assert — stamp inválido, retorna 401
        Assert.False(nextCalled);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }
}
