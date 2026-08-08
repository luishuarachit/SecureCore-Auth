using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.AspNetCore.Tests;

public class AuthEventContextEnricherTests
{
    [Fact]
    public async Task Enriches_WithIpUserAgentAndPath()
    {
        var inner = Substitute.For<IAuthEventDispatcher>();
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.45") }
        };
        httpContext.Request.Path = "/auth/login";
        httpContext.Request.Headers["User-Agent"] = "TestAgent/1.0";
        httpContext.Request.Headers["X-Forwarded-For"] = "10.0.0.1";

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        var enricher = new AuthEventContextEnricher(accessor, inner);

        var evt = new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = "u1"
        };

        await enricher.DispatchAsync(evt);

        await inner.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e =>
                e.Metadata["ip"] == "203.0.113.45" &&
                e.Metadata["path"] == "/auth/login" &&
                e.Metadata["ua"] == "TestAgent/1.0" &&
                e.Metadata["xff"] == "10.0.0.1"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task WithoutHttpContext_DoesNotEnrich_DoesNotThrow()
    {
        var inner = Substitute.For<IAuthEventDispatcher>();
        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns((HttpContext?)null);

        var enricher = new AuthEventContextEnricher(accessor, inner);

        var evt = new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = "u1"
        };

        await enricher.DispatchAsync(evt);

        await inner.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.Metadata.Count == evt.Metadata.Count),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AddsRoles_WhenUserIsAuthenticated()
    {
        var inner = Substitute.For<IAuthEventDispatcher>();
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = System.Net.IPAddress.Loopback }
        };
        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim("role", "admin"));
        identity.AddClaim(new Claim("role", "user"));
        httpContext.User = new ClaimsPrincipal(identity);
        httpContext.Request.Path = "/auth/login";

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        var enricher = new AuthEventContextEnricher(accessor, inner);

        var evt = new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = "u1"
        };

        await enricher.DispatchAsync(evt);

        await inner.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.Metadata["roles"] == "admin,user"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task NoRoles_WhenUserNotAuthenticated()
    {
        var inner = Substitute.For<IAuthEventDispatcher>();
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = System.Net.IPAddress.Loopback }
        };
        httpContext.Request.Path = "/auth/login";

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        var enricher = new AuthEventContextEnricher(accessor, inner);

        var evt = new AuthEvent
        {
            EventType = AuthEventType.AnonymousLoginFailed
        };

        await enricher.DispatchAsync(evt);

        await inner.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => !e.Metadata.ContainsKey("roles")),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public void AnonymousLoginFailed_AllowsNullUserId()
    {
        var evt = new AuthEvent
        {
            EventType = AuthEventType.AnonymousLoginFailed
        };

        Assert.Null(evt.UserId);
    }

    [Fact]
    public void RateLimitExceeded_AllowsNullUserId()
    {
        var evt = new AuthEvent
        {
            EventType = AuthEventType.RateLimitExceeded
        };

        Assert.Null(evt.UserId);
    }

    [Fact]
    public async Task Enricher_PreservesOriginalMetadata()
    {
        var inner = Substitute.For<IAuthEventDispatcher>();
        var httpContext = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = System.Net.IPAddress.Loopback }
        };
        httpContext.Request.Path = "/auth/login";

        var accessor = Substitute.For<IHttpContextAccessor>();
        accessor.HttpContext.Returns(httpContext);

        var enricher = new AuthEventContextEnricher(accessor, inner);

        var evt = new AuthEvent
        {
            EventType = AuthEventType.LoginFailed,
            UserId = "u1",
            Metadata = new Dictionary<string, string> { ["reason"] = "invalid_password" }
        };

        await enricher.DispatchAsync(evt);

        await inner.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.Metadata["reason"] == "invalid_password"),
            Arg.Any<CancellationToken>());
    }
}
