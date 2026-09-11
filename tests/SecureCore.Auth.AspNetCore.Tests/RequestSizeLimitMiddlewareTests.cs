using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests de <see cref="RequestSizeLimitMiddleware"/> — asignación de
/// IHttpMaxRequestBodySizeFeature antes del binding (protección real A-10).
/// </summary>
public class RequestSizeLimitMiddlewareTests
{
    [Fact]
    public async Task AuthPath_AppliesConfiguredMaxRequestBodySize_ToFeature()
    {
        var feature = new TestMaxRequestBodySizeFeature();
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/auth/login";

        var middleware = CreateMiddleware(new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        // La barrera física queda activa: Kestrel rechazará con 413 cualquier cuerpo mayor
        Assert.Equal(2048, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task AuthGroupPaths_AreAllCovered()
    {
        var feature = new TestMaxRequestBodySizeFeature();
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/auth/forgot-password";

        var middleware = CreateMiddleware(new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        Assert.Equal(2048, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task WebAuthnPaths_GetDedicatedLargerCap()
    {
        // DIDÁCTICA (A-29): los payloads FIDO2 superan el límite de credenciales (2048 B) pero
        // NO quedan ilimitados: se les asigna el tope propio MaxWebAuthnRequestBodySize (64 KB).
        var feature = new TestMaxRequestBodySizeFeature { MaxRequestBodySize = 30_000_000 };
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/auth/webauthn/login/complete";

        var middleware = CreateMiddleware(new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        Assert.Equal(65536, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task NonAuthPath_DoesNotTouchMaxRequestBodySize()
    {
        var feature = new TestMaxRequestBodySizeFeature { MaxRequestBodySize = 30_000_000 };
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/api/other";

        var middleware = CreateMiddleware(new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        Assert.Equal(30_000_000, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task CustomPrefix_IsHonored()
    {
        var feature = new TestMaxRequestBodySizeFeature();
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/secure/login";

        var middleware = CreateMiddleware(new PathString("/secure"));
        await middleware.InvokeAsync(httpContext);

        Assert.Equal(2048, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task ReadOnlyFeature_IsSkipped_WithoutThrowing()
    {
        var feature = new TestMaxRequestBodySizeFeature { IsReadOnly = true, MaxRequestBodySize = 999 };
        var httpContext = new DefaultHttpContext();
        httpContext.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);
        httpContext.Request.Path = "/auth/login";

        var middleware = CreateMiddleware(new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        // No se modifica ni se lanza cuando la feature ya es read-only
        Assert.Equal(999, feature.MaxRequestBodySize);
    }

    [Fact]
    public async Task NoFeature_ProceedsToNextWithoutThrowing()
    {
        var called = false;
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/auth/login";

        var middleware = new RequestSizeLimitMiddleware(
            _ => { called = true; return Task.CompletedTask; },
            Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions()),
            new PathString("/auth"));
        await middleware.InvokeAsync(httpContext);

        Assert.True(called);
    }

    private static RequestSizeLimitMiddleware CreateMiddleware(PathString prefix)
    {
        return new RequestSizeLimitMiddleware(
            _ => Task.CompletedTask,
            Microsoft.Extensions.Options.Options.Create(new SecureAuthOptions()),
            prefix);
    }

    private sealed class TestMaxRequestBodySizeFeature : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly { get; set; }
        public long? MaxRequestBodySize { get; set; }
    }
}
