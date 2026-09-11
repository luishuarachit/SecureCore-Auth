using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.AspNetCore.Extensions;
using SecureCore.Auth.OAuth.Abstractions;

namespace SecureCore.Auth.AspNetCore.Tests;

/// <summary>
/// Tests de DistributedCacheOAuthStateStore — consumo single-use del state OAuth (A-06/S2).
/// </summary>
public class DistributedCacheOAuthStateStoreTests
{
    // El state de OAuth debe ser base64url con longitud [32, 64]; 43 'a' es válido.
    private const string ValidState = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    private static OAuthStateEntry CreateEntry() => new(
        Nonce: "nonce-1",
        Provider: "google",
        RedirectUri: "https://app.example/callback",
        CreatedAt: DateTimeOffset.UtcNow,
        CallbackUri: null);

    private static DistributedCacheOAuthStateStore CreateSut(
        out ISingleUseTokenStore store,
        IDistributedCache? cache = null)
    {
        store = Substitute.For<ISingleUseTokenStore>();
        return new DistributedCacheOAuthStateStore(
            cache ?? Substitute.For<IDistributedCache>(),
            logger: null,
            singleUseTokenStore: store);
    }

    [Fact]
    public async Task ConsumeAsync_DelegatesToSingleUseStore_AndReturnsEntry()
    {
        // Arrange
        var sut = CreateSut(out var store);
        var entry = CreateEntry();
        store.GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(JsonSerializer.Serialize(entry)));

        // Act
        var result = await sut.ConsumeAsync(ValidState);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(entry.Nonce, result!.Nonce);
        Assert.Equal(entry.Provider, result.Provider);
        Assert.Equal(entry.RedirectUri, result.RedirectUri);

        await store.Received(1).GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ConsumeAsync_DoubleConsume_SecondReturnsNull()
    {
        // Arrange: el store consume la key en la primera llamada → null en la segunda.
        var sut = CreateSut(out var store);
        var entry = CreateEntry();
        store.GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(JsonSerializer.Serialize(entry)),
                     ValueTask.FromResult<string?>((string?)null));

        // Act
        var first = await sut.ConsumeAsync(ValidState);
        var second = await sut.ConsumeAsync(ValidState);

        // Assert
        Assert.NotNull(first);
        Assert.Null(second);
        await store.Received(2).GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ConsumeAsync_StoreMissing_ReturnsNull()
    {
        // Arrange
        var sut = CreateSut(out var store);
        store.GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>((string?)null));

        // Act
        var result = await sut.ConsumeAsync(ValidState);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ConsumeAsync_WithoutSingleUseStore_UsesLegacyGetRemovePath()
    {
        // Arrange: sin ISingleUseTokenStore → retrocompatibilidad GET + REMOVE inline.
        var cache = Substitute.For<IDistributedCache>();
        var entry = CreateEntry();
        cache.GetAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>())
            .Returns(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(entry)));
        var sut = new DistributedCacheOAuthStateStore(cache);

        // Act
        var result = await sut.ConsumeAsync(ValidState);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(entry.Nonce, result!.Nonce);
        await cache.Received(1).RemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ConsumeAsync_TamperedJson_ReturnsNull_WithoutThrowing()
    {
        // Arrange: JSON corrupto (tampered) → se descarta sin lanzar (fail-secure).
        var sut = CreateSut(out var store);
        store.GetAndRemoveAsync("OAuthState_" + ValidState, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>("{ not valid json ]"));

        // Act
        var result = await sut.ConsumeAsync(ValidState);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task ConsumeAsync_InvalidState_Throws()
    {
        // Arrange: state demasiado corto / caracteres inválidos → se rechaza antes del acceso.
        var sut = CreateSut(out var store);

        // Act + Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
        {
            return sut.ConsumeAsync("abc").AsTask();
        });
        await store.DidNotReceiveWithAnyArgs().GetAndRemoveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SaveAsync_WithSingleUseStore_WritesThroughSpi()
    {
        // Arrange: el ciclo de vida completo pasa por ISingleUseTokenStore (H1 — sin split-brain).
        var cache = Substitute.For<IDistributedCache>();
        var store = Substitute.For<ISingleUseTokenStore>();
        var sut = new DistributedCacheOAuthStateStore(cache, singleUseTokenStore: store);
        var entry = CreateEntry();
        var ttl = TimeSpan.FromMinutes(10);

        // Act
        await sut.SaveAsync(ValidState, entry, ttl, CancellationToken.None);

        // Assert: escritura vía SPI, nunca directa a IDistributedCache.
        await store.Received(1).SetAsync(
            "OAuthState_" + ValidState,
            Arg.Is<string>(json => json.Contains(entry.Nonce) && json.Contains(entry.Provider)),
            ttl,
            Arg.Any<CancellationToken>());
        await cache.DidNotReceiveWithAnyArgs().SetAsync(null!, null!, null!, default);
    }

    [Fact]
    public async Task SaveAsync_WithoutSingleUseStore_UsesCacheDirect()
    {
        // Arrange: sin ISingleUseTokenStore → retrocompatibilidad: escritura directa.
        var cache = Substitute.For<IDistributedCache>();
        var sut = new DistributedCacheOAuthStateStore(cache);
        var entry = CreateEntry();
        var ttl = TimeSpan.FromMinutes(10);

        // Act
        await sut.SaveAsync(ValidState, entry, ttl, CancellationToken.None);

        // Assert
        await cache.Received(1).SetAsync(
            "OAuthState_" + ValidState,
            Arg.Is<byte[]>(bytes => bytes.Length > 0),
            Arg.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpirationRelativeToNow == ttl),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SaveAsync_NullEntry_Throws()
    {
        // Arrange: defensa M2 — entry nulo se rechaza antes de tocar el store.
        var sut = CreateSut(out var store);

        // Act + Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            sut.SaveAsync(ValidState, null!, TimeSpan.FromMinutes(10)));
        await store.DidNotReceiveWithAnyArgs().SetAsync(null!, null!, default, default);
    }
}
