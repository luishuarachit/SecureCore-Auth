using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Moq;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

public class SingleUseTokenStoreTests
{
    [Fact]
    public async Task SetAsync_StoresValueWithRequestedTtl()
    {
        // Arrange
        var cacheMock = new Mock<IDistributedCache>();
        var sut = new DistributedCacheSingleUseTokenStore(cacheMock.Object);
        var ttl = TimeSpan.FromMinutes(2);

        // Act
        await sut.SetAsync("key-1", "value-1", ttl, CancellationToken.None);

        // Assert
        // DIDÁCTICA: SetStringAsync es una extensión que llama al método de interfaz SetAsync,
        // por eso se verifica la invariante real del contrato IDistributedCache.
        cacheMock.Verify(
            m => m.SetAsync(
                "key-1",
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(o => o.AbsoluteExpirationRelativeToNow == ttl),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetAndRemoveAsync_ExistingValue_ReturnsValueAndRemoves()
    {
        // Arrange
        var cacheMock = new Mock<IDistributedCache>();
        cacheMock.Setup(m => m.GetAsync("key-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes("stored-value"));
        var sut = new DistributedCacheSingleUseTokenStore(cacheMock.Object);

        // Act
        var result = await sut.GetAndRemoveAsync("key-1", CancellationToken.None);

        // Assert
        Assert.Equal("stored-value", result);
        cacheMock.Verify(m => m.RemoveAsync("key-1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GetAndRemoveAsync_MissingKey_ReturnsNull_WithoutRemoving()
    {
        // Arrange
        var cacheMock = new Mock<IDistributedCache>();
        cacheMock.Setup(m => m.GetAsync("key-missing", It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);
        var sut = new DistributedCacheSingleUseTokenStore(cacheMock.Object);

        // Act
        var result = await sut.GetAndRemoveAsync("key-missing", CancellationToken.None);

        // Assert
        Assert.Null(result);
        cacheMock.Verify(m => m.RemoveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetAndRemoveAsync_DoubleConsume_SecondCallReturnsNull()
    {
        // Arrange: simula el consumo single-use — la key ya no está tras la primera lectura.
        var cacheMock = new Mock<IDistributedCache>();
        cacheMock.SetupSequence(m => m.GetAsync("key-1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes("stored-value"))
            .ReturnsAsync((byte[]?)null);
        var sut = new DistributedCacheSingleUseTokenStore(cacheMock.Object);

        // Act
        var first = await sut.GetAndRemoveAsync("key-1", CancellationToken.None);
        var second = await sut.GetAndRemoveAsync("key-1", CancellationToken.None);

        // Assert
        Assert.Equal("stored-value", first);
        Assert.Null(second);
        cacheMock.Verify(m => m.RemoveAsync("key-1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SetAsync_NonPositiveTtl_Throws()
    {
        // Arrange: defensa M1 — un TTL <= 0 crearía una entrada ya expirada.
        var cacheMock = new Mock<IDistributedCache>();
        var sut = new DistributedCacheSingleUseTokenStore(cacheMock.Object);

        // Act + Assert
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            sut.SetAsync("key-1", "value-1", TimeSpan.Zero, CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            sut.SetAsync("key-1", "value-1", TimeSpan.FromSeconds(-5), CancellationToken.None).AsTask());

        cacheMock.Verify(
            m => m.SetAsync(It.IsAny<string>(), It.IsAny<byte[]>(), It.IsAny<DistributedCacheEntryOptions>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }
}
