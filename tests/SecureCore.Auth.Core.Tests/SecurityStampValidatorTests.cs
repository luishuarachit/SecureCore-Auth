using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests para SecurityStampValidator — validación de SSV con caché.
/// </summary>
public class SecurityStampValidatorTests
{
    private readonly SecurityStampValidator _validator;
    private readonly IUserStore _userStore;
    private readonly IDistributedCache _cache;

    public SecurityStampValidatorTests()
    {
        _userStore = Substitute.For<IUserStore>();
        _cache = Substitute.For<IDistributedCache>();

        var options = Options.Create(new SecureAuthOptions
        {
            SecurityStampCacheDuration = TimeSpan.FromMinutes(5)
        });

        _validator = new SecurityStampValidator(
            _userStore, _cache, options, NullLogger<SecurityStampValidator>.Instance);
    }

    [Fact]
    public async Task ValidateAsync_CacheHit_MatchingStamp_ReturnsTrue()
    {
        // Arrange — stamp en caché coincide
        var stamp = "valid-stamp";
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(System.Text.Encoding.UTF8.GetBytes(stamp));

        // Act
        var result = await _validator.ValidateAsync("u1", stamp);

        // Assert — no consulta la DB
        Assert.True(result);
        await _userStore.DidNotReceive().GetSecurityStampAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ValidateAsync_CacheHit_DifferentStamp_ReturnsFalse()
    {
        // Arrange — stamp en caché es diferente (sesión revocada)
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(System.Text.Encoding.UTF8.GetBytes("new-stamp"));

        // Act
        var result = await _validator.ValidateAsync("u1", "old-stamp");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task ValidateAsync_CacheMiss_FetchesFromStore_ReturnsTrue()
    {
        // Arrange — caché vacía, pero store tiene el stamp
        var stamp = "current-stamp";
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((byte[]?)null);
        _userStore.GetSecurityStampAsync("u1")
            .Returns(ValueTask.FromResult<string?>(stamp));

        // Act
        var result = await _validator.ValidateAsync("u1", stamp);

        // Assert — consultó la DB y repobló la caché
        Assert.True(result);
        await _userStore.Received(1).GetSecurityStampAsync("u1", Arg.Any<CancellationToken>());
        await _cache.Received(1).SetAsync(
            Arg.Any<string>(), Arg.Any<byte[]>(),
            Arg.Any<DistributedCacheEntryOptions>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ValidateAsync_CacheMiss_UserNotFound_ReturnsFalse()
    {
        // Arrange
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((byte[]?)null);
        _userStore.GetSecurityStampAsync("u1")
            .Returns(ValueTask.FromResult<string?>(null));

        // Act
        var result = await _validator.ValidateAsync("u1", "any-stamp");

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task InvalidateCacheAsync_RemovesEntry()
    {
        // Act
        await _validator.InvalidateCacheAsync("u1");

        // Assert
        await _cache.Received(1).RemoveAsync(
            Arg.Is<string>(k => k.Contains("u1")), Arg.Any<CancellationToken>());
    }
}
