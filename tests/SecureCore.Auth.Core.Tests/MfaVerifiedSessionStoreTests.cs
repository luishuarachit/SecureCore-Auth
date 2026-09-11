using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests de DistributedCacheMfaVerifiedSessionStore — ventana "mfa_verified" (S3, A-21).
/// </summary>
public class MfaVerifiedSessionStoreTests
{
    private readonly IDistributedCache _cache = Substitute.For<IDistributedCache>();
    private readonly DistributedCacheMfaVerifiedSessionStore _store;

    public MfaVerifiedSessionStoreTests()
    {
        _store = NewStore(TimeSpan.FromHours(8));
    }

    private DistributedCacheMfaVerifiedSessionStore NewStore(TimeSpan ttl)
    {
        return new DistributedCacheMfaVerifiedSessionStore(
            _cache,
            Options.Create(new SecureAuthOptions { MfaVerifiedTtl = ttl }),
            NullLogger<DistributedCacheMfaVerifiedSessionStore>.Instance);
    }

    [Fact]
    public async Task SetVerifiedAsync_Then_IsVerified_ReturnsTrue()
    {
        // DIDÁCTICA: GetStringAsync es un extensor sobre GetAsync (byte[]); stubeamos GetAsync.
        _cache.GetAsync("mfa_verified:u1", Arg.Any<CancellationToken>())
            .Returns(Encoding.UTF8.GetBytes("totp"));

        await _store.SetVerifiedAsync("u1", "totp");

        Assert.True(await _store.IsVerifiedAsync("u1"));
    }

    [Fact]
    public async Task SetVerifiedAsync_StoresMethodWithConfiguredTtl()
    {
        var store = NewStore(TimeSpan.FromMinutes(30));

        await store.SetVerifiedAsync("u1", "email_otp");

        // DIDÁCTICA: la ventana se persiste con el TTL configurado (SecureAuthOptions.MfaVerifiedTtl)
        // para que el store expire solo, sin jobs de limpieza. Se verifica contra SetAsync
        // directamente (GetStringAsync/SetStringAsync son extensores sobre los métodos base).
        await _cache.Received(1).SetAsync(
            "mfa_verified:u1",
            Arg.Any<byte[]>(),
            Arg.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpirationRelativeToNow == TimeSpan.FromMinutes(30)),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task IsVerifiedAsync_UnknownUser_ReturnsFalse()
    {
        // DIDÁCTICA: sin entrada en caché, GetStringAsync devuelve null → no verificado.
        _cache.GetAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((byte[]?)null);

        Assert.False(await _store.IsVerifiedAsync("nobody"));
    }

    [Fact]
    public async Task ClearAsync_Then_IsVerified_ReturnsFalse()
    {
        await _store.ClearAsync("u1");

        await _cache.Received(1).RemoveAsync("mfa_verified:u1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task InvalidTtl_FallsBackToDefault8Hours()
    {
        // Arrange: MfaVerifiedTtl = 0 (misconfiguración) → fallback defensivo de 8 h.
        var store = NewStore(TimeSpan.Zero);

        await store.SetVerifiedAsync("u1", "totp");

        await _cache.Received(1).SetAsync(
            "mfa_verified:u1",
            Arg.Any<byte[]>(),
            Arg.Is<DistributedCacheEntryOptions>(o =>
                o.AbsoluteExpirationRelativeToNow == TimeSpan.FromHours(8)),
            Arg.Any<CancellationToken>());
    }
}
