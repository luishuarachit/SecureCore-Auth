using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests del store de challenges WebAuthn (S4/A-23) — delegación a la primitiva single-use (S2).
/// </summary>
/// <remarks>
/// DIDÁCTICA: <see cref="DistributedCacheWebAuthnChallengeStore"/> delega el ciclo de vida
/// del challenge (set con TTL + consumo atómico) en <see cref="ISingleUseTokenStore"/> (S2).
/// El prefijo "webauthn:challenge:" evita colisiones con OAuth state y otros tokens single-use
/// que comparten el mismo store.
/// </remarks>
public class WebAuthnChallengeStoreTests
{
    private const string KeyPrefix = "webauthn:challenge:";

    private readonly ISingleUseTokenStore _singleUseStore = Substitute.For<ISingleUseTokenStore>();
    private readonly DistributedCacheWebAuthnChallengeStore _store;

    public WebAuthnChallengeStoreTests()
    {
        _store = new DistributedCacheWebAuthnChallengeStore(
            _singleUseStore,
            NullLogger<DistributedCacheWebAuthnChallengeStore>.Instance);
    }

    [Fact]
    public async Task CreateAsync_DelegatesToSingleUseStore_WithPrefixedKeyAndTtl()
    {
        var ttl = TimeSpan.FromSeconds(60);

        await _store.CreateAsync("c1", "payload-json", ttl);

        await _singleUseStore.Received(1).SetAsync(
            $"{KeyPrefix}c1",
            "payload-json",
            ttl,
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_EmptyChallengeId_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _store.CreateAsync("", "payload", TimeSpan.FromSeconds(60)).AsTask());

        await _singleUseStore.DidNotReceiveWithAnyArgs().SetAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_NullPayload_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            _store.CreateAsync("c1", null!, TimeSpan.FromSeconds(60)).AsTask());

        await _singleUseStore.DidNotReceiveWithAnyArgs().SetAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAndDeleteAsync_ConsumesPrefixedKey_ReturnsPayload()
    {
        _singleUseStore.GetAndRemoveAsync($"{KeyPrefix}c1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>("payload-json"));

        var result = await _store.GetAndDeleteAsync("c1");

        Assert.Equal("payload-json", result);
        await _singleUseStore.Received(1).GetAndRemoveAsync(
            $"{KeyPrefix}c1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GetAndDeleteAsync_MissingChallenge_ReturnsNull()
    {
        _singleUseStore.GetAndRemoveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        var result = await _store.GetAndDeleteAsync("unknown");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetAndDeleteAsync_EmptyChallengeId_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _store.GetAndDeleteAsync(null!).AsTask());

        await _singleUseStore.DidNotReceiveWithAnyArgs().GetAndRemoveAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RoundTrip_CreateThenConsume_ReturnsPayload()
    {
        // DIDÁCTICA: integración con el fallback real sobre MemoryDistributedCache.
        var store = NewRealStore();

        await store.CreateAsync("c1", "payload-json", TimeSpan.FromMinutes(5));
        var result = await store.GetAndDeleteAsync("c1");

        Assert.Equal("payload-json", result);
    }

    [Fact]
    public async Task DoubleConsume_ReturnsNullOnSecondRead()
    {
        // DIDÁCTICA (S2): single-use garantizado — el segundo consumo no obtiene valor.
        var store = NewRealStore();
        await store.CreateAsync("c1", "payload-json", TimeSpan.FromMinutes(5));

        var first = await store.GetAndDeleteAsync("c1");
        var second = await store.GetAndDeleteAsync("c1");

        Assert.Equal("payload-json", first);
        Assert.Null(second);
    }

    [Fact]
    public async Task ExpiredChallenge_ReturnsNull()
    {
        // DIDÁCTICA: la expiración la gobierna el TTL del cache subyacente (sin jobs de limpieza).
        var store = NewRealStore();
        await store.CreateAsync("c1", "payload-json", TimeSpan.FromMilliseconds(150));

        await Task.Delay(400);

        var result = await store.GetAndDeleteAsync("c1");
        Assert.Null(result);
    }

    [Fact]
    public async Task CreateAsync_CorruptedPayloadRoundTrip_DelegatesUnknownBlob()
    {
        // DIDÁCTICA: el store es opaco al formato del payload. No se valida la semántica:
        // un payload corrupto llega intacto al orquestador, que decide rechazarlo con
        // error genérico. Aquí solo verificamos que el byte[] viaja sin transformaciones.
        var store = NewRealStore();

        await store.CreateAsync("odd", "not-a-valid-json", TimeSpan.FromMinutes(5));
        var result = await store.GetAndDeleteAsync("odd");

        Assert.Equal("not-a-valid-json", result);
    }

    private static DistributedCacheWebAuthnChallengeStore NewRealStore()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var singleUse = new DistributedCacheSingleUseTokenStore(cache);
        return new DistributedCacheWebAuthnChallengeStore(
            singleUse,
            NullLogger<DistributedCacheWebAuthnChallengeStore>.Instance);
    }
}