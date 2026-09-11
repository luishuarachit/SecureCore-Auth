using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests del store default de recovery codes (F5/A-20) — consumo atómico vía S2 + índice JSON
/// para distinguir estados sin consumir.
/// </summary>
/// <remarks>
/// DIDÁCTICA: <see cref="DistributedCacheRecoveryCodeStore"/> separa DÓS fuentes:
/// 1) el token single-use por código en <see cref="ISingleUseTokenStore"/> (S2), que gobierna
///    la garantía de consumo único y funciona con cualquier backend S2 que registre el host;
/// 2) el índice por usuario en IDistributedCache (lista JSON de hashes pendientes/usados), que
///    alimenta <see cref="IRecoveryCodeStore.GetStatusAsync"/> y la invalidación. La redención
///    depende SOLO de S2; el índice es metadatos (verify/validate).
/// </remarks>
public class RecoveryCodeStoreTests
{
    private const string KeyPrefix = "recovery:code:";

    private readonly ISingleUseTokenStore _singleUseStore = Substitute.For<ISingleUseTokenStore>();
    private readonly DistributedCacheRecoveryCodeStore _store;

    public RecoveryCodeStoreTests()
    {
        _singleUseStore.SetAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);
        _singleUseStore.GetAndRemoveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        _store = NewRealStore(_singleUseStore);
    }

    [Fact]
    public async Task CreateAsync_DelegatesToSingleUseStore_WithPrefixedKeyAndLifetimeTtl()
    {
        var hash = ComputeHash("abc");

        await _store.CreateAsync("u1", hash);

        await _singleUseStore.Received(1).SetAsync(
            $"{KeyPrefix}u1|{hash}",
            hash,
            TimeSpan.FromDays(30),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_EmptyUserId_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _store.CreateAsync("", ComputeHash("abc")).AsTask());

        await _singleUseStore.DidNotReceiveWithAnyArgs().SetAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CreateAsync_NullHash_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            _store.CreateAsync("u1", null!).AsTask());

        await _singleUseStore.DidNotReceiveWithAnyArgs().SetAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RoundTrip_Create_GetStatus_ReturnsValid()
    {
        // DIDÁCTICA: integración con el fallback REAL (MemoryDistributedCache + S2 default).
        var store = NewFullyRealStore();
        var hash = ComputeHash("recovery-code-1");

        await store.CreateAsync("u1", hash);
        var status = await store.GetStatusAsync("u1", hash);

        Assert.Equal(RecoveryCodeStatus.Valid, status);
    }

    [Fact]
    public async Task GetStatus_UnknownHash_ReturnsInvalid()
    {
        var store = NewFullyRealStore();

        var status = await store.GetStatusAsync("u1", ComputeHash("never-issued"));

        Assert.Equal(RecoveryCodeStatus.Invalid, status);
    }

    [Fact]
    public async Task RedeemAsync_ValidCode_ReturnsTrue_AndStatusBecomesAlreadyUsed()
    {
        var store = NewFullyRealStore();
        var code = "recovery-code-1";
        var hash = ComputeHash(code);

        await store.CreateAsync("u1", hash);

        var redeemed = await store.RedeemAsync("u1", hash);
        var statusAfter = await store.GetStatusAsync("u1", hash);

        Assert.True(redeemed);
        Assert.Equal(RecoveryCodeStatus.AlreadyUsed, statusAfter);
    }

    [Fact]
    public async Task DoubleRedemption_SecondReturnsFalse()
    {
        // DIDÁCTICA (S2): single-use — el segundo consumo (concurrente o secuencial) falla.
        var store = NewFullyRealStore();
        var hash = ComputeHash("recovery-code-1");
        await store.CreateAsync("u1", hash);

        var first = await store.RedeemAsync("u1", hash);
        var second = await store.RedeemAsync("u1", hash);

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task RedeemAsync_UnknownCode_ReturnsFalse()
    {
        var store = NewFullyRealStore();

        var redeemed = await store.RedeemAsync("u1", ComputeHash("never-issued"));

        Assert.False(redeemed);
    }

    [Fact]
    public async Task InvalidatePendingAsync_ClearPendingCodes_StatusInvalidAndNotRedeemable()
    {
        var store = NewFullyRealStore();
        var hash = ComputeHash("recovery-code-1");
        await store.CreateAsync("u1", hash);

        await store.InvalidatePendingAsync("u1");

        var status = await store.GetStatusAsync("u1", hash);
        var redeemed = await store.RedeemAsync("u1", hash);

        Assert.Equal(RecoveryCodeStatus.Invalid, status);
        Assert.False(redeemed);
    }

    [Fact]
    public async Task InvalidatePendingAsync_AlreadyUsedCode_RemainsNonRedeemable()
    {
        // DIDÁCTICA: un código YA consumido no tiene token S2 que invalidar. La invalidación
        // limpia el índice completo del usuario (el estado "usado" es informativo y se pierde
        // con la regeneración), pero el single-use ya garantizó que no puede volver a redimirse.
        var store = NewFullyRealStore();
        var hash = ComputeHash("recovery-code-1");
        await store.CreateAsync("u1", hash);
        await store.RedeemAsync("u1", hash);

        await store.InvalidatePendingAsync("u1");

        Assert.Equal(RecoveryCodeStatus.Invalid, await store.GetStatusAsync("u1", hash));
        Assert.False(await store.RedeemAsync("u1", hash));
    }

    private static DistributedCacheRecoveryCodeStore NewRealStore(ISingleUseTokenStore singleUse)
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        return new DistributedCacheRecoveryCodeStore(
            singleUse,
            cache,
            new InMemoryOperationLock(TimeSpan.FromSeconds(5)),
            Options.Create(new MfaOptions { RecoveryCodeLifetimeDays = 30 }),
            NullLogger<DistributedCacheRecoveryCodeStore>.Instance);
    }

    private static DistributedCacheRecoveryCodeStore NewFullyRealStore()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        return new DistributedCacheRecoveryCodeStore(
            new DistributedCacheSingleUseTokenStore(cache),
            cache,
            new InMemoryOperationLock(TimeSpan.FromSeconds(5)),
            Options.Create(new MfaOptions { RecoveryCodeLifetimeDays = 30 }),
            NullLogger<DistributedCacheRecoveryCodeStore>.Instance);
    }

    [Fact]
    public async Task RedeemAsync_Concurrent_ExactlyOneSucceeds()
    {
        // DIDÁCTICA (A2, auditoría): la primitiva S2 por defecto es GET + REMOVE (NO atómica).
        // Sin el lock por código, N redenciones concurrentes podrían leer la entrada antes de
        // borrarla y todas "triunfar". El IOperationLock por clave serializa: exactamente una.
        var store = NewFullyRealStore();
        var hash = ComputeHash("recovery-code-1");
        await store.CreateAsync("u1", hash);

        var tasks = Enumerable.Range(0, 10)
            .Select(_ => store.RedeemAsync("u1", hash).AsTask())
            .ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(1, results.Count(r => r));
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
