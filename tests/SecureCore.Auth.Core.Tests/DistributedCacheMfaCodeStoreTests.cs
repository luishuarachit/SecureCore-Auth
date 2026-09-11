using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests de <c>DistributedCacheMfaCodeStore</c> — en particular el fix de auditoría del marcador
/// anti-replay TOTP: un intento ERRÓNEO no debe destruir la entrada (de lo contrario, un fallo
/// ajeno re-habilitaría el replay del código legítimo dentro de la ventana de tolerancia).
/// </summary>
public class DistributedCacheMfaCodeStoreTests
{
    private readonly IDistributedCache _cache = new MemoryDistributedCache(
        Options.Create(new MemoryDistributedCacheOptions()));
    private readonly DistributedCacheMfaCodeStore _store;

    public DistributedCacheMfaCodeStoreTests()
    {
        _store = new DistributedCacheMfaCodeStore(_cache, NullLogger<DistributedCacheMfaCodeStore>.Instance);
    }

    [Fact]
    public async Task ValidateAndRemove_CorrectCode_ReturnsTrue_AndConsumesSingleUse()
    {
        await _store.StoreCodeHashAsync("k", ComputeHash("123456"), TimeSpan.FromMinutes(5));

        Assert.True(await _store.ValidateAndRemoveCodeAsync("k", "123456"));
        Assert.False(await _store.ValidateAndRemoveCodeAsync("k", "123456"), "El código es single-use: la segunda validación falla");
    }

    [Fact]
    public async Task ValidateAndRemove_WrongCode_DoesNotDestroyEntry_AndReplayIsStillRejected()
    {
        // DIDÁCTICA (auditoría): el marcador anti-replay TOTP almacena el hash del código usado.
        // Si un intento erróneo lo borrara, el replay del código legítimo quedaría re-habilitado.
        await _store.StoreCodeHashAsync("totp:u1", ComputeHash("123456"), TimeSpan.FromMinutes(1));

        Assert.False(await _store.ValidateAndRemoveCodeAsync("totp:u1", "999999"), "Código erróneo no debe validar");

        // El marcador debe seguir presente → el replay del código legítimo sigue siendo rechazado.
        Assert.True(await _store.ValidateAndRemoveCodeAsync("totp:u1", "123456"),
            "El marcador sobrevive a intentos erróneos: el replay del código usado sigue detectándose");
    }

    [Fact]
    public async Task ValidateAndRemove_MissingEntry_ReturnsFalse()
    {
        Assert.False(await _store.ValidateAndRemoveCodeAsync("k", "123456"));
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
