using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de IEmailOtpStore con consumo atómico vía S2 (ISingleUseTokenStore).
/// </summary>
/// <remarks>
/// DIDÁCTICA (S3): El consumo combina "leer (hash)" + "borrar" de forma que la entrada
/// desaparezca ATOMÁTICAMENTE. Delegar en <c>ISingleUseTokenStore</c> (S2, primitiva
/// GETDEL) garantiza que un código solo pueda validarse una vez incluso en multi-instancia,
/// sin necesidad de un lock. Si el consumidor registra un backend Redis con GETDEL atómico,
/// esta garantía es real; con el default sobre IDistributedCache (GET + REMOVE) la ventana
/// residual es ~1 ms y ya está documentada en S2.
///
/// SEGURIDAD:
/// - Nunca se almacena el código en texto plano: solo su hash SHA-256 (hex minúsculas).
/// - La comparación es en tiempo constante (<c>CryptographicOperations.FixedTimeEquals</c>).
/// - Longitudes distintas se descartan sin lanzar (FixedTimeEquals exige longitudes iguales).
/// </remarks>
public sealed class DistributedCacheEmailOtpStore(
    ISingleUseTokenStore singleUseTokenStore,
    ILogger<DistributedCacheEmailOtpStore> logger)
    : IEmailOtpStore
{
    /// <inheritdoc />
    public Task StoreCodeHashAsync(string key, string codeHash, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(codeHash);

        logger.LogDebug("OTP de verify-action almacenado en clave {Key}, TTL {Ttl}", key, ttl);
        return singleUseTokenStore.SetAsync(key, codeHash, ttl, cancellationToken).AsTask();
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAndRemoveCodeAsync(string key, string code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(code);

        // DIDÁCTICA: GetAndRemoveAsync consume la entrada de forma atómica (S2). Si devuelve
        // null, el código no existía (expirado o ya consumido): se falla sin distinguir.
        var storedHash = await singleUseTokenStore.GetAndRemoveAsync(key, cancellationToken);
        if (storedHash is null)
        {
            logger.LogDebug("OTP de verify-action no encontrado para clave {Key} (expirado o ya usado)", key);
            return false;
        }

        var providedHash = ComputeHash(code);

        // DIDÁCTICA: FixedTimeEquals exige longitudes iguales; ante hashes de distinta
        // longitud (defensa ante un store corrupto) devolvemos false sin lanzar.
        if (storedHash.Length != providedHash.Length)
        {
            logger.LogWarning("Longitud inesperada de hash almacenado para clave {Key}", key);
            return false;
        }

        var isValid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(storedHash),
            Encoding.UTF8.GetBytes(providedHash));

        logger.LogInformation(isValid
            ? "OTP de verify-action validado correctamente para clave {Key}"
            : "OTP de verify-action inválido para clave {Key}", key);

        return isValid;
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
