using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Interfaz para cifrado del secreto TOTP.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El secreto TOTP se almacena cifrado en la BD.
/// Usamos AES-256-GCM (authenticated encryption).
/// La clave de cifrado debe ser provista por el implementador mediante configuración.
/// </remarks>
public interface IMfaEncryptionService
{
    /// <summary>
    /// Cifra el secreto TOTP.
    /// </summary>
    string Encrypt(string plainText);

    /// <summary>
    /// Descifra el secreto TOTP.
    /// </summary>
    string Decrypt(string cipherText);
}

/// <summary>
/// Implementación de IMfaEncryptionService usando AES-256-GCM.
/// </summary>
public sealed class AesMfaEncryptionService : IMfaEncryptionService
{
    private readonly byte[] _key;

    public AesMfaEncryptionService(IOptions<MfaOptions> options)
    {
        var keyString = options.Value.EncryptionKey;
        if (string.IsNullOrEmpty(keyString))
            throw new InvalidOperationException(
                "MfaOptions.EncryptionKey es requerida. Genere una clave de 32 bytes (64 caracteres hex) y configúrela.");

        _key = Convert.FromHexString(keyString);
        if (_key.Length != 32)
            throw new InvalidOperationException(
                "MfaOptions.EncryptionKey debe tener 64 caracteres (256 bits en hex).");
    }

    public string Encrypt(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var cipherText = new byte[plainBytes.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plainBytes, cipherText, tag);

        var result = new byte[nonce.Length + cipherText.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(cipherText, 0, result, nonce.Length, cipherText.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + cipherText.Length, tag.Length);

        return Convert.ToHexString(result).ToLowerInvariant();
    }

    public string Decrypt(string cipherTextHex)
    {
        var data = Convert.FromHexString(cipherTextHex);

        var nonce = new byte[12];
        var cipherText = new byte[data.Length - 12 - 16];
        var tag = new byte[16];

        Buffer.BlockCopy(data, 0, nonce, 0, 12);
        Buffer.BlockCopy(data, 12, cipherText, 0, cipherText.Length);
        Buffer.BlockCopy(data, 12 + cipherText.Length, tag, 0, 16);

        var plainText = new byte[cipherText.Length];

        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipherText, tag, plainText);

        return Encoding.UTF8.GetString(plainText);
    }
}