using System.Security.Cryptography;
using System.Text;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación de TOTP según RFC 6238.
/// </summary>
/// <remarks>
/// DIDÁCTICA: TOTP usa HMAC-SHA1 con pasos de 30 segundos.
/// - Secret: 20 bytes codificado en Base32
/// - Código: 6 dígitos (000000-999999)
/// - Ventana de tolerancia: ±1 paso (±60 segundos)
///
/// No usamos librerías externas - implementación nativa con
/// System.Security.Cryptography.HMACSHA1 y System.Security.Cryptography.RandomNumberGenerator.
/// </remarks>
public sealed class TotpService : ITotpService
{
    private const int SecretSizeBytes = 20;
    private const int StepIntervalSeconds = 30;
    private const int CodeDigits = 6;
    private const int TolerantSteps = 1;

    private static readonly char[] Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

    public string GenerateSecret()
    {
        var secretBytes = new byte[SecretSizeBytes];
        RandomNumberGenerator.Fill(secretBytes);
        return Base32Encode(secretBytes);
    }

    public string GenerateAuthUri(string secret, string accountName, string issuer)
    {
        var encodedIssuer = Uri.EscapeDataString(issuer);
        var encodedAccount = Uri.EscapeDataString(accountName);

        return $"otpauth://totp/{encodedIssuer}:{encodedAccount}?secret={secret}&issuer={encodedIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    public bool ValidateCode(string secret, string code)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(code))
            return false;

        if (code.Length != CodeDigits || !code.All(char.IsDigit))
            return false;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var currentStep = now / StepIntervalSeconds;

        for (int i = -TolerantSteps; i <= TolerantSteps; i++)
        {
            var step = currentStep + i;
            var expectedCode = GenerateCodeForStep(secret, step);
            if (CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedCode),
                Encoding.ASCII.GetBytes(code)))
            {
                return true;
            }
        }

        return false;
    }

    public List<string> GenerateRecoveryCodes(int count)
    {
        var codes = new List<string>();
        for (int i = 0; i < count; i++)
        {
            var bytes = new byte[16];
            RandomNumberGenerator.Fill(bytes);
            var code = Convert.ToHexString(bytes).ToLowerInvariant();
            codes.Add(code);
        }
        return codes;
    }

    private static string GenerateCodeForStep(string secret, long step)
    {
        var secretBytes = Base32Decode(secret);
        var stepBytes = BitConverter.GetBytes(step);

        if (BitConverter.IsLittleEndian)
            Array.Reverse(stepBytes);

        using var hmac = new HMACSHA1(secretBytes);
        var hash = hmac.ComputeHash(stepBytes);

        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);

        var otp = binary % (int)Math.Pow(10, CodeDigits);
        return otp.ToString().PadLeft(CodeDigits, '0');
    }

    private static string Base32Encode(byte[] data)
    {
        var result = new StringBuilder();
        var bitsRemaining = data.Length * 8;

        foreach (var b in data)
        {
            result.Append(Base32Alphabet[(b >> 3) & 0x1F]);
            bitsRemaining -= 5;
            if (bitsRemaining >= 5)
            {
                result.Append(Base32Alphabet[(b << 2) & 0x1F]);
                bitsRemaining -= 5;
            }
            else if (bitsRemaining > 0)
            {
                result.Append(Base32Alphabet[(b << (5 - (bitsRemaining - 5))) & 0x1F]);
                bitsRemaining = 0;
            }
        }

        return result.ToString();
    }

    private static byte[] Base32Decode(string input)
    {
        input = input.TrimEnd('=').ToUpperInvariant().Replace(" ", "");

        var output = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var c in input)
        {
            var value = Array.IndexOf(Base32Alphabet, c);
            if (value < 0)
                continue;

            buffer = (buffer << 5) | value;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                output.Add((byte)(buffer >> (bitsLeft - 8)));
                bitsLeft -= 8;
            }
        }

        return output.ToArray();
    }
}