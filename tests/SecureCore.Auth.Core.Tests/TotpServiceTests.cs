using System.Reflection;
using System.Text;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

public class TotpServiceTests
{
    private readonly TotpService _totpService = new();

    // RFC 4648: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" == base32(ASCII "12345678901234567890")
    private const string RfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    [Fact]
    public void GenerateSecret_ReturnsValidBase32_Of32Chars()
    {
        var secret = _totpService.GenerateSecret();

        Assert.Equal(32, secret.Length);
        Assert.All(secret, c => Assert.True(
            (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'),
            $"Caracter inválido '{c}' fuera del alfabeto Base32."));
    }

    [Fact]
    public void GenerateSecret_DecodesBackTo20Bytes()
    {
        var secret = _totpService.GenerateSecret();
        var decoded = InvokeDecode(secret);

        Assert.Equal(20, decoded.Length);
    }

    [Fact]
    public void GenerateSecret_GeneratesDifferentSecrets_EachCall()
    {
        var s1 = _totpService.GenerateSecret();
        var s2 = _totpService.GenerateSecret();

        Assert.NotEqual(s1, s2);
    }

    // ── Vectores RFC 6238 (HMAC-SHA1, 6 dígitos, paso 30s, T0=0) ──
    // Se prueban a través de GenerateCodeForStep para controlar el tiempo exacto.
    // Los counters son floor(T/30) de los valores T del RFC.

    [Theory]
    [InlineData(0L, "755224")]          // RFC 4226 App.D: counter 0 (HOTP base)
    [InlineData(1L, "287082")]          // RFC 6238 T=59  → 94287082
    [InlineData(37037036L, "081804")]   // RFC 6238 T=1111111109 → 07081804
    [InlineData(37037037L, "050471")]   // RFC 6238 T=1111111111 → 14050471
    [InlineData(41152263L, "005924")]   // RFC 6238 T=1234567890 → 89005924
    [InlineData(66666666L, "279037")]   // RFC 6238 T=2000000000 → 69279037
    [InlineData(666666666L, "353130")]  // RFC 6238 T=20000000000 → 65353130
    public void GenerateCodeForStep_MatchesRfc6238Vectors(long step, string expected)
    {
        var actual = InvokeGenerateCodeForStep(RfcSecret, step);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Base32Decode_Rfc4648Secret_ReturnsAsciiSecretBytes()
    {
        var decoded = InvokeDecode(RfcSecret);

        Assert.Equal("12345678901234567890", Encoding.ASCII.GetString(decoded));
    }

    // ── Vectores RFC 4648 para Base32Encode (sin padding, como lo emite la librería) ──

    [Theory]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32Encode_MatchesRfc4648Vectors(string input, string expected)
    {
        var actual = InvokeEncode(Encoding.ASCII.GetBytes(input));

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Base32_RoundTrip_PreservesBytes()
    {
        var random = new byte[64];
        System.Security.Cryptography.RandomNumberGenerator.Fill(random);

        var encoded = InvokeEncode(random);
        var decoded = InvokeDecode(encoded);

        Assert.Equal(random, decoded);
    }

    [Fact]
    public void Base32_RoundTrip_EmptyInput()
    {
        Assert.Equal(string.Empty, InvokeEncode([]));
        Assert.Empty(InvokeDecode(string.Empty));
    }

    [Fact]
    public void ValidateCode_CorrectCode_ReturnsTrue()
    {
        var secret = _totpService.GenerateSecret();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var expectedCode = InvokeGenerateCodeForStep(secret, step);

        Assert.True(_totpService.ValidateCode(secret, expectedCode));
    }

    [Fact]
    public void ValidateCode_WrongCode_ReturnsFalse()
    {
        var secret = _totpService.GenerateSecret();
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = InvokeGenerateCodeForStep(secret, step);

        var wrong = code == "000000" ? "000001" : "000000";
        Assert.False(_totpService.ValidateCode(secret, wrong));
    }

    [Fact]
    public void ValidateCode_AcceptsStepWithinTolerance()
    {
        var secret = _totpService.GenerateSecret();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;

        var prevCode = InvokeGenerateCodeForStep(secret, now - 1);
        var nextCode = InvokeGenerateCodeForStep(secret, now + 1);

        Assert.True(_totpService.ValidateCode(secret, prevCode));
        Assert.True(_totpService.ValidateCode(secret, nextCode));
    }

    [Fact]
    public void ValidateCode_EmptySecretOrCode_ReturnsFalse()
    {
        Assert.False(_totpService.ValidateCode("", "123456"));
        Assert.False(_totpService.ValidateCode(RfcSecret, ""));
        Assert.False(_totpService.ValidateCode(null!, "123456"));
    }

    [Theory]
    [InlineData("12345")]          // longitud corta
    [InlineData("1234567")]        // longitud larga
    [InlineData("abcdef")]         // no numérico
    [InlineData("12a456")]         // parcialmente no numérico
    public void ValidateCode_MalformedCode_ReturnsFalse(string code)
    {
        Assert.False(_totpService.ValidateCode(RfcSecret, code));
    }

    [Fact]
    public void GenerateAuthUri_ContainsSecretIssuerAndOtpParams()
    {
        var uri = _totpService.GenerateAuthUri(RfcSecret, "user@example.com", "MyIssuer");

        Assert.StartsWith("otpauth://totp/", uri);
        Assert.Contains($"secret={RfcSecret}", uri);
        Assert.Contains("issuer=MyIssuer", uri);
        Assert.Contains("algorithm=SHA1", uri);
        Assert.Contains("digits=6", uri);
        Assert.Contains("period=30", uri);
    }

    [Fact]
    public void GenerateRecoveryCodes_ReturnsUniqueCodes()
    {
        var codes = _totpService.GenerateRecoveryCodes(10);

        Assert.Equal(10, codes.Count);
        Assert.Equal(codes.Count, codes.Distinct().Count());
        Assert.All(codes, c => Assert.Equal(32, c.Length));
    }

    // ── Helpers con reflection para métodos privados ──

    private static string InvokeEncode(byte[] data)
    {
        var method = typeof(TotpService).GetMethod(
            "Base32Encode", BindingFlags.NonPublic | BindingFlags.Static)!;
        return (string)method.Invoke(null, [data])!;
    }

    private static byte[] InvokeDecode(string input)
    {
        var method = typeof(TotpService).GetMethod(
            "Base32Decode", BindingFlags.NonPublic | BindingFlags.Static)!;
        return (byte[])method.Invoke(null, [input])!;
    }

    private static string InvokeGenerateCodeForStep(string secret, long step)
    {
        var method = typeof(TotpService).GetMethod(
            "GenerateCodeForStep", BindingFlags.NonPublic | BindingFlags.Static)!;
        return (string)method.Invoke(null, [secret, step])!;
    }
}
