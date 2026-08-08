using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests de seguridad del flujo de enrollment MFA (S2/S3 del plan).
/// Cubre: binding del mfaSessionToken al enrollment (P2), protección contra
/// overwrite del secreto TOTP (P3) y single-use del token.
/// </summary>
public class MfaEnrollmentSecurityTests
{
    private readonly IUserStore _userStore;
    private readonly ITotpService _totpService;
    private readonly IEmailMfaService _emailMfaService;
    private readonly IMfaCodeStore _mfaCodeStore;
    private readonly IMfaSessionStore _mfaSessionStore;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IMfaEncryptionService _encryptionService;
    private readonly IAuthEventDispatcher _eventDispatcher;
    private readonly MfaOrchestrator _orchestrator;

    private const string TestEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    public MfaEnrollmentSecurityTests()
    {
        _userStore = Substitute.For<IUserStore>();
        _totpService = new TotpService();
        _emailMfaService = Substitute.For<IEmailMfaService>();
        _mfaCodeStore = Substitute.For<IMfaCodeStore>();
        _mfaSessionStore = Substitute.For<IMfaSessionStore>();
        _passwordHasher = Substitute.For<IPasswordHasher>();
        _encryptionService = Substitute.For<IMfaEncryptionService>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

        var mfaOptions = Options.Create(new MfaOptions
        {
            Enabled = true,
            AllowUserEnrollment = true,
            AllowUserDisable = true,
            AllowedMethods = new List<string> { "totp", "email" },
            EncryptionKey = TestEncryptionKey
        });

        _orchestrator = new MfaOrchestrator(
            _userStore,
            _totpService,
            _emailMfaService,
            _mfaCodeStore,
            _mfaSessionStore,
            _passwordHasher,
            _encryptionService,
            _eventDispatcher,
            mfaOptions,
            NullLogger<MfaOrchestrator>.Instance);
    }

    private UserIdentity EnrolledUser(string id = "u1")
    {
        return new UserIdentity
        {
            Id = id,
            Email = "test@example.com",
            PasswordHash = null,
            SecurityStamp = Guid.NewGuid().ToString(),
            MfaEnrollmentStatus = MfaEnrollmentStatus.Enrolled,
            PreferredMfaMethod = "totp"
        };
    }

    private UserIdentity PendingUser(string id = "u1", string? encryptedSecret = null)
    {
        return new UserIdentity
        {
            Id = id,
            Email = "test@example.com",
            PasswordHash = null,
            SecurityStamp = Guid.NewGuid().ToString(),
            MfaEnrollmentStatus = MfaEnrollmentStatus.Pending,
            PreferredMfaMethod = "totp",
            TotpSecretEncrypted = encryptedSecret
        };
    }

    // ── P2: Binding del mfaSessionToken al enrollment ──

    [Fact]
    public async Task CompleteEnrollmentAsync_WithoutValidToken_ReturnsFalse()
    {
        var user = PendingUser(encryptedSecret: "encrypted-secret");
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((string?)null); // token inválido/expirado

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "123456", "invalid-token");

        Assert.False(result);
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_TokenOfAnotherUser_ReturnsFalse()
    {
        var user = PendingUser(encryptedSecret: "encrypted-secret");
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("attacker-user"); // token emitido para otro usuario

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "123456", "token-of-other");

        Assert.False(result);
        await _mfaSessionStore.DidNotReceive().ConsumeMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_ValidToken_Success_ConsumesToken()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _encryptionService.Decrypt(secret).Returns(secret); // ciphertext == plaintext en el mock

        // Generar un código TOTP válido para el momento actual
        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = GenerateTotpCode(secret, step);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", code, "valid-token");

        Assert.True(result);
        await _mfaSessionStore.Received(1).ConsumeMfaSessionTokenAsync("valid-token", Arg.Any<CancellationToken>());
        await _userStore.Received(1).UpdateMfaEnrollmentAsync(
            "u1", MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_ValidToken_InvalidCode_DoesNotConsumeToken()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _encryptionService.Decrypt(secret).Returns(secret);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "000000", "valid-token");

        Assert.False(result);
        await _mfaSessionStore.DidNotReceive().ConsumeMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _userStore.DidNotReceive().UpdateMfaEnrollmentAsync(
            Arg.Any<string>(), MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ── P3: Protección contra overwrite del secreto ──

    [Fact]
    public async Task StartEnrollmentAsync_WhenAlreadyEnrolled_Throws()
    {
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(EnrolledUser());

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _orchestrator.StartEnrollmentAsync("u1", MfaMethod.Totp));

        // No debe generar ni sobrescribir el secreto
        await _userStore.DidNotReceive().SetTotpSecretAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StartEnrollmentAsync_WhenPendingWithExistingSecret_Throws_DoesNotOverwrite()
    {
        var user = PendingUser(encryptedSecret: "existing-pending-secret");
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _orchestrator.StartEnrollmentAsync("u1", MfaMethod.Totp));

        // El secreto pendiente existente NO debe sobrescribirse
        await _userStore.DidNotReceive().SetTotpSecretAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StartEnrollmentAsync_WhenPendingWithoutSecret_AllowsNewEnrollment()
    {
        var user = PendingUser(encryptedSecret: null);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.CreateMfaSessionTokenAsync("u1", "totp", Arg.Any<int>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns("new-token");

        var response = await _orchestrator.StartEnrollmentAsync("u1", MfaMethod.Totp);

        Assert.NotNull(response.TotpAuthUri);
        await _userStore.Received(1).SetTotpSecretAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task StartEnrollmentAsync_WhenNotEnrolled_GeneratesAndStoresNewSecret()
    {
        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            PasswordHash = null,
            SecurityStamp = Guid.NewGuid().ToString(),
            MfaEnrollmentStatus = MfaEnrollmentStatus.None
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.CreateMfaSessionTokenAsync("u1", "totp", Arg.Any<int>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns("new-token");

        var response = await _orchestrator.StartEnrollmentAsync("u1", MfaMethod.Totp);

        Assert.NotNull(response.TotpAuthUri);
        await _userStore.Received(1).SetTotpSecretAsync("u1", Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _userStore.Received(1).UpdateMfaEnrollmentAsync(
            "u1", MfaEnrollmentStatus.Pending, "totp", Arg.Any<CancellationToken>());
    }

    // ── T5: Fingerprint anti-race del secreto ──

    [Fact]
    public async Task StartEnrollmentAsync_PassesSecretFingerprintToToken()
    {
        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            PasswordHash = null,
            SecurityStamp = Guid.NewGuid().ToString(),
            MfaEnrollmentStatus = MfaEnrollmentStatus.None
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        string? capturedFingerprint = null;
        _mfaSessionStore.CreateMfaSessionTokenAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<int>(), Arg.Do<string?>(fp => capturedFingerprint = fp), Arg.Any<CancellationToken>())
            .Returns("new-token");

        await _orchestrator.StartEnrollmentAsync("u1", MfaMethod.Totp);

        Assert.False(string.IsNullOrEmpty(capturedFingerprint));
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_SecretChangedSinceStart_ReturnsFalse()
    {
        var originalSecret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: originalSecret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        // Fingerprint del token corresponde al secreto ORIGINAL del inicio.
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(originalSecret));

        // Simula TOCTOU: el secreto almacenado fue SOBRESCRITO por otro enrollment
        // con un secreto DIFERENTE entre Start y Complete.
        var replacedSecret = _totpService.GenerateSecret();
        _encryptionService.Decrypt(originalSecret).Returns(replacedSecret);

        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = GenerateTotpCode(replacedSecret, step);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", code, "valid-token");

        Assert.False(result);
        await _userStore.DidNotReceive().UpdateMfaEnrollmentAsync(
            Arg.Any<string>(), MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_SecretUnchanged_Success()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(secret));
        _encryptionService.Decrypt(secret).Returns(secret);

        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = GenerateTotpCode(secret, step);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", code, "valid-token");

        Assert.True(result);
        await _mfaSessionStore.Received(1).ConsumeMfaSessionTokenAsync("valid-token", Arg.Any<CancellationToken>());
        await _userStore.Received(1).UpdateMfaEnrollmentAsync(
            "u1", MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ── T6/T7 (P4): single-use del código TOTP + rate-limit de enrollment ──

    [Fact]
    public async Task CompleteEnrollmentAsync_ReusedTotpCode_ReturnsFalse()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(secret));
        _encryptionService.Decrypt(secret).Returns(secret);

        // El código ya fue usado previamente: el store lo detecta
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "123456", "valid-token");

        Assert.False(result);
        await _mfaSessionStore.DidNotReceive().ConsumeMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _userStore.DidNotReceive().UpdateMfaEnrollmentAsync(
            Arg.Any<string>(), MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_NewTotpCode_Success_MarksCodeAsUsed()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(secret));
        _encryptionService.Decrypt(secret).Returns(secret);
        // Código NO usado antes (retorna false)
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = GenerateTotpCode(secret, step);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", code, "valid-token");

        Assert.True(result);
        // Debe marcar el código como usado en el store
        await _mfaCodeStore.Received(1).StoreCodeHashAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_ExceededMaxAttempts_ReturnsFalse()
    {
        var user = PendingUser(encryptedSecret: "encrypted-secret") with
        {
            MfaFailedAttemptsCount = 5 // igual a MaxVerificationAttempts
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "123456", "valid-token");

        Assert.False(result);
        await _mfaSessionStore.DidNotReceive().ConsumeMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_InvalidCode_IncrementsAttempts()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(secret));
        _encryptionService.Decrypt(secret).Returns(secret);
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", "000000", "valid-token");

        Assert.False(result);
        await _userStore.Received(1).IncrementMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>());
        await _userStore.DidNotReceive().UpdateMfaEnrollmentAsync(
            Arg.Any<string>(), MfaEnrollmentStatus.Enrolled, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteEnrollmentAsync_Success_ResetsAttempts()
    {
        var secret = _totpService.GenerateSecret();
        var user = PendingUser(encryptedSecret: secret);
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _mfaSessionStore.ValidateMfaSessionTokenAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns("u1");
        _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(TotpComputeHash(secret));
        _encryptionService.Decrypt(secret).Returns(secret);
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var step = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        var code = GenerateTotpCode(secret, step);

        var result = await _orchestrator.CompleteEnrollmentAsync("u1", code, "valid-token");

        Assert.True(result);
        await _userStore.Received(1).ResetMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>());
    }

    // ── T8/T9 (P5): lockout temporal con CodeRetryWindowMinutes ──

    [Fact]
    public async Task VerifyAsync_ActiveMfaLockout_ReturnsFalse()
    {
        var user = EnrolledUser() with
        {
            MfaFailedAttemptsCount = 5,
            LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(3) // lockout activo
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);

        var result = await _orchestrator.VerifyAsync("u1", "123456");

        Assert.False(result.Success);
        Assert.Contains("Demasiados intentos", result.ErrorMessage);
    }

    [Fact]
    public async Task VerifyAsync_ExpiredMfaLockout_ResetsCounterAndAllowsRetry()
    {
        var user = EnrolledUser() with
        {
            MfaFailedAttemptsCount = 5,
            LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(-1) // ventana ya expirada
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _encryptionService.Decrypt(Arg.Any<string>()).Returns(_totpService.GenerateSecret());
        _userStore.IncrementMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>()).Returns(1);

        // Código inválido → pasa la validación de intentos y falla por código
        var result = await _orchestrator.VerifyAsync("u1", "000000");

        Assert.False(result.Success);
        // Debe haber reseteado el contador y desbloqueado (T9)
        await _userStore.Received(1).ResetMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>());
        await _userStore.Received(1).SetLockoutEndAsync("u1", null, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_ReachingMaxAttempts_SetsTemporaryLockout()
    {
        var secret = _totpService.GenerateSecret();
        var user = EnrolledUser() with { TotpSecretEncrypted = secret };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _encryptionService.Decrypt(secret).Returns(secret);
        _userStore.IncrementMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>()).Returns(5); // alcanza el máximo

        // T8: debe fijar LockoutEnd en el futuro (ventana de reintentos)
        DateTimeOffset? capturedLockoutEnd = null;
        await _userStore.SetLockoutEndAsync(
            "u1", Arg.Do<DateTimeOffset?>(d => capturedLockoutEnd = d), Arg.Any<CancellationToken>());

        var result = await _orchestrator.VerifyAsync("u1", "000000");

        Assert.False(result.Success);
        Assert.NotNull(capturedLockoutEnd);
        Assert.True(capturedLockoutEnd > DateTimeOffset.UtcNow);
    }

    // ── Auditoría: fixes post-T1..T9 ──

    [Fact]
    public async Task DisableAsync_PendingEnrollment_CancelsAndAllowsReenroll()
    {
        // Usuario atascado en Pending (token expirado) → puede cancelar vía DisableAsync
        var user = PendingUser(encryptedSecret: "stale-secret") with { PasswordHash = null };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _userStore.UpdateMfaEnrollmentAsync("u1", MfaEnrollmentStatus.Disabled, null, Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        var result = await _orchestrator.DisableAsync("u1", "");

        Assert.True(result);
        await _userStore.Received(1).UpdateMfaEnrollmentAsync(
            "u1", MfaEnrollmentStatus.Disabled, null, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ApplyMfaLockout_DoesNotShortenActivePasswordLockout()
    {
        var secret = _totpService.GenerateSecret();
        var user = EnrolledUser() with
        {
            TotpSecretEncrypted = secret,
            LockoutEnd = DateTimeOffset.UtcNow.AddHours(2) // lockout de contraseña más largo
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _encryptionService.Decrypt(secret).Returns(secret);
        _userStore.IncrementMfaFailedAttemptsAsync("u1", Arg.Any<CancellationToken>()).Returns(5);

        await _orchestrator.VerifyAsync("u1", "000000");

        // No debe tocar LockoutEnd: ya existe un lockout de contraseña más largo activo
        await _userStore.DidNotReceive().SetLockoutEndAsync(
            "u1", Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_ReusedTotpCode_ReturnsFalse()
    {
        var secret = _totpService.GenerateSecret();
        var user = EnrolledUser() with { TotpSecretEncrypted = secret };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>()).Returns(user);
        _encryptionService.Decrypt(secret).Returns(secret);
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true); // código ya usado

        var result = await _orchestrator.VerifyAsync("u1", "123456");

        Assert.False(result.Success);
        Assert.Contains("Código inválido", result.ErrorMessage);
    }

    private static string TotpComputeHash(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GenerateTotpCode(string secret, long step)
    {
        var bytes = TotpBase32Decode(secret);
        var stepBytes = BitConverter.GetBytes(step);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(stepBytes);

        using var hmac = new System.Security.Cryptography.HMACSHA1(bytes);
        var hash = hmac.ComputeHash(stepBytes);
        var offset = hash[^1] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) |
                     ((hash[offset + 1] & 0xFF) << 16) |
                     ((hash[offset + 2] & 0xFF) << 8) |
                     (hash[offset + 3] & 0xFF);
        return (binary % 1000000).ToString().PadLeft(6, '0');
    }

    private static byte[] TotpBase32Decode(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        input = input.TrimEnd('=').ToUpperInvariant().Replace(" ", "");
        var output = new List<byte>();
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var c in input)
        {
            var value = alphabet.IndexOf(c);
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
