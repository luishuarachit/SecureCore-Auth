using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests de RecoveryCodeOrchestrator (F5/A-20) — flujo completo generar→verificar→usar,
/// hashing de código (nunca plaintext al store) y anti-abuso por cuenta (S1, scope Recovery).
/// </summary>
public class RecoveryCodeOrchestratorTests
{
    private const string UserId = "u1";

    private readonly IRecoveryCodeStore _store = Substitute.For<IRecoveryCodeStore>();
    private readonly ITotpService _totpService = Substitute.For<ITotpService>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IAccountProtectionService _protection = Substitute.For<IAccountProtectionService>();

    private readonly MfaOptions _mfaOptions = new()
    {
        Enabled = true,
        EnableRecoveryCodes = true,
        RecoveryCodeCount = 5
    };

    public RecoveryCodeOrchestratorTests()
    {
        _store.CreateAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);
        _store.GetStatusAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Invalid));
        _store.RedeemAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(false));
        _eventDispatcher.DispatchAsync(Arg.Any<AuthEvent>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        _protection.CheckAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(true, RemainingAttempts: 3, LockEnd: null, EscalationLevel: 0)));
    }

    private RecoveryCodeOrchestrator CreateOrchestrator(bool enableProtection = false)
    {
        return new RecoveryCodeOrchestrator(
            _store,
            _totpService,
            _eventDispatcher,
            new InMemoryOperationLock(TimeSpan.FromSeconds(5)),
            Options.Create(_mfaOptions),
            NullLogger<RecoveryCodeOrchestrator>.Instance,
            enableProtection ? _protection : null,
            enableProtection ? Options.Create(new AccountProtectionOptions { Enabled = true }) : null);
    }

    // ─────────────────────────────────────────────
    //  GenerateAsync
    // ─────────────────────────────────────────────

    [Fact]
    public async Task GenerateAsync_WhenDisabled_ReturnsFailure_AndDoesNotTouchStore()
    {
        _mfaOptions.EnableRecoveryCodes = false;
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.GenerateAsync(UserId);

        Assert.False(result.Success);
        Assert.Null(result.Codes);
        await _store.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _store.DidNotReceiveWithAnyArgs().InvalidatePendingAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GenerateAsync_GeneratesCodes_ReturnsPlaintextOnce_AndPersistsOnlyHashes()
    {
        var codes = new List<string> { "code-a", "code-b", "code-c" };
        _totpService.GenerateRecoveryCodes(5).Returns(codes);
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.GenerateAsync(UserId);

        Assert.True(result.Success);
        Assert.Equal(codes, result.Codes);

        // DIDÁCTICA: el store recibe SOLO los hashes SHA-256 (hex minúsculas); nunca plaintext.
        foreach (var code in codes)
        {
            await _store.Received(1).CreateAsync(UserId, ComputeHash(code), Arg.Any<CancellationToken>());
            await _store.DidNotReceive().CreateAsync(UserId, code, Arg.Any<CancellationToken>());
        }

        // El lote anterior se invalidó ANTES de crear el nuevo (replace completo).
        await _store.Received(1).InvalidatePendingAsync(UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GenerateAsync_DispatchesRecoveryCodesGenerated()
    {
        _totpService.GenerateRecoveryCodes(Arg.Any<int>()).Returns(["x"]);
        var orchestrator = CreateOrchestrator();

        await orchestrator.GenerateAsync(UserId);

        Received.InOrder(() =>
        {
            _store.InvalidatePendingAsync(UserId, Arg.Any<CancellationToken>());
            _eventDispatcher.DispatchAsync(
                Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodesGenerated),
                Arg.Any<CancellationToken>());
        });
    }

    [Fact]
    public async Task GenerateAsync_WhenRecoveryCodeCountInvalid_ReturnsFailure_AndDoesNotInvalidate()
    {
        // DIDÁCTICA (B5, defensa en profundidad): un count inválido (0) NO debe invalidar el
        // lote anterior — el usuario conservaría sus códigos de emergencia ante una mala config.
        _mfaOptions.RecoveryCodeCount = 0;
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.GenerateAsync(UserId);

        Assert.False(result.Success);
        Assert.Null(result.Codes);
        await _store.DidNotReceiveWithAnyArgs().InvalidatePendingAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _store.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ─────────────────────────────────────────────
    //  VerifyAsync
    // ─────────────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_ValidCode_ReturnsValid_AndResetsProtectionWhenEnabled()
    {
        _store.GetStatusAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Valid));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.VerifyAsync(UserId, "code");

        Assert.True(result.IsValid);
        Assert.Equal(RecoveryCodeStatus.Valid, result.Status);
        await _protection.Received(1).RecordSuccessAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_AlreadyUsedCode_MapsStatus_WithoutConsuming()
    {
        _store.GetStatusAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.AlreadyUsed));
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.VerifyAsync(UserId, "code");

        Assert.False(result.IsValid);
        Assert.Equal(RecoveryCodeStatus.AlreadyUsed, result.Status);
        await _store.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_InvalidCode_RecordsProtectionFailureWhenEnabled()
    {
        _store.GetStatusAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.Invalid));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.VerifyAsync(UserId, "bad");

        Assert.False(result.IsValid);
        await _protection.Received(1).RecordFailureAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodeVerificationFailed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_InvalidCode_DispatchesRecoveryCodeVerificationFailed()
    {
        // DIDÁCTICA (B3, auditoría): cada verificación fallida emite un evento (paridad con
        // MfaVerificationFailed de S1) para que el host detecte intentos de uso de códigos robados.
        _store.GetStatusAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(RecoveryCodeStatus.AlreadyUsed));
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.VerifyAsync(UserId, "code");

        Assert.False(result.IsValid);
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodeVerificationFailed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_WhenDisabled_ReturnsInvalid()
    {
        _mfaOptions.EnableRecoveryCodes = false;
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.VerifyAsync(UserId, "code");

        Assert.False(result.IsValid);
        await _store.DidNotReceiveWithAnyArgs().GetStatusAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_LockedOut_ReturnsInvalid_WithoutRevealingReason()
    {
        _protection.CheckAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(false, 0, DateTimeOffset.UtcNow.AddMinutes(10), 1)));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.VerifyAsync(UserId, "code");

        // DIDÁCTICA: ante lockout el verify responde genérico (Invalid) — no revelar el bloqueo.
        Assert.False(result.IsValid);
        await _store.DidNotReceiveWithAnyArgs().GetStatusAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ─────────────────────────────────────────────
    //  UseAsync
    // ─────────────────────────────────────────────

    [Fact]
    public async Task UseAsync_Success_RedeemsAndDispatchesRecoveryCodeRedeemed_AndResetsProtection()
    {
        _store.RedeemAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(true));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.UseAsync(UserId, "code");

        Assert.True(result.Success);
        await _store.Received(1).RedeemAsync(UserId, ComputeHash("code"), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodeRedeemed),
            Arg.Any<CancellationToken>());
        await _protection.Received(1).RecordSuccessAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UseAsync_InvalidCode_ReturnsGenericFailure_AndRecordsProtectionFailure()
    {
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.UseAsync(UserId, "bad");

        Assert.False(result.Success);
        Assert.False(result.LockedOut);
        await _protection.Received(1).RecordFailureAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodeRedemptionFailed),
            Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceive().DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.RecoveryCodeRedeemed),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UseAsync_Failure_ThatTriggersLockout_ReturnsBlocked_AndAuditsAccountLockedOut()
    {
        // DIDÁCTICA (S1): el primer Check permite; el fallo dispara el lockout; el Check post-fallo
        // ya no permite (escalado). El endpoint traduce LockedOut en 429 sin revelar detalles.
        _protection.CheckAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>())
            .Returns(
                ValueTask.FromResult(new AccountProtectionResult(true, 1, null, 0)),
                ValueTask.FromResult(new AccountProtectionResult(false, 0, DateTimeOffset.UtcNow.AddMinutes(10), 1)));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.UseAsync(UserId, "bad");

        Assert.False(result.Success);
        Assert.True(result.LockedOut);
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e =>
                e.EventType == AuthEventType.AccountLockedOut &&
                e.Metadata.ContainsKey("scope") && e.Metadata["scope"] == "recovery"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UseAsync_AlreadyLockedBeforeCall_ReturnsBlocked_WithoutRedeeming()
    {
        _protection.CheckAsync(AccountProtectionScope.Recovery, UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(false, 0, DateTimeOffset.UtcNow.AddMinutes(10), 2)));
        var orchestrator = CreateOrchestrator(enableProtection: true);

        var result = await orchestrator.UseAsync(UserId, "code");

        Assert.False(result.Success);
        Assert.True(result.LockedOut);
        await _store.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UseAsync_WhenDisabled_ReturnsGenericFailure()
    {
        _mfaOptions.EnableRecoveryCodes = false;
        var orchestrator = CreateOrchestrator();

        var result = await orchestrator.UseAsync(UserId, "code");

        Assert.False(result.Success);
    }

    [Fact]
    public async Task UseAsync_OversizedCode_RejectedBeforeStore()
    {
        // DIDÁCTICA (H3): un código de 100+ caracteres se descarta antes de tocar hash/store.
        var orchestrator = CreateOrchestrator();
        var huge = new string('a', 300);

        var result = await orchestrator.UseAsync(UserId, huge);

        Assert.False(result.Success);
        await _store.DidNotReceiveWithAnyArgs().RedeemAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
