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
/// Tests de VerifyActionOrchestrator — step-up (S3, A-22) con OTP de verify-action.
/// </summary>
public class VerifyActionOrchestratorTests
{
    private const string UserId = "u1";
    private const string LockedMessage = "Demasiados intentos. Intente más tarde.";

    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IEmailOtpStore _otpStore = Substitute.For<IEmailOtpStore>();
    private readonly IEmailOtpSender _otpSender = Substitute.For<IEmailOtpSender>();
    private readonly IMfaVerifiedSessionStore _mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

    private static readonly VerifyActionOptions DefaultOptions = new();

    private VerifyActionOrchestrator CreateOrchestrator(
        IAccountProtectionService? protection = null,
        AccountProtectionOptions? protectionOptions = null,
        VerifyActionOptions? options = null)
    {
        return new VerifyActionOrchestrator(
            _userStore,
            _otpStore,
            _otpSender,
            _mfaVerified,
            _eventDispatcher,
            Options.Create(options ?? DefaultOptions),
            NullLogger<VerifyActionOrchestrator>.Instance,
            protection,
            protectionOptions is null ? null : Options.Create(protectionOptions));
    }

    private static UserIdentity CreateTestUser() => new()
    {
        Id = UserId,
        Email = "test@example.com",
        PasswordHash = null,
        SecurityStamp = Guid.NewGuid().ToString()
    };

    [Fact]
    public async Task SendVerifyCodeAsync_Success_StoresHashAndSends()
    {
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());

        var result = await orchestrator.SendVerifyCodeAsync(UserId, VerifyActionChannel.Email);

        Assert.True(result.Success);
        await _otpStore.Received(1).StoreCodeHashAsync(
            Arg.Is<string>(k => k == $"verify_action:{UserId}"),
            Arg.Any<string>(),
            Arg.Is<TimeSpan>(t => t == TimeSpan.FromMinutes(DefaultOptions.TtlMinutes)),
            Arg.Any<CancellationToken>());
        await _otpSender.Received(1).SendAsync("test@example.com", Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendVerifyCodeAsync_UserNotFound_ReturnsGenericFailure()
    {
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(null));

        var result = await orchestrator.SendVerifyCodeAsync(UserId);

        Assert.False(result.Success);
        Assert.Equal("No se pudo enviar el código de verificación.", result.ErrorMessage);
        await _otpStore.DidNotReceiveWithAnyArgs().StoreCodeHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendVerifyCodeAsync_UnsupportedChannel_ReturnsFailure()
    {
        var orchestrator = CreateOrchestrator();

        // DIDÁCTICA: solo Email implementado en esta versión; el fallo no revela detalles.
        var result = await orchestrator.SendVerifyCodeAsync(UserId, (VerifyActionChannel)99);

        Assert.False(result.Success);
        await _otpStore.DidNotReceiveWithAnyArgs().StoreCodeHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendVerifyCodeAsync_SenderThrows_ReturnsGenericFailure()
    {
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());
        _otpSender.SendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("SMTP caído")));

        // Act: el fallo de entrega no puede estallar al endpoint ni filtrar el error.
        var result = await orchestrator.SendVerifyCodeAsync(UserId);

        Assert.False(result.Success);
        Assert.Equal("No se pudo enviar el código de verificación.", result.ErrorMessage);
    }

    [Fact]
    public async Task SendVerifyCodeAsync_WithProtection_EachSendDecrementsBudget()
    {
        // Arrange: S1 activo — cada envío es un intento contra el scope VerifyAction.
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        var orchestrator = CreateOrchestrator(protection, new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) });
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());

        await orchestrator.SendVerifyCodeAsync(UserId);

        var check = await protection.CheckAsync(AccountProtectionScope.VerifyAction, UserId);
        Assert.Equal(4, check.RemainingAttempts);
    }

    [Fact]
    public async Task SendVerifyCodeAsync_WithProtection_ExhaustedBudget_Blocks()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        // MaxSendsPerWindow=5 para que el 6º envío se bloquee por S1 (no por el throttle duro).
        var orchestrator = CreateOrchestrator(protection,
            new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) },
            new VerifyActionOptions { MaxSendsPerWindow = 5 });
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());

        for (var i = 0; i < 5; i++)
        {
            await orchestrator.SendVerifyCodeAsync(UserId);
        }

        var result = await orchestrator.SendVerifyCodeAsync(UserId);

        Assert.False(result.Success);
        Assert.Equal(LockedMessage, result.ErrorMessage);
        await _otpStore.Received(5).StoreCodeHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
        await _otpSender.Received(5).SendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendVerifyCodeAsync_WithoutProtection_ThrottleBlocksFourthWithinWindow()
    {
        // Arrange (H1, auditoría): el throttle duro aplica SIEMPRE, incluso sin S1.
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());

        // Act: el tope por defecto es 3 envíos por ventana (TtlMinutes).
        for (var i = 0; i < 3; i++)
        {
            var ok = await orchestrator.SendVerifyCodeAsync(UserId);
            Assert.True(ok.Success);
        }

        var fourth = await orchestrator.SendVerifyCodeAsync(UserId);

        // Assert: el 4º envío se bloquea sin depender del opt-in de S1.
        Assert.False(fourth.Success);
        Assert.Equal(LockedMessage, fourth.ErrorMessage);
        await _otpStore.Received(3).StoreCodeHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
        await _otpSender.Received(3).SendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendVerifyCodeAsync_SendFails_DoesNotStoreHashNorRecordBudget()
    {
        // Arrange (M2, auditoría): el hash se persiste SOLO si la entrega fue satisfactoria.
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());
        _otpSender.SendAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("SMTP caído")));

        var result = await orchestrator.SendVerifyCodeAsync(UserId);

        Assert.False(result.Success);
        Assert.Equal("No se pudo enviar el código de verificación.", result.ErrorMessage);
        await _otpStore.DidNotReceiveWithAnyArgs().StoreCodeHashAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyActionAsync_Success_ResetsSendThrottle()
    {
        // Arrange (H1): tras 3 envíos el throttle está lleno; una verificación correcta lo renueva.
        var orchestrator = CreateOrchestrator();
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(CreateTestUser());
        _otpStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        for (var i = 0; i < 3; i++)
        {
            await orchestrator.SendVerifyCodeAsync(UserId);
        }

        var blocked = await orchestrator.SendVerifyCodeAsync(UserId);
        Assert.False(blocked.Success);

        await orchestrator.VerifyActionAsync(UserId, "123456");

        var afterVerify = await orchestrator.SendVerifyCodeAsync(UserId);
        Assert.True(afterVerify.Success);
    }

    [Fact]
    public async Task VerifyActionAsync_OversizedCode_RejectedWithoutHashingOrConsuming()
    {
        // Arrange (H3): un código con longitud distinta a CodeLength se rechaza en seco.
        var orchestrator = CreateOrchestrator();
        _otpStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await orchestrator.VerifyActionAsync(UserId, new string('9', 1024));

        Assert.False(result.Success);
        await _otpStore.DidNotReceiveWithAnyArgs().ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _mfaVerified.DidNotReceiveWithAnyArgs().SetVerifiedAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyActionAsync_ValidCode_SuccessAndMarksVerified()
    {
        var orchestrator = CreateOrchestrator();
        _otpStore.ValidateAndRemoveCodeAsync($"verify_action:{UserId}", Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await orchestrator.VerifyActionAsync(UserId, "123456");

        Assert.True(result.Success);
        await _mfaVerified.Received(1).SetVerifiedAsync(UserId, "email_otp", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.MfaVerificationSuccess
                && e.Metadata.ContainsKey("purpose") && e.Metadata["purpose"] == "verify_action"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyActionAsync_InvalidCode_FailureAndDispatchesEvent()
    {
        var orchestrator = CreateOrchestrator();
        _otpStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var result = await orchestrator.VerifyActionAsync(UserId, "000000");

        Assert.False(result.Success);
        await _mfaVerified.DidNotReceiveWithAnyArgs().SetVerifiedAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.MfaVerificationFailed
                && e.Metadata.ContainsKey("purpose") && e.Metadata["purpose"] == "verify_action"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyActionAsync_ValidCode_ConsumesSingleUseAndRecordsSuccess()
    {
        // Arrange: S1 — el código acertado renueva el presupuesto del scope VerifyAction.
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        var orchestrator = CreateOrchestrator(protection, new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) });
        _otpStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await orchestrator.VerifyActionAsync(UserId, "123456");

        Assert.True(result.Success);
        var check = await protection.CheckAsync(AccountProtectionScope.VerifyAction, UserId);
        Assert.True(check.Allowed);
        Assert.Equal(5, check.RemainingAttempts);
    }

    [Fact]
    public async Task VerifyActionAsync_WithProtection_FifthInvalidContractsLock()
    {
        // Arrange
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var protection = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) }), clock);
        var orchestrator = CreateOrchestrator(protection, new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) });
        _otpStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // Act: 5 códigos inválidos (el 5º dispara el lockout nivel 1).
        for (var i = 0; i < 5; i++)
        {
            await orchestrator.VerifyActionAsync(UserId, "000000");
        }

        var sixth = await orchestrator.VerifyActionAsync(UserId, "000000");

        // Assert: mensaje genérico (anti-enumeración) y sin consumo adicional del store.
        Assert.False(sixth.Success);
        Assert.Equal(LockedMessage, sixth.ErrorMessage);
        await _otpStore.Received(5).ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        var check = await protection.CheckAsync(AccountProtectionScope.VerifyAction, UserId);
        Assert.False(check.Allowed);
        Assert.Equal(1, check.EscalationLevel);
    }
}
