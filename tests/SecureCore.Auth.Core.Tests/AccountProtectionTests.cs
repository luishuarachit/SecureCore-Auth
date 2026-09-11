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
/// TimeProvider manual para control determinista del reloj en los tests de S1.
/// </summary>
internal sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset _utcNow = start;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan delta) => _utcNow += delta;
}

/// <summary>
/// Tests de InMemoryAccountProtectionService — subsistema S1 (anti-abuso por cuenta).
/// </summary>
public class AccountProtectionServiceTests
{
    private static readonly TimeSpan[] Escalation = [TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), TimeSpan.FromHours(1), TimeSpan.FromHours(24)];

    private readonly ManualTimeProvider _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly IAccountProtectionService _service;

    public AccountProtectionServiceTests()
    {
        _service = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions
            {
                Enabled = true,
                Window = TimeSpan.FromHours(1),
                EscalationDurations = Escalation
            }),
            _clock);
    }

    [Fact]
    public async Task Check_NoFailures_AllowedWithFullBudget()
    {
        var result = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.True(result.Allowed);
        Assert.Equal(5, result.RemainingAttempts);
        Assert.Null(result.LockEnd);
        Assert.Equal(0, result.EscalationLevel);
    }

    [Fact]
    public async Task RecordFailure_FourTimes_RemainingDecreases()
    {
        for (var i = 0; i < 4; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        var result = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.True(result.Allowed);
        Assert.Equal(1, result.RemainingAttempts);
    }

    [Fact]
    public async Task RecordFailure_FiveTimes_ActivatesEscalatedLock()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        var result = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.False(result.Allowed);
        Assert.Equal(0, result.RemainingAttempts);
        Assert.Equal(1, result.EscalationLevel);
        // 1er bloqueo: 10 min (escalamiento).
        Assert.NotNull(result.LockEnd);
        Assert.InRange(result.LockEnd!.Value - _clock.GetUtcNow(), TimeSpan.FromMinutes(9.9), TimeSpan.FromMinutes(10.1));
    }

    [Fact]
    public async Task RecordFailure_DuringActiveLock_IsIgnored()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        var before = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");

        var after = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.False(after.Allowed);
        Assert.Equal(before.LockEnd, after.LockEnd);
        Assert.Equal(1, after.EscalationLevel);
    }

    [Fact]
    public async Task Escalation_AfterLockExpires_NextLockIsLevel2()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        // El lockout de nivel 1 (10 min) expira → decae solo (revisión perezosa).
        _clock.Advance(TimeSpan.FromMinutes(11));

        var released = await _service.CheckAsync(AccountProtectionScope.Password, "u1");
        Assert.True(released.Allowed);
        Assert.Equal(5, released.RemainingAttempts);

        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        var secondLock = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.False(secondLock.Allowed);
        Assert.Equal(2, secondLock.EscalationLevel);
        Assert.InRange(secondLock.LockEnd!.Value - _clock.GetUtcNow(), TimeSpan.FromMinutes(29.9), TimeSpan.FromMinutes(30.1));
    }

    [Fact]
    public async Task RecordSuccess_ResetsBudget()
    {
        for (var i = 0; i < 4; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        await _service.RecordSuccessAsync(AccountProtectionScope.Password, "u1");

        var result = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.True(result.Allowed);
        Assert.Equal(5, result.RemainingAttempts);
    }

    [Fact]
    public async Task ResetAllForUserAsync_ClearsEveryScope()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        for (var i = 0; i < 3; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Recovery, "u1");
        }

        Assert.True(await _service.AnyActiveLockAsync("u1"));

        await _service.ResetAllForUserAsync("u1");

        Assert.False(await _service.AnyActiveLockAsync("u1"));
        Assert.True((await _service.CheckAsync(AccountProtectionScope.Password, "u1")).Allowed);
        Assert.True((await _service.CheckAsync(AccountProtectionScope.Recovery, "u1")).Allowed);
    }

    [Fact]
    public async Task AnyActiveLockAsync_OnlyTracksMatchingKey()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        Assert.True(await _service.AnyActiveLockAsync("u1"));
        Assert.False(await _service.AnyActiveLockAsync("u2"));
    }

    [Fact]
    public async Task Window_Sliding_OldFailuresDoNotCount()
    {
        for (var i = 0; i < 4; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        // Superar la ventana de 1h: los fallos dejan de contar.
        _clock.Advance(TimeSpan.FromHours(2));

        var result = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.True(result.Allowed);
        Assert.Equal(5, result.RemainingAttempts);
    }

    [Fact]
    public async Task RecoveryScope_UsesItsOwnLimit_IndependentlyFromPassword()
    {
        for (var i = 0; i < 3; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Recovery, "u1");
        }

        var recovery = await _service.CheckAsync(AccountProtectionScope.Recovery, "u1");
        var password = await _service.CheckAsync(AccountProtectionScope.Password, "u1");

        Assert.False(recovery.Allowed);
        Assert.Equal(1, recovery.EscalationLevel);
        // El scope Password no se ve afectado (presupuesto independiente por factor).
        Assert.True(password.Allowed);
        Assert.Equal(5, password.RemainingAttempts);
    }

    [Fact]
    public async Task ResetAsync_ClearsSingleScope()
    {
        for (var i = 0; i < 5; i++)
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        await _service.ResetAsync(AccountProtectionScope.Password, "u1");

        Assert.True((await _service.CheckAsync(AccountProtectionScope.Password, "u1")).Allowed);
    }

    [Fact]
    public async Task ParallelRecordFailures_ResultInExactlyOneLock_WithoutEscalationBurst()
    {
        const int iterations = 20;

        await Parallel.ForAsync(0, iterations, async (_, ct) =>
        {
            await _service.RecordFailureAsync(AccountProtectionScope.Password, "parallel-user", ct);
        });

        var result = await _service.CheckAsync(AccountProtectionScope.Password, "parallel-user");

        // Solo el quinto fallo logró activar el lockout; los demás intentos ocurrieron
        // durante un lock activo y fueron ignorados → nivel 1 sin escalar por ráfaga.
        Assert.False(result.Allowed);
        Assert.Equal(1, result.EscalationLevel);
    }

    [Fact]
    public void Options_Defaults_MatchDesign()
    {
        var options = new AccountProtectionOptions();

        Assert.False(options.Enabled); // D-03: el subsistema es opt-in.
        Assert.Equal(TimeSpan.FromMinutes(5), options.Window);
        Assert.Equal(5, options.GetMaxAttempts(AccountProtectionScope.Password));
        Assert.Equal(5, options.GetMaxAttempts(AccountProtectionScope.MfaLogin));
        Assert.Equal(5, options.GetMaxAttempts(AccountProtectionScope.Passkey));
        Assert.Equal(3, options.GetMaxAttempts(AccountProtectionScope.Recovery));
        Assert.Equal(5, options.GetMaxAttempts(AccountProtectionScope.VerifyAction));
        Assert.Equal(TimeSpan.FromMinutes(10), options.GetLockDuration(1));
        Assert.Equal(TimeSpan.FromMinutes(30), options.GetLockDuration(2));
        Assert.Equal(TimeSpan.FromMinutes(60), options.GetLockDuration(3));
        Assert.Equal(TimeSpan.FromHours(24), options.GetLockDuration(4));
        Assert.Equal(TimeSpan.FromHours(24), options.GetLockDuration(10)); // techo MaxLockDuration
    }

    [Fact]
    public void GetLockDuration_ClampedToMaxLockDuration()
    {
        // H2: una duración configurada que supera MaxLockDuration se recorta al techo,
        // en vez de exceder el límite duro.
        var options = new AccountProtectionOptions
        {
            MaxLockDuration = TimeSpan.FromHours(24),
            EscalationDurations = new[] { TimeSpan.FromMinutes(10), TimeSpan.FromHours(24), TimeSpan.FromHours(72) }
        };

        Assert.Equal(TimeSpan.FromMinutes(10), options.GetLockDuration(1));
        Assert.Equal(TimeSpan.FromHours(24), options.GetLockDuration(2));
        Assert.Equal(TimeSpan.FromHours(24), options.GetLockDuration(3)); // 72 h → 24 h
    }

    [Fact]
    public void GetLockDuration_NonPositiveDurationsOrLevels_FallBackToMaxLockDuration()
    {
        var options = new AccountProtectionOptions
        {
            EscalationDurations = new TimeSpan[] { TimeSpan.MinValue, TimeSpan.Zero }
        };

        // H1: duraciones no positivas y niveles fuera de rango nunca producen lockouts nulos.
        Assert.Equal(AccountProtectionOptions.DefaultMaxLockDuration, options.GetLockDuration(1));
        Assert.Equal(AccountProtectionOptions.DefaultMaxLockDuration, options.GetLockDuration(2));
        Assert.Equal(AccountProtectionOptions.DefaultMaxLockDuration, options.GetLockDuration(0));
    }

    [Fact]
    public void GetWindow_And_GetMaxLockDuration_FallBackToDefaults_OnNonPositiveValues()
    {
        // H1: misconfiguración (0 o negativo) decae al default en lugar de fail-open.
        var options = new AccountProtectionOptions
        {
            Window = TimeSpan.Zero,
            MaxLockDuration = TimeSpan.Zero
        };

        Assert.Equal(AccountProtectionOptions.DefaultWindow, options.GetWindow());
        Assert.Equal(AccountProtectionOptions.DefaultMaxLockDuration, options.GetMaxLockDuration());
    }

    [Fact]
    public async Task RecordFailure_WithNonPositiveWindow_UsesDefaultWindow()
    {
        // H1: aunque el servicio se construya con opciones no validadas (uso directo),
        // la ventana defensiva (>0) evita que todos los fallos caduquen al instante.
        var service = new InMemoryAccountProtectionService(
            Options.Create(new AccountProtectionOptions { Enabled = true, Window = TimeSpan.Zero }),
            _clock);

        for (var i = 0; i < 5; i++)
        {
            await service.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        var result = await service.CheckAsync(AccountProtectionScope.Password, "u1");
        Assert.False(result.Allowed);
        Assert.Equal(1, result.EscalationLevel);
    }
}

/// <summary>
/// Tests de la integración de S1 en IdentityOrchestrator (scope Password).
/// </summary>
public class IdentityOrchestratorAccountProtectionTests
{
    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly ISessionStore _sessionStore = Substitute.For<ISessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IMfaSessionStore _mfaSessionStore = Substitute.For<IMfaSessionStore>();
    private readonly IMfaService _mfaService = Substitute.For<IMfaService>();
    private readonly AccountProtectionOptions _apOptions = new()
    {
        Enabled = true,
        Window = TimeSpan.FromHours(1),
        EscalationDurations = [TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), TimeSpan.FromHours(1), TimeSpan.FromHours(24)]
    };
    private readonly ManualTimeProvider _clock = new(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private readonly IAccountProtectionService _protection;

    public IdentityOrchestratorAccountProtectionTests()
    {
        _protection = new InMemoryAccountProtectionService(Options.Create(_apOptions), _clock);

        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddMinutes(15))));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("hash");
    }

    private IdentityOrchestrator CreateOrchestrator() => new(
        _userStore,
        _passwordHasher,
        _tokenService,
        _sessionStore,
        new LockoutManager(_userStore, Options.Create(new SecureAuthOptions()), NullLogger<LockoutManager>.Instance),
        _eventDispatcher,
        Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) }),
        Options.Create(new MfaOptions { Enabled = false }),
        _mfaSessionStore,
        _mfaService,
        NullLogger<IdentityOrchestrator>.Instance,
        _protection,
        Options.Create(_apOptions));

    private UserIdentity CreateUser() => new()
    {
        Id = "u1",
        Email = "test@example.com",
        PasswordHash = "hashed-password",
        SecurityStamp = Guid.NewGuid().ToString(),
        TwoFactorEnabled = false,
        LockoutEnd = null
    };

    [Fact]
    public async Task SignInWithPasswordAsync_FifthWrongPassword_TriggersLock()
    {
        // Arrange
        _userStore.FindByEmailAsync("test@example.com", Arg.Any<CancellationToken>()).Returns(CreateUser());
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerificationResult.Failed);
        var orchestrator = CreateOrchestrator();

        // Act
        for (var i = 0; i < 5; i++)
        {
            var (_, _, _) = await orchestrator.SignInWithPasswordAsync("test@example.com", "wrong");
        }

        // Assert: el 5º fallo dispara el lockout.
        var check = await _protection.CheckAsync(AccountProtectionScope.Password, "u1");
        Assert.False(check.Allowed);
        Assert.Equal(1, check.EscalationLevel);

        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.AccountLockedOut && e.Metadata["reason"] == "lock_triggered"),
            Arg.Any<CancellationToken>());

        // Con S1 la DB no se toca para contar intentos.
        await _userStore.DidNotReceiveWithAnyArgs().IncrementFailedAccessCountAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_LockedAccount_ReturnsLockedOut_AndSkipsPasswordCheck()
    {
        // Arrange: lockout activo por anti-abuso.
        for (var i = 0; i < 5; i++)
        {
            await _protection.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        _userStore.FindByEmailAsync("test@example.com", Arg.Any<CancellationToken>()).Returns(CreateUser());
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerificationResult.Success);
        var orchestrator = CreateOrchestrator();

        // Act
        var (result, _, _) = await orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        // Assert
        Assert.Equal(SignInResult.LockedOut, result);
        _passwordHasher.DidNotReceiveWithAnyArgs().VerifyPassword(Arg.Any<string>(), Arg.Any<string>());

        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.AccountLockedOut && e.Metadata["reason"] == "account_protection_lock"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SignInWithPasswordAsync_SuccessfulLogin_ResetsPasswordScope()
    {
        // Arrange: presupuesto consumido parcialmente.
        for (var i = 0; i < 4; i++)
        {
            await _protection.RecordFailureAsync(AccountProtectionScope.Password, "u1");
        }

        _userStore.FindByEmailAsync("test@example.com", Arg.Any<CancellationToken>()).Returns(CreateUser());
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerificationResult.Success);
        var orchestrator = CreateOrchestrator();

        // Act
        var (result, _, _) = await orchestrator.SignInWithPasswordAsync("test@example.com", "correct");

        // Assert: éxito → reset del scope.
        Assert.Equal(SignInResult.Success, result);
        var check = await _protection.CheckAsync(AccountProtectionScope.Password, "u1");
        Assert.True(check.Allowed);
        Assert.Equal(5, check.RemainingAttempts);
    }

    [Fact]
    public async Task SignInWithPasswordAsync_WithoutProtection_UsesLegacyLockoutPath()
    {
        // Arrange: orquestador SIN subsistema S1 (default, D-03).
        var orchestrator = new IdentityOrchestrator(
            _userStore,
            _passwordHasher,
            _tokenService,
            _sessionStore,
            new LockoutManager(_userStore, Options.Create(new SecureAuthOptions()), NullLogger<LockoutManager>.Instance),
            _eventDispatcher,
            Options.Create(new SecureAuthOptions { RefreshTokenLifetime = TimeSpan.FromDays(7) }),
            Options.Create(new MfaOptions { Enabled = false }),
            _mfaSessionStore,
            _mfaService,
            NullLogger<IdentityOrchestrator>.Instance);

        _userStore.FindByEmailAsync("test@example.com", Arg.Any<CancellationToken>()).Returns(CreateUser());
        _passwordHasher.VerifyPassword(Arg.Any<string>(), Arg.Any<string>()).Returns(PasswordVerificationResult.Failed);
        _userStore.IncrementFailedAccessCountAsync("u1", Arg.Any<CancellationToken>()).Returns(1);

        // Act
        var (result, _, _) = await orchestrator.SignInWithPasswordAsync("test@example.com", "wrong");

        // Assert: flujo legacy intacto (contador en DB).
        Assert.Equal(SignInResult.Failed, result);
        await _userStore.Received(1).IncrementFailedAccessCountAsync("u1", Arg.Any<CancellationToken>());
    }
}

/// <summary>
/// Tests de la integración de S1 en MfaOrchestrator.VerifyAsync (scope MfaLogin).
/// </summary>
public class MfaOrchestratorAccountProtectionTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly ITotpService _totpService = Substitute.For<ITotpService>();
    private readonly IEmailMfaService _emailMfaService = Substitute.For<IEmailMfaService>();
    private readonly IMfaCodeStore _mfaCodeStore = Substitute.For<IMfaCodeStore>();
    private readonly IMfaSessionStore _mfaSessionStore = Substitute.For<IMfaSessionStore>();
    private readonly IPasswordHasher _passwordHasher = Substitute.For<IPasswordHasher>();
    private readonly IMfaEncryptionService _encryptionService = Substitute.For<IMfaEncryptionService>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

    private const string UserId = "u1";
    private const string LockedMessage = "Demasiados intentos. Intente más tarde.";

    private UserIdentity EnrolledEmailUser(int failedAttempts = 0, DateTimeOffset? lockoutEnd = null) => new()
    {
        Id = UserId,
        Email = "test@example.com",
        PasswordHash = null,
        SecurityStamp = Guid.NewGuid().ToString(),
        MfaEnrollmentStatus = MfaEnrollmentStatus.Enrolled,
        PreferredMfaMethod = "email",
        MfaFailedAttemptsCount = failedAttempts,
        TotpSecretEncrypted = null,
        LockoutEnd = lockoutEnd
    };

    private MfaOrchestrator CreateOrchestrator(
        ManualTimeProvider clock,
        AccountProtectionOptions? protectionOptions = null,
        IAccountProtectionService? protection = null)
    {
        var mfaOptions = Options.Create(new MfaOptions
        {
            Enabled = true,
            AllowedMethods = new List<string> { "totp", "email" },
            MaxVerificationAttempts = 5,
            CodeRetryWindowMinutes = 3
        });

        return new MfaOrchestrator(
            _userStore,
            _totpService,
            _emailMfaService,
            _mfaCodeStore,
            _mfaSessionStore,
            _passwordHasher,
            _encryptionService,
            _eventDispatcher,
            mfaOptions,
            NullLogger<MfaOrchestrator>.Instance,
            protection,
            protectionOptions is null ? null : Options.Create(protectionOptions));
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_FifthInvalidCodeContractsLock_AndNextIsBlocked()
    {
        // Arrange
        var clock = new ManualTimeProvider(Start);
        var protectionOptions = new AccountProtectionOptions
        {
            Enabled = true,
            Window = TimeSpan.FromHours(1),
            EscalationDurations = [TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), TimeSpan.FromHours(1)]
        };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(EnrolledEmailUser());
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // Act: 5 códigos inválidos.
        for (var i = 0; i < 5; i++)
        {
            await orchestrator.VerifyAsync(UserId, "000000");
        }

        // Assert: el 5º activa el lockout escalonado nivel 1.
        var check = await protection.CheckAsync(AccountProtectionScope.MfaLogin, UserId);
        Assert.False(check.Allowed);
        Assert.Equal(1, check.EscalationLevel);
        Assert.InRange(check.LockEnd!.Value - clock.GetUtcNow(), TimeSpan.FromMinutes(9.9), TimeSpan.FromMinutes(10.1));

        // Con S1 no se toca la DB para contar fallos.
        await _userStore.DidNotReceiveWithAnyArgs().IncrementMfaFailedAttemptsAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());

        // M3: paridad de auditoría — un evento MfaVerificationFailed por cada intento fallido,
        // y el último (lockout) registra attempts == MaxVerificationAttempts.
        await _eventDispatcher.Received(5).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.MfaVerificationFailed),
            Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.MfaVerificationFailed
                && e.Metadata.ContainsKey("attempts") && e.Metadata["attempts"] == "5"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_NextAttemptAfterLockReturnsBlocked()
    {
        // Arrange
        var clock = new ManualTimeProvider(Start);
        var protectionOptions = new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(EnrolledEmailUser());
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // Act: 6 intentos inválidos (el 6º ya ve el lockout activo).
        MfaVerificationResult? last = null;
        for (var i = 0; i < 6; i++)
        {
            last = await orchestrator.VerifyAsync(UserId, "000000");
        }

        // Assert: mensaje genérico de bloqueo (anti-enumeración), sin detalle del lockout.
        Assert.NotNull(last);
        Assert.False(last!.Success);
        Assert.Equal(LockedMessage, last.ErrorMessage);
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_EscalatesToLevel2_AfterNextLockEpisodes()
    {
        // Arrange
        var clock = new ManualTimeProvider(Start);
        var protectionOptions = new AccountProtectionOptions
        {
            Enabled = true,
            Window = TimeSpan.FromHours(1),
            EscalationDurations = [TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), TimeSpan.FromHours(1)]
        };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(EnrolledEmailUser());
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // Primer episodio: 5 fallos → nivel 1 (10 min).
        for (var i = 0; i < 5; i++)
        {
            await orchestrator.VerifyAsync(UserId, "000000");
        }

        // El lockout de nivel 1 expira.
        clock.Advance(TimeSpan.FromMinutes(11));

        // Segundo episodio: 5 fallos → nivel 2 (30 min).
        for (var i = 0; i < 5; i++)
        {
            await orchestrator.VerifyAsync(UserId, "000000");
        }

        var check = await protection.CheckAsync(AccountProtectionScope.MfaLogin, UserId);
        Assert.False(check.Allowed);
        Assert.Equal(2, check.EscalationLevel);
        Assert.InRange(check.LockEnd!.Value - clock.GetUtcNow(), TimeSpan.FromMinutes(29.9), TimeSpan.FromMinutes(30.1));
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_ValidCodeResetsScope()
    {
        // Arrange
        var clock = new ManualTimeProvider(Start);
        var protectionOptions = new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(EnrolledEmailUser());
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        for (var i = 0; i < 3; i++)
        {
            await orchestrator.VerifyAsync(UserId, "000000");
        }

        // Ahora el código es válido → verificación exitosa.
        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>()).Returns(EnrolledEmailUser());
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await orchestrator.VerifyAsync(UserId, "123456");

        // Assert: éxito → reset del scope MfaLogin.
        Assert.True(result.Success);
        var check = await protection.CheckAsync(AccountProtectionScope.MfaLogin, UserId);
        Assert.True(check.Allowed);
        Assert.Equal(5, check.RemainingAttempts);
    }

    [Fact]
    public async Task VerifyAsync_WithoutProtection_UsesLegacyMfaLockout()
    {
        // Arrange: sin S1 → flujo legacy T8/T9 con contador en DB y CodeRetryWindowMinutes.
        var clock = new ManualTimeProvider(Start);
        var orchestrator = CreateOrchestrator(clock, protectionOptions: null, protection: null);

        var failedCount = 0;
        DateTimeOffset? lockedUntil = null;

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(_ => EnrolledEmailUser(failedCount, lockedUntil));
        _userStore.IncrementMfaFailedAttemptsAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(_ => ++failedCount);
        _userStore.SetLockoutEndAsync(UserId, Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                lockedUntil = ci.ArgAt<DateTimeOffset?>(1);
                return Task.CompletedTask;
            });
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // Act: 5 códigos inválidos (el 5º dispara el lockout legacy de 3 min).
        for (var i = 0; i < 5; i++)
        {
            await orchestrator.VerifyAsync(UserId, "000000");
        }

        var sixth = await orchestrator.VerifyAsync(UserId, "000000");

        // Assert
        Assert.Equal(LockedMessage, sixth.ErrorMessage);
        await _userStore.Received(5).IncrementMfaFailedAttemptsAsync(UserId, Arg.Any<CancellationToken>());
        await _userStore.Received(1).SetLockoutEndAsync(UserId, Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_HonorsPendingLegacyDbLock_DuringTransition()
    {
        // Arrange: M2 — con S1 activo, un lockout legacy en DB aún vigente (fijado antes de
        // habilitar S1 o por una instancia de una flota mixta) bloquea el login MFA.
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var protectionOptions = new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(EnrolledEmailUser(failedAttempts: 5, lockoutEnd: clock.GetUtcNow().AddMinutes(3)));
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true); // aunque el código fuera válido, el lockout pendiente manda.

        // Act
        var result = await orchestrator.VerifyAsync(UserId, "123456");

        // Assert: fail-closed en la transición (S1 ignora el scope MfaLogin porque no registró
        // ningún fallo, pero el lockout legacy pendiente sí bloquea.
        Assert.False(result.Success);
        Assert.Equal(LockedMessage, result.ErrorMessage);
        await _userStore.DidNotReceiveWithAnyArgs().SetLockoutEndAsync(Arg.Any<string>(), Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyAsync_WithProtection_ExpiredLegacyDbLock_SelfHealsAndProceeds()
    {
        // Arrange: M2 — un LockoutEnd legacy ya expirado se auto-resetea (T9) y el flujo continúa,
        // de modo que un bloqueo histórico no puede vetar la cuenta para siempre.
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var protectionOptions = new AccountProtectionOptions { Enabled = true, Window = TimeSpan.FromHours(1) };
        var protection = new InMemoryAccountProtectionService(Options.Create(protectionOptions), clock);
        var orchestrator = CreateOrchestrator(clock, protectionOptions, protection);

        _userStore.FindByIdAsync(UserId, Arg.Any<CancellationToken>())
            .Returns(EnrolledEmailUser(failedAttempts: 5, lockoutEnd: clock.GetUtcNow().AddMinutes(-1)));
        _mfaCodeStore.ValidateAndRemoveCodeAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        // Act
        var result = await orchestrator.VerifyAsync(UserId, "123456");

        // Assert: lockout expirado → reset en DB (T9) y verificación exitosa.
        Assert.True(result.Success);
        // T9 (reset por expiración) + reset por éxito del flujo = 2 llamadas.
        await _userStore.Received(2).ResetMfaFailedAttemptsAsync(UserId, Arg.Any<CancellationToken>());
        await _userStore.Received(1).SetLockoutEndAsync(UserId, Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }
}
