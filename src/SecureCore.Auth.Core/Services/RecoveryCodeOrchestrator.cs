using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador de recovery codes de primera clase (F5, A-18/A-20): el mecanismo de
/// "último recurso" para entrar a la cuenta cuando el factor MFA habitual no está disponible.
/// </summary>
/// <remarks>
/// DIDÁCTICA (S5): antes de esta fase AuthCore GENERABA códigos de recuperación al enrollar
/// MFA (<c>MfaOrchestrator.CompleteEnrollmentAsync</c>) pero <c>VerifyAsync</c> jamás los
/// redimía (A-18): eran dead codes. Este orquestador convierte el flujo en completo:
///
///   generar → mostrar UNA VEZ → verificar (sin consumir) → usar (single-use atómico).
///
/// SEGURIDAD:
/// - El texto plano de un código existe únicamente en el resultado de
///   <see cref="GenerateAsync"/> (una sola vez). El store recibe siempre hashes SHA-256
///   (hex minúsculas), coherentes con <c>IUserStore.SetRecoveryCodesAsync</c>.
/// - El consumo es single-use atómico vía la primitiva S2 (GETDEL): reusar o replicar un
///   código es imposible, incluso en multi-instancia.
/// - ANTI-ENUMERACIÓN: verificar y usar devuelven resultados genéricos; el cliente jamás
///   distingue "código inexistente" vs "código ya consumido" vs "cuenta bloqueada".
///
/// ANTI-ABUSO (S1): el scope <c>AccountProtectionScope.Recovery</c> limita los intentos de
/// redimir códigos por cuenta (un fallo consume el presupuesto; un éxito lo renueva). Al
/// dispararse el lockout se emite <c>AccountLockedOut</c> con scope "recovery".
///
/// PATRÓN DE NEGOCIO: <see cref="UseAsync"/> consume el código y devuelve el evento
/// <c>RecoveryCodeRedeemed</c>. El host decide entonces si rota el SecurityStamp o revoca
/// sesiones (la redención de un recovery code puede significar "mi dispositivo MFA se perdió").
/// </remarks>
public sealed class RecoveryCodeOrchestrator(
    IRecoveryCodeStore recoveryCodeStore,
    ITotpService totpService,
    IAuthEventDispatcher eventDispatcher,
    IOperationLock operationLock,
    IOptions<MfaOptions> mfaOptions,
    ILogger<RecoveryCodeOrchestrator> logger,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null)
{
    private readonly MfaOptions _mfaOptions = mfaOptions.Value;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;

    /// <summary>
    /// DIDÁCTICA (F5, auditoría): timeout del lock de generación. La generación es una
    /// operación corta (escribe un lote de hashes); 5 s evita que una generación colisione
    /// con la anterior en regeneraciones concurrentes (doble clic) sin penalizar al host.
    /// </summary>
    private static readonly TimeSpan _operationLockTimeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    /// <summary>
    /// Indica si el mecanismo de recovery codes está disponible (MFA habilitado + opt-in).
    /// </summary>
    private bool RecoveryEnabled => _mfaOptions.Enabled && _mfaOptions.EnableRecoveryCodes;

    /// <summary>
    /// Genera un lote nuevo de recovery codes para la cuenta.
    /// </summary>
    /// <param name="userId">ID de la cuenta autenticada.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// Los códigos en texto plano SOLO aquí (una única vez); los hashes quedan persistidos en
    /// el store. Si el mecanismo está deshabilitado devuelve fallo con mensaje genérico.
    /// </returns>
    public async Task<RecoveryCodeGenerationResult> GenerateAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        if (!RecoveryEnabled)
        {
            logger.LogDebug("Generación de recovery codes rechazada: mecanismo deshabilitado ({UserId})", userId);
            return RecoveryCodeGenerationResult.Fail("Los códigos de recuperación no están habilitados.");
        }

        // DIDÁCTICA (B5, defensa en profundidad): aunque MfaOptions valida [Range(1,20)] en el
        // registro, un host puede construir las opciones sin validación; un count inválido NO
        // debe invalidar el lote anterior (dejaría al usuario sin códigos de emergencia).
        if (_mfaOptions.RecoveryCodeCount < 1)
        {
            logger.LogWarning(
                "Generación de recovery codes rechazada: RecoveryCodeCount inválido ({Count}) para {UserId}",
                _mfaOptions.RecoveryCodeCount, userId);
            return RecoveryCodeGenerationResult.Fail("Los códigos de recuperación no están habilitados.");
        }

        // DIDÁCTICA (B2, auditoría): la regeneración es read-modify-write sobre el índice del
        // usuario (invalidar + re-crear). Sin serializar, dos GenerateAsync concurrentes (doble
        // clic en "generar") intercalan lecturas/escrituras del índice y dejan un lote de tokens
        // S2 HUÉRFANOS (redimibles pero no indexados). El lock por usuario serializa el flujo:
        // la segunda generación espera, invalida el lote de la primera y crea el suyo.
        using var generateLock = await operationLock.AcquireAsync(
            $"recovery:generate:{userId}",
            _operationLockTimeout,
            cancellationToken);

        // DIDÁCTICA: regenerar reemplaza el lote anterior COMPLETO. Todo código viejo no
        // consumido deja de ser válido (invalidate del store). Un recovery code perdido o en
        // manos de otra persona queda así inutilizable al emitir uno nuevo.
        await recoveryCodeStore.InvalidatePendingAsync(userId, cancellationToken);

        var codes = totpService.GenerateRecoveryCodes(_mfaOptions.RecoveryCodeCount);
        foreach (var code in codes)
        {
            // DIDÁCTICA: solo el HASH conoce el store; el plaintext muere al terminar la
            // iteración. Coherente con el flujo legacy SetRecoveryCodesAsync (A-18).
            var hash = ComputeHash(code);
            await recoveryCodeStore.CreateAsync(userId, hash, cancellationToken);
        }

        logger.LogInformation("Se generaron {Count} recovery codes para el usuario {UserId}", codes.Count, userId);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.RecoveryCodesGenerated,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["count"] = codes.Count.ToString() }
        }, cancellationToken);

        return RecoveryCodeGenerationResult.Ok(codes);
    }

    /// <summary>
    /// Comprueba si un código es redimible SIN consumirlo (fase "verify" del flujo).
    /// </summary>
    /// <param name="userId">ID de la cuenta.</param>
    /// <param name="code">Código capturado por el usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tri-estado <c>Valid/AlreadyUsed/Invalid</c> (no consume el single-use).</returns>
    public async Task<RecoveryCodeVerificationResult> VerifyAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        if (!RecoveryEnabled)
        {
            return RecoveryCodeVerificationResult.FromStatus(RecoveryCodeStatus.Invalid);
        }

        // DIDÁCTICA (H3, patrón verify-action): rechazo barato ANTES de tocar hash/store;
        // con sesión verificado el atacante no debe poder forzar SHA-256 con blobs gigantes.
        if (code.Length > RecoveryCodeMaxLength)
        {
            logger.LogDebug("Longitud de código de recovery inválida para {UserId}", userId);
            return RecoveryCodeVerificationResult.FromStatus(RecoveryCodeStatus.Invalid);
        }

        if (AccountProtectionEnabled)
        {
            var check = await _accountProtection!.CheckAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
            if (!check.Allowed)
            {
                // DIDÁCTICA: ante lockout se responde genérico (Invalid) — no revelar el estado
                // de bloqueo en una consulta "verify". El ramo "use" sí lo informa (429).
                logger.LogWarning("Verify de recovery code bloqueado por anti-abuso (nivel {Level}): {UserId}",
                    check.EscalationLevel, userId);
                return RecoveryCodeVerificationResult.FromStatus(RecoveryCodeStatus.Invalid);
            }
        }

        var status = await recoveryCodeStore.GetStatusAsync(userId, ComputeHash(code), cancellationToken);
        if (status != RecoveryCodeStatus.Valid)
        {
            // DIDÁCTICA (S1): verificar con un código no válido es un intento fallido contra la
            // cuenta (permite brute-forcing). Se contabiliza en el presupuesto del scope Recovery.
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordFailureAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
            }

            logger.LogWarning("Verify de recovery code NO válido para el usuario {UserId} (estado {Status})",
                userId, status);
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.RecoveryCodeVerificationFailed,
                UserId = userId,
                Metadata = new Dictionary<string, string> { ["status"] = status.ToString() }
            }, cancellationToken);
            return RecoveryCodeVerificationResult.FromStatus(status);
        }

        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
        }

        logger.LogInformation("Verify de recovery code válido para el usuario {UserId}", userId);
        return RecoveryCodeVerificationResult.FromStatus(RecoveryCodeStatus.Valid);
    }

    /// <summary>
    /// Consume un recovery code de forma atómica (single-use) y emite el evento
    /// <c>RecoveryCodeRedeemed</c>.
    /// </summary>
    /// <param name="userId">ID de la cuenta.</param>
    /// <param name="code">Código a redimir.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// <c>Ok</c> si se consumió; <c>Blocked</c> si la cuenta está en lockout por anti-abuso;
    /// <c>Failed</c> con mensaje genérico si el código es inválido, expiró o ya fue usado.
    /// </returns>
    public async Task<RecoveryCodeUseResult> UseAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        if (!RecoveryEnabled)
        {
            return RecoveryCodeUseResult.Failed("Código inválido.");
        }

        if (code.Length > RecoveryCodeMaxLength)
        {
            logger.LogDebug("Longitud de código de recovery inválida para {UserId}", userId);
            return RecoveryCodeUseResult.Failed("Código inválido.");
        }

        if (AccountProtectionEnabled)
        {
            var check = await _accountProtection!.CheckAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
            if (!check.Allowed)
            {
                logger.LogWarning("Redención de recovery code bloqueada por anti-abuso (nivel {Level}): {UserId}",
                    check.EscalationLevel, userId);
                return RecoveryCodeUseResult.Blocked();
            }
        }

        var redeemed = await recoveryCodeStore.RedeemAsync(userId, ComputeHash(code), cancellationToken);
        if (!redeemed)
        {
            // DIDÁCTICA (S1): un fallo de redención (código erróneo, expirado, ya consumido o
            // jamás emitido) es indistinguible para el cliente PERO consume el presupuesto de
            // la cuenta. Si el fallo dispara el lockout, se audita con AccountLockedOut.
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordFailureAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
                var post = await _accountProtection!.CheckAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
                if (!post.Allowed)
                {
                    logger.LogWarning("Cuenta {UserId} bloqueada por intentos fallidos de recovery codes", userId);
                    await eventDispatcher.DispatchAsync(new AuthEvent
                    {
                        EventType = AuthEventType.AccountLockedOut,
                        UserId = userId,
                        Metadata = new Dictionary<string, string>
                        {
                            ["reason"] = "lock_triggered",
                            ["scope"] = "recovery"
                        }
                    }, cancellationToken);

                    return RecoveryCodeUseResult.Blocked();
                }
            }

            logger.LogWarning("Redención de recovery code fallida para el usuario {UserId}", userId);
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.RecoveryCodeRedemptionFailed,
                UserId = userId
            }, cancellationToken);
            return RecoveryCodeUseResult.Failed("Código inválido.");
        }

        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.Recovery, userId, cancellationToken);
        }

        logger.LogInformation("Recovery code redimido para el usuario {UserId}", userId);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.RecoveryCodeRedeemed,
            UserId = userId
        }, cancellationToken);

        return RecoveryCodeUseResult.Ok();
    }

    /// <summary>
    /// Tope de longitud aceptado para un código (un recovery code generado por el framework
    /// son 32 caracteres hex; el margen cubre futuros formatos sin abrir el DoS por payload).
    /// </summary>
    private const int RecoveryCodeMaxLength = 128;

    /// <summary>
    /// Hash SHA-256 en hex minúsculas (64 caracteres), coherente con el flujo legacy
    /// <c>IUserStore.SetRecoveryCodesAsync</c> de <see cref="MfaOrchestrator"/>.
    /// </summary>
    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
