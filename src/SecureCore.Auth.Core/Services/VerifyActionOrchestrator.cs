using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador del step-up genérico (S3, A-22): verificación temporal de acciones sensibles.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Frente a un login completo, el step-up (verify-action) pide "una prueba de
/// identidad ADICIONAL" antes de una mutación sensible (crear/cambiar contraseña, abrir un
/// panel de administración, etc.). El flujo:
///
/// 1. <see cref="SendVerifyCodeAsync"/>: genera un OTP de un solo uso, persiste SOLO su hash
///    (nunca el texto plano) y lo entrega por el canal elegido.
/// 2. <see cref="VerifyActionAsync"/>: valida el OTP en tiempo constante (single-use atómico
///    vía S2) y marca la sesión como verify-action verificada sobre la ventana compartida
///    <c>SecureAuthOptions.MfaVerifiedTtl</c> (S3). El host consulta
///    <c>IMfaVerifiedSessionStore.IsVerifiedAsync</c> para decidir si la acción procede.
///
/// ANTI-ABUSO (S1): el scope <c>AccountProtectionScope.VerifyAction</c> limita tanto los
/// envíos (un envío = un intento contra el presupuesto) como los intentos de validación. El
/// presupuesto se renueva con un código validado correctamente (<c>RecordSuccessAsync</c>).
///
/// ANTI-ABUSO DURADO (H1, auditoría): además de S1, un throttle de envíos por usuario y ventana
/// (<c>VerifyActionOptions.MaxSendsPerWindow</c>, default 3) aplica SIEMPRE, incluso sin S1.
/// Sin esta red de seguridad, un atacante con sesión válida emitiría códigos sin límite y
/// brute-forcearía el OTP (~10^6 combinaciones). La verificación correcta también renueva el
/// throttle (paridad con el presupuesto S1). Al ser en memoria por instancia, con S1
/// distribuido conviene mantener ambos.
///
/// NO-ENUMERACIÓN: los fallos (usuario inexistente, canal no soportado, entrega fallida) se
/// reportan con mensajes genéricos; el perfil de respuesta es uniforme.
/// </remarks>
public sealed class VerifyActionOrchestrator(
    IUserStore userStore,
    IEmailOtpStore otpStore,
    IEmailOtpSender otpSender,
    IMfaVerifiedSessionStore mfaVerifiedSessionStore,
    IAuthEventDispatcher eventDispatcher,
    IOptions<VerifyActionOptions> verifyActionOptions,
    ILogger<VerifyActionOrchestrator> logger,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null)
{
    private readonly VerifyActionOptions _verifyActionOptions = verifyActionOptions.Value;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;

    /// <summary>
    /// Throttle duro de envíos por usuario (H1): ventana deslizante en memoria, siempre activa.
    /// </summary>
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _sendThrottles = new();

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    /// <summary>
    /// Envía el código OTP de verify-action al usuario autenticado.
    /// </summary>
    /// <param name="userId">ID del usuario que solicita la verificación.</param>
    /// <param name="channel">Canal de entrega (solo <see cref="VerifyActionChannel.Email"/> en esta versión).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Resultado explícito; los mensajes de error son genéricos (no-enumeración).</returns>
    public async Task<VerifyActionSendResult> SendVerifyCodeAsync(
        string userId,
        VerifyActionChannel channel = VerifyActionChannel.Email,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        if (channel != VerifyActionChannel.Email)
        {
            logger.LogDebug("Canal de verify-action no soportado solicitado por {UserId}", userId);
            return new VerifyActionSendResult(false, "El canal de verificación solicitado no está soportado.");
        }

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            // DIDÁCTICA: flujo autenticado — no divulgamos que el usuario no existe (genérico).
            logger.LogDebug("SendVerifyCode sin usuario para {UserId} (sin oráculo)", userId);
            return new VerifyActionSendResult(false, "No se pudo enviar el código de verificación.");
        }

        // DIDÁCTICA (H1): el throttle duro aplica antes que S1 y nunca depende del opt-in.
        // Barrera mínima contra la emisión ilimitada de códigos (brute-force del OTP y
        // email-flood). La ventana es TtlMinutes; el presupuesto es MaxSendsPerWindow.
        var now = DateTimeOffset.UtcNow;
        if (!TryAllowSend(userId, now))
        {
            logger.LogWarning("Envío de verify-action limitado por throttle duro ({Max} por ventana): {UserId}",
                _verifyActionOptions.MaxSendsPerWindow, userId);
            return new VerifyActionSendResult(false, "Demasiados intentos. Intente más tarde.");
        }

        if (AccountProtectionEnabled)
        {
            var check = await _accountProtection!.CheckAsync(AccountProtectionScope.VerifyAction, userId, cancellationToken);
            if (!check.Allowed)
            {
                logger.LogWarning("Envío de verify-action bloqueado por anti-abuso (nivel {Level}): {UserId}",
                    check.EscalationLevel, userId);
                return new VerifyActionSendResult(false, "Demasiados intentos. Intente más tarde.");
            }
        }

        var code = GenerateOtpCode(_verifyActionOptions.CodeLength);
        var ttl = TimeSpan.FromMinutes(_verifyActionOptions.TtlMinutes);

        try
        {
            await otpSender.SendAsync(user.Email, code, cancellationToken);
        }
        catch (Exception ex)
        {
            // DIDÁCTICA: un fallo de entrega (sender no configurado, SMTP caído…) NUNCA debe
            // filtrar detalles al cliente. Se reporta genérico y se audita por log.
            logger.LogError(ex, "Falló la entrega del OTP de verify-action para el usuario {UserId}", userId);
            return new VerifyActionSendResult(false, "No se pudo enviar el código de verificación.");
        }

        // DIDÁCTICA (M2, auditoría): SOLO tras una entrega satisfactoria persistimos el hash
        // y consumimos presupuesto. Antes, si el sender fallaba, quedaba un hash huérfano en
        // el store y no se registraba el intento fallido contra S1.
        await otpStore.StoreCodeHashAsync(CreateOtpKey(userId), ComputeHash(code), ttl, cancellationToken);

        // DIDÁCTICA (S1): cada envío consume una unidad del presupuesto de verify-action.
        // El límite de 5 (default) acota el bombardeo de emails (email-flood) sobre una cuenta.
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordFailureAsync(AccountProtectionScope.VerifyAction, userId, cancellationToken);
        }

        logger.LogInformation("OTP de verify-action enviado al usuario {UserId}", userId);
        return new VerifyActionSendResult(true);
    }

    /// <summary>
    /// Valida el código OTP de verify-action y marca la sesión como verificada (S3).
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="code">Código recibido por el canal.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// true si el código era válido (y no consumido): la sesión queda marcada como verify-action
    /// verificada dentro de <c>SecureAuthOptions.MfaVerifiedTtl</c>.
    /// </returns>
    public async Task<VerifyActionVerifyResult> VerifyActionAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(code);

        // DIDÁCTICA (H3): rechazo barato de códigos mal formados ANTES de tocar el hash/store.
        // Evita que un atacante force SHA-256/Redis con blobs gigantes y mantiene el perfil
        // de fallo indistinguible (no consume el presupuesto ni el OTP real).
        if (code.Length != _verifyActionOptions.CodeLength)
        {
            logger.LogDebug("Longitud de código de verify-action inválida para {UserId}", userId);
            return new VerifyActionVerifyResult(false, "Código inválido.");
        }

        if (AccountProtectionEnabled)
        {
            var check = await _accountProtection!.CheckAsync(AccountProtectionScope.VerifyAction, userId, cancellationToken);
            if (!check.Allowed)
            {
                logger.LogWarning("Verify-action bloqueado por anti-abuso (nivel {Level}): {UserId}",
                    check.EscalationLevel, userId);
                return new VerifyActionVerifyResult(false, "Demasiados intentos. Intente más tarde.");
            }
        }

        // DIDÁCTICA: consumo atómico single-use (S2). Fallo único e indistinguible para
        // código erróneo, expirado o ya consumido.
        var isValid = await otpStore.ValidateAndRemoveCodeAsync(CreateOtpKey(userId), code, cancellationToken);
        if (!isValid)
        {
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordFailureAsync(AccountProtectionScope.VerifyAction, userId, cancellationToken);
            }

            logger.LogWarning("OTP de verify-action inválido para el usuario {UserId}", userId);
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.MfaVerificationFailed,
                UserId = userId,
                Metadata = new Dictionary<string, string> { ["purpose"] = "verify_action" }
            }, cancellationToken);

            return new VerifyActionVerifyResult(false, "Código inválido.");
        }

        // DIDÁCTICA (S1): el código correcto renueva el presupuesto del scope verify-action
        // (el usuario demostró ser legítimo) y abre la ventana de sesión verificada.
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.VerifyAction, userId, cancellationToken);
        }

        // DIDÁCTICA (H1): paridad — una verificación correcta renueva también el throttle duro,
        // de modo que un usuario legítimo pueda volver a pedir código dentro de la ventana.
        _sendThrottles.TryRemove(userId, out _);

        await mfaVerifiedSessionStore.SetVerifiedAsync(userId, "email_otp", cancellationToken);

        logger.LogInformation("Verify-action exitoso para el usuario {UserId}", userId);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.MfaVerificationSuccess,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["purpose"] = "verify_action" }
        }, cancellationToken);

        return new VerifyActionVerifyResult(true);
    }

    private static string CreateOtpKey(string userId) => $"verify_action:{userId}";

    /// <summary>
    /// Throttle de envíos por usuario (H1): ventana deslizante en memoria, siempre activa.
    /// Devuelve true si el usuario aún tiene presupuesto de envíos para la ventana actual.
    /// </summary>
    private bool TryAllowSend(string userId, DateTimeOffset now)
    {
        var window = TimeSpan.FromMinutes(_verifyActionOptions.TtlMinutes);
        var maxSends = _verifyActionOptions.MaxSendsPerWindow;

        // DIDÁCTICA (auditoría): FAIL-CLOSED. Un host que construya opciones sin validación
        // ([Range]) con window<=0 o maxSends<=0 NO debe desactivar silenciosamente el throttle
        // duro de envíos (anti email-flood): ante configuración inválida se deniega el envío.
        if (window <= TimeSpan.Zero || maxSends <= 0)
        {
            return false;
        }

        var queue = _sendThrottles.GetOrAdd(userId, static _ => new Queue<DateTimeOffset>());

        lock (queue)
        {
            // DIDÁCTICA: purgamos las entradas que ya cayeron fuera de la ventana; así el
            // presupuesto "se recarga" de forma deslizante como en S1.
            var cutoff = now - window;
            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }

            if (queue.Count >= maxSends)
            {
                return false;
            }

            queue.Enqueue(now);
            return true;
        }
    }

    /// <summary>
    /// Genera un OTP numérico con CSPRNG y relleno a la longitud configurada.
    /// </summary>
    private static string GenerateOtpCode(int length)
    {
        // DIDÁCTICA: RandomNumberGenerator.GetInt32 evita el sesgo de Random.Next
        // (modulo bias) y la previsibilidad de la semilla temporal.
        var max = Enumerable.Range(0, length).Aggregate(1, (acc, _) => acc * 10);
        return RandomNumberGenerator.GetInt32(0, max).ToString($"D{length}");
    }

    private static string ComputeHash(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

/// <summary>
/// Adaptador por defecto de IEmailOtpSender que delega en IEmailService (S3).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Si el consumidor ya registró su IEmailService (para MFA o reset), este
/// adaptador lo reutiliza sin implementar nada nuevo. Si no registró ninguno, el default
/// NullEmailService lanzará al enviar y el orquestador reportará un fallo genérico
/// (nunca un 500 con detalles). Registre su implementación propia de IEmailOtpSender
/// ANTES de AddVerifyAction() para sobrescribirlo (TryAdd).
/// </remarks>
public sealed class EmailServiceEmailOtpSender(IEmailService emailService) : IEmailOtpSender
{
    /// <inheritdoc />
    public Task SendAsync(string email, string code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(code);

        return emailService.SendAsync(
            email,
            "Código de verificación",
            htmlBody: $"""<p>Tu código de verificación es: <strong>{code}</strong></p>""",
            textBody: $"Tu código de verificación es: {code}",
            cancellationToken);
    }
}
