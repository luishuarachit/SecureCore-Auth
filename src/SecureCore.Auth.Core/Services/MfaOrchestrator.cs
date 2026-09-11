using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador principal de MFA.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este orquestador sigue el patrón de IdentityOrchestrator - no
/// implementa lógica de bajo nivel (TOTP, cifrado), sino que coordina los
/// servicios para ejecutar flujos complejos de enrollment y verificación.
///
/// PRINCIPIOS DE SEGURIDAD:
/// 1. Anti-enumeración: No revelar si un usuario tiene MFA activo en endpoints públicos
/// 2. Rate limiting: Limitar intentos de verificación (configurable en MfaOptions)
/// 3. Tiempo constante: Usar CryptographicOperations.FixedTimeEquals para comparaciones
/// 4. Logging: Registrar eventos de seguridad (enrollment, verificación, fallos)
/// 5. Cifrado: El secreto TOTP se almacena cifrado con AES-256-GCM
///
/// FLUJO DE ENROLLMENT:
/// 1. StartEnrollmentAsync: Genera secreto TOTP o código email, crea token de sesión
/// 2. CompleteEnrollmentAsync: Verifica código inicial, guarda configuración
///
/// FLUJO DE LOGIN CON MFA:
/// 1. SignInWithPasswordAsync: Si requiere MFA, retorna mfaSessionToken
/// 2. CompleteMfaLoginAsync: Verifica código MFA, genera tokens de acceso
/// </remarks>
public sealed class MfaOrchestrator(
    IUserStore userStore,
    ITotpService totpService,
    IEmailMfaService emailMfaService,
    IMfaCodeStore mfaCodeStore,
    IMfaSessionStore mfaSessionStore,
    IPasswordHasher passwordHasher,
    IMfaEncryptionService encryptionService,
    IAuthEventDispatcher eventDispatcher,
    IOptions<MfaOptions> options,
    ILogger<MfaOrchestrator> logger,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null) : IMfaService
{
    private readonly IUserStore _userStore = userStore;
    private readonly ITotpService _totpService = totpService;
    private readonly IEmailMfaService _emailMfaService = emailMfaService;
    private readonly IMfaCodeStore _mfaCodeStore = mfaCodeStore;
    private readonly IMfaSessionStore _mfaSessionStore = mfaSessionStore;
    private readonly IPasswordHasher _passwordHasher = passwordHasher;
    private readonly IMfaEncryptionService _encryptionService = encryptionService;
    private readonly IAuthEventDispatcher _eventDispatcher = eventDispatcher;
    private readonly MfaOptions _options = options.Value;
    private readonly ILogger<MfaOrchestrator> _logger = logger;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;

    /// <summary>
    /// Ventana de tolerancia TOTP (±1 paso de 30s = 60s) durante la cual un código
    /// ya usado no puede reutilizarse en el enrollment.
    /// </summary>
    private const int TotpReuseWindowSeconds = 60;

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    public async Task<MfaEnrollmentResponse> StartEnrollmentAsync(
        string userId,
        MfaMethod method,
        CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            throw new ArgumentException("Usuario no encontrado", nameof(userId));

        if (!_options.AllowUserEnrollment)
            throw new InvalidOperationException("El enrollment de MFA está deshabilitado.");

        if (!_options.AllowedMethods.Contains(method.ToString().ToLowerInvariant()))
            throw new InvalidOperationException($"Método MFA '{method}' no está permitido.");

        // S3 (P3): Proteger el secreto contra overwrite. Un usuario ya enrolado no
        // puede ser re-enrolado sin deshabilitar MFA primero (evita que un atacante
        // con acceso a StartEnrollmentAsync sobrescriba el secreto TOTP activo con
        // uno que él controla y luego lo complete con un código que él mismo genera).
        if (user.MfaEnrollmentStatus == MfaEnrollmentStatus.Enrolled)
        {
            throw new InvalidOperationException(
                "El usuario ya tiene MFA activo. Deshabilite MFA antes de re-enrolar.");
        }

        // T4 (P3): Si ya hay un enrollment pendiente con un secreto TOTP generado,
        // no sobrescribirlo. Evita el race de enrollments solapados: un segundo
        // StartEnrollmentAsync invalidaría el QR que el usuario legítimo está
        // escaneando (y permitiría a un atacante completar el flujo con un secreto
        // que él controla).
        if (user.MfaEnrollmentStatus == MfaEnrollmentStatus.Pending &&
            !string.IsNullOrEmpty(user.TotpSecretEncrypted))
        {
            throw new InvalidOperationException(
                "El usuario ya tiene un enrollment MFA pendiente. Complete el enrollment actual antes de iniciar otro.");
        }

        string? authUri = null;
        string? emailCode = null;
        string? secretFingerprint = null;

        switch (method)
        {
            case MfaMethod.Totp:
                var secret = _totpService.GenerateSecret();
                authUri = _totpService.GenerateAuthUri(secret, user.Email, _options.TotpIssuer);

                var encryptedSecret = _encryptionService.Encrypt(secret);
                await _userStore.SetTotpSecretAsync(userId, encryptedSecret, cancellationToken);
                await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Pending, "totp", cancellationToken);

                // T5 (P3): Fingerprint del secreto para validar en la completación que
                // el secreto no cambió desde el inicio del enrollment (anti-race/TOCTOU).
                secretFingerprint = ComputeHash(secret);
                break;

            case MfaMethod.Email:
                emailCode = _emailMfaService.GenerateCode(_options.EmailCodeLength);
                await _emailMfaService.SendCodeAsync(user.Email, emailCode, cancellationToken);

                // DIDÁCTICA: Almacenamos el hash SHA-256 del código en caché
                // para poder validarlo después. El código se elimina tras el primer
                // intento de validación (single-use).
                var emailCodeHash = ComputeHash(emailCode);
                var codeKey = GetEmailCodeKey(userId);
                await _mfaCodeStore.StoreCodeHashAsync(
                    codeKey,
                    emailCodeHash,
                    TimeSpan.FromMinutes(_options.EmailCodeLifetimeMinutes),
                    cancellationToken);

                await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Pending, "email", cancellationToken);
                break;

            default:
                throw new ArgumentException($"Método MFA '{method}' no soportado.");
        }

        var mfaToken = await _mfaSessionStore.CreateMfaSessionTokenAsync(
            userId, method.ToString(), _options.MfaSessionTokenMinutes, secretFingerprint, cancellationToken);

        _logger.LogInformation("Enrollment MFA iniciado para usuario {UserId}, método: {Method}", userId, method);

        return new MfaEnrollmentResponse(method, authUri, mfaToken);
    }

    public async Task<bool> CompleteEnrollmentAsync(
        string userId,
        string code,
        string mfaSessionToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(mfaSessionToken);

        // S2 (P2): Vincular el enrollment al token de sesión. Solo quien inició el
        // enrollment (recibió el mfaSessionToken de StartEnrollmentAsync) puede
        // completarlo. Validamos y consumimos (single-use) como hace el login.
        var tokenUserId = await _mfaSessionStore.ValidateMfaSessionTokenAsync(mfaSessionToken, cancellationToken);
        if (tokenUserId is null || !string.Equals(tokenUserId, userId, StringComparison.Ordinal))
        {
            _logger.LogWarning("Enrollment MFA rechazado: token de sesión inválido o de otro usuario");
            return false;
        }

        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return false;

        if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Pending)
            return false;

        // T7 (P4): Límite de intentos de verificación de enrollment (mismo control
        // que VerifyAsync). Evita fuerza bruta sobre el código de enrollment.
        if (user.MfaFailedAttemptsCount >= _options.MaxVerificationAttempts)
        {
            // T8/T9 (P5): Lockout temporal (no permanente). Si la ventana expiró,
            // se resetea el contador y se permite reintentar.
            var lockedOut = await IsMfaLockedOutAsync(user, userId, cancellationToken);
            if (lockedOut)
            {
                _logger.LogWarning("Usuario {UserId} bloqueado temporalmente por enrollment MFA", userId);
                return false;
            }
        }

        var method = user.PreferredMfaMethod?.ToLowerInvariant() ?? "totp";
        bool isValid;

        if (method == "totp")
        {
            if (string.IsNullOrEmpty(user.TotpSecretEncrypted))
                return false;

            var secret = _encryptionService.Decrypt(user.TotpSecretEncrypted);

            // T5 (P3): Validar que el secreto no cambió desde que se inició el enrollment.
            // El token contiene el fingerprint del secreto al momento del Start. Si el
            // secreto fue sobrescrito entre Start y Complete (enrollment concurrente /
            // TOCTOU), el fingerprint no coincide y se rechaza la completación.
            var tokenFingerprint = await _mfaSessionStore.GetMfaSessionTokenFingerprintAsync(mfaSessionToken, cancellationToken);
            var currentFingerprint = ComputeHash(secret);
            if (!string.IsNullOrEmpty(tokenFingerprint) &&
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(tokenFingerprint),
                    Encoding.ASCII.GetBytes(currentFingerprint)))
            {
                _logger.LogWarning("Enrollment MFA rechazado: el secreto TOTP cambió durante el enrollment para usuario {UserId}", userId);
                return false;
            }

            // T6 (P4): Single-use del código TOTP dentro de la ventana de tolerancia.
            // Si el código ya fue usado para completar el enrollment, se rechaza el reuso.
            var totpUsedKey = GetTotpUsedCodeKey(userId);
            if (await _mfaCodeStore.ValidateAndRemoveCodeAsync(totpUsedKey, code, cancellationToken))
            {
                _logger.LogWarning("Enrollment MFA rechazado: código TOTP reutilizado para usuario {UserId}", userId);
                return false;
            }

            isValid = _totpService.ValidateCode(secret, code);
        }
        else if (method == "email")
        {
            var codeKey = GetEmailCodeKey(userId);
            isValid = await _mfaCodeStore.ValidateAndRemoveCodeAsync(codeKey, code, cancellationToken);
        }
        else
        {
            return false;
        }

        if (!isValid)
        {
            // T7 (P4): Incrementar el contador de intentos fallidos de enrollment.
            var newCount = await _userStore.IncrementMfaFailedAttemptsAsync(userId, cancellationToken);
            _logger.LogWarning("Código de enrollment MFA inválido para usuario {UserId}, intentos: {Count}", userId, newCount);

            // T8 (P5): Bloquear temporalmente al alcanzar el máximo de intentos.
            await ApplyMfaLockoutIfNeededAsync(newCount, userId, user.LockoutEnd, cancellationToken);
            return false;
        }

        // T6 (P4): Marcar el código TOTP como usado (single-use dentro de la ventana).
        if (method == "totp")
        {
            await _mfaCodeStore.StoreCodeHashAsync(
                GetTotpUsedCodeKey(userId),
                ComputeHash(code),
                TimeSpan.FromSeconds(TotpReuseWindowSeconds),
                cancellationToken);
        }

        // T7 (P4): Resetear el contador de intentos fallidos al completar con éxito.
        await _userStore.ResetMfaFailedAttemptsAsync(userId, cancellationToken);

        // Consumir el token de sesión (single-use) para que no pueda reutilizarse.
        await _mfaSessionStore.ConsumeMfaSessionTokenAsync(mfaSessionToken, cancellationToken);

        await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Enrolled, method, cancellationToken);

        // DIDÁCTICA (auditoría F5): el enrollment legacy YA NO genera recovery codes aquí. El
        // bloque anterior escribía hashes en IUserStore.SetRecoveryCodesAsync que NADIE redimía
        // (A-18) y descartaba el texto plano (el método retorna bool, el usuario jamás veía los
        // códigos): funcionalidad rota + orfanato. La solución real es
        // RecoveryCodeOrchestrator.GenerateAsync (F5), que SÍ devuelve el plaintext una sola vez
        // y persiste solo hashes con su propio store de redención.

        _logger.LogInformation("Enrollment MFA completado para usuario {UserId}, método: {Method}", userId, method);

        await _eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
        {
            EventType = Abstractions.Models.AuthEventType.MfaEnrolled,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["method"] = method }
        }, cancellationToken);

        return true;
    }

    public async Task<MfaVerificationResult> VerifyAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return new MfaVerificationResult(false, "Usuario no encontrado", null);
        }

        if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Enrolled)
        {
            return new MfaVerificationResult(false, "MFA no está activo", null);
        }

        // DIDÁCTICA (S1): Anti-abuso por cuenta — scope MfaLogin, escalonado. Si el subsistema
        // está registrado y habilitado, reemplaza el contador en DB (T8/T9 con
        // CodeRetryWindowMinutes fijo). El fallback legacy se conserva cuando no.
        if (AccountProtectionEnabled)
        {
            var protectionCheck = await _accountProtection!.CheckAsync(AccountProtectionScope.MfaLogin, userId, cancellationToken);
            if (!protectionCheck.Allowed)
            {
                _logger.LogWarning("Usuario {UserId} bloqueado por anti-abuso MFA (nivel {Level})",
                    userId, protectionCheck.EscalationLevel);
                return new MfaVerificationResult(false, "Demasiados intentos. Intente más tarde.", null);
            }

            // Transición legacy→S1: honorar un lockout en DB aún activo (fijado antes de habilitar
            // S1 o por una instancia de una flota mixta). Se auto-resetea al expirar (T9), por lo
            // que no puede bloquear para siempre; sin este control, habilitar S1 destraba cuentas
            // que el legacy había bloqueado (fail-open de transición).
            if (user.MfaFailedAttemptsCount >= _options.MaxVerificationAttempts)
            {
                var lockedOut = await IsMfaLockedOutAsync(user, userId, cancellationToken);
                if (lockedOut)
                {
                    _logger.LogWarning("Usuario {UserId} bloqueado temporalmente por verificación MFA (transición legacy)", userId);
                    return new MfaVerificationResult(false, "Demasiados intentos. Intente más tarde.", null);
                }
            }
        }
        else if (user.MfaFailedAttemptsCount >= _options.MaxVerificationAttempts)
        {
            // T8/T9 (P5): Lockout temporal (no permanente). Si la ventana expiró,
            // se resetea el contador y se permite reintentar.
            var lockedOut = await IsMfaLockedOutAsync(user, userId, cancellationToken);
            if (lockedOut)
            {
                _logger.LogWarning("Usuario {UserId} bloqueado temporalmente por verificación MFA", userId);
                return new MfaVerificationResult(false, "Demasiados intentos. Intente más tarde.", null);
            }
        }

        var method = user.PreferredMfaMethod?.ToLowerInvariant() ?? "totp";
        bool isValid;

        if (method == "totp")
        {
            if (string.IsNullOrEmpty(user.TotpSecretEncrypted))
            {
                return new MfaVerificationResult(false, "Configuración MFA inválida", null);
            }

            // T6 (P4): Single-use del código TOTP dentro de la ventana de tolerancia.
            // Evita reutilizar un código capturado para re-verificar el login.
            var totpUsedKey = GetTotpUsedCodeKey(userId);
            if (await _mfaCodeStore.ValidateAndRemoveCodeAsync(totpUsedKey, code, cancellationToken))
            {
                _logger.LogWarning("Verificación MFA rechazada: código TOTP reutilizado para usuario {UserId}", userId);
                return new MfaVerificationResult(false, "Código inválido", null);
            }

            var secret = _encryptionService.Decrypt(user.TotpSecretEncrypted);
            isValid = _totpService.ValidateCode(secret, code);
        }
        else if (method == "email")
        {
            var codeKey = GetEmailCodeKey(userId);
            isValid = await _mfaCodeStore.ValidateAndRemoveCodeAsync(codeKey, code, cancellationToken);
        }
        else
        {
            return new MfaVerificationResult(false, "Método MFA no soportado", null);
        }

        if (!isValid)
        {
            // DIDÁCTICA (S1): con anti-abuso habilitado se registra el fallo en el subsistema
            // (scope MfaLogin, escalonado). Si este fallo dispara el lockout, se responde
            // genéricamente sin enumeración. Sin S1 se conserva el flujo legacy T8/T9.
            await RegisterMfaVerificationFailureAsync(user, userId, method, isProtectionEnabled: AccountProtectionEnabled, cancellationToken);
            return new MfaVerificationResult(false, "Código inválido", null);
        }

        // T6 (P4): Marcar el código TOTP como usado (single-use dentro de la ventana).
        if (method == "totp")
        {
            await _mfaCodeStore.StoreCodeHashAsync(
                GetTotpUsedCodeKey(userId),
                ComputeHash(code),
                TimeSpan.FromSeconds(TotpReuseWindowSeconds),
                cancellationToken);
        }

        await _userStore.ResetMfaFailedAttemptsAsync(userId, cancellationToken);

        // DIDÁCTICA (S1): éxito → reset del scope MfaLogin (limpieza del anti-abuso).
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.MfaLogin, userId, cancellationToken);
        }

        _logger.LogInformation("Verificación MFA exitosa para usuario {UserId}, método: {Method}", userId, method);

        await _eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
        {
            EventType = Abstractions.Models.AuthEventType.MfaVerificationSuccess,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["method"] = method }
        }, cancellationToken);

        return new MfaVerificationResult(true, null, Enum.Parse<MfaMethod>(method, true));
    }

    public async Task<bool> DisableAsync(
        string userId,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (!_options.AllowUserDisable)
            throw new InvalidOperationException("La deshabilitación de MFA está deshabilitada.");

        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return false;

        // Permite "cancelar" un enrollment pendiente (T4): si el token de sesión del
        // enrollment expiró (5 min por defecto) o el usuario abandonó el flujo, no debe
        // quedar atascado en Pending sin forma de salir. Deshabilitar desde Pending
        // cancela el enrollment y permite iniciar uno nuevo.
        if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Enrolled &&
            user.MfaEnrollmentStatus != MfaEnrollmentStatus.Pending)
            return false;

        // DIDÁCTICA: Solo verificamos la contraseña si el usuario realmente tiene una.
        // Usuarios registrados vía OAuth (Google, Microsoft, etc.) no tienen contraseña
        // (PasswordHash es null). Exigirles contraseña impediría deshabilitar MFA.
        // Para usuarios con contraseña, SIEMPRE se requiere verificarla.
        if (user.PasswordHash is not null)
        {
            if (string.IsNullOrEmpty(password))
            {
                _logger.LogWarning("Intento de deshabilitar MFA sin contraseña para usuario {UserId} que sí tiene password", userId);
                return false;
            }

            var verificationResult = _passwordHasher.VerifyPassword(user.PasswordHash, password);
            if (verificationResult == Abstractions.Interfaces.PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Intento de deshabilitar MFA con contraseña incorrecta para usuario {UserId}", userId);
                return false;
            }
        }

        await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Disabled, null, cancellationToken);

        _logger.LogInformation("MFA deshabilitado para usuario {UserId}", userId);

        await _eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
        {
            EventType = Abstractions.Models.AuthEventType.MfaDisabled,
            UserId = userId
        }, cancellationToken);

        return true;
    }

    public async Task<List<MfaMethodInfo>> GetUserMethodsAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return [];

        var methods = new List<MfaMethodInfo>();

        if (_options.AllowedMethods.Contains("totp"))
        {
            var isEnrolled = user.MfaEnrollmentStatus == MfaEnrollmentStatus.Enrolled &&
                             user.PreferredMfaMethod == "totp";
            methods.Add(new MfaMethodInfo(MfaMethod.Totp, "Authenticator (TOTP)", isEnrolled));
        }

        if (_options.AllowedMethods.Contains("email"))
        {
            var isEnrolled = user.MfaEnrollmentStatus == MfaEnrollmentStatus.Enrolled &&
                             user.PreferredMfaMethod == "email";
            methods.Add(new MfaMethodInfo(MfaMethod.Email, "Código por email", isEnrolled));
        }

        return methods;
    }

    /// <summary>
    /// Obtiene los métodos MFA disponibles para enrollment.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método devuelve los métodos que el usuario puede configurar.
    /// NO revela si el usuario ya tiene MFA activo (anti-enumeración).
    /// El frontend debe usar SignInWithPasswordAsync para determinar si se requiere MFA.
    /// </remarks>
    public List<MfaMethodInfo> GetAvailableMethodsForEnrollment()
    {
        var methods = new List<MfaMethodInfo>();

        if (_options.AllowedMethods.Contains("totp"))
        {
            methods.Add(new MfaMethodInfo(MfaMethod.Totp, "Authenticator (TOTP)", false));
        }

        if (_options.AllowedMethods.Contains("email"))
        {
            methods.Add(new MfaMethodInfo(MfaMethod.Email, "Código por email", false));
        }

        return methods;
    }

    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Genera la clave de caché para un código MFA de email.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: La clave incluye el userId para aislamiento entre usuarios.
    /// Cada nuevo enrollment sobrescribe el código anterior, y la validación
    /// elimina el código de la caché (single-use).
    /// </remarks>
    private static string GetEmailCodeKey(string userId)
    {
        return $"mfa_email_code:{userId}";
    }

    /// <summary>
    /// Genera la clave de caché para el código TOTP ya usado en el enrollment.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Evita el reuso del mismo código TOTP dentro de la ventana de
    /// tolerancia (±1 paso). La clave incluye el userId para aislamiento entre usuarios.
    /// </remarks>
    private static string GetTotpUsedCodeKey(string userId)
    {
        return $"mfa_totp_used_code:{userId}";
    }

    /// <summary>
    /// Registra un fallo de verificación MFA. Con S1 habilitado usa el subsistema de
    /// anti-abuso (scope MfaLogin, escalonado); sin S1 conserva el flujo legacy T8/T9
    /// (contador en DB + bloqueo con CodeRetryWindowMinutes).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Cuando el fallo activa un lockout (alcanza el máximo del scope) no se
    /// informa al cliente de otra forma que el mensaje genérico "Código inválido" (el
    /// siguiente intento verá el bloqueo). Esto evita dar feedback de cuándo se bloquea
    /// la cuenta. El evento MfaVerificationFailed se emite en CADA intento fallido en
    /// ambos caminos (paridad de auditoría con el legacy).
    /// </remarks>
    private async Task RegisterMfaVerificationFailureAsync(
        UserIdentity user,
        string userId,
        string method,
        bool isProtectionEnabled,
        CancellationToken cancellationToken)
    {
        if (isProtectionEnabled)
        {
            await _accountProtection!.RecordFailureAsync(AccountProtectionScope.MfaLogin, userId, cancellationToken);

            var protectionCheck = await _accountProtection.CheckAsync(AccountProtectionScope.MfaLogin, userId, cancellationToken);

            // Paridad de auditoría con el legacy: un evento por intento fallido. Cuando el
            // fallo dispara el lockout (RemainingAttempts == 0) se registra el máximo.
            await _eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
            {
                EventType = Abstractions.Models.AuthEventType.MfaVerificationFailed,
                UserId = userId,
                Metadata = new Dictionary<string, string>
                {
                    ["method"] = method,
                    ["attempts"] = protectionCheck.Allowed
                        ? protectionCheck.RemainingAttempts.ToString()
                        : _options.MaxVerificationAttempts.ToString()
                }
            }, cancellationToken);

            if (protectionCheck.Allowed)
            {
                return;
            }

            _logger.LogWarning("Usuario {UserId} bloqueado por anti-abuso MFA tras exceder intentos (nivel {Level})",
                userId, protectionCheck.EscalationLevel);

            return;
        }

        var newCount = await _userStore.IncrementMfaFailedAttemptsAsync(userId, cancellationToken);
        _logger.LogWarning("Verificación MFA fallida para usuario {UserId}, intentos: {Count}", userId, newCount);

        // T8 (P5): Bloquear temporalmente al alcanzar el máximo de intentos.
        await ApplyMfaLockoutIfNeededAsync(newCount, userId, user.LockoutEnd, cancellationToken);

        await _eventDispatcher.DispatchAsync(new Abstractions.Models.AuthEvent
        {
            EventType = Abstractions.Models.AuthEventType.MfaVerificationFailed,
            UserId = userId,
            Metadata = new Dictionary<string, string>
            {
                ["method"] = method,
                ["attempts"] = newCount.ToString()
            }
        }, cancellationToken);
    }

    /// <summary>
    /// T8/T9 (P5): Determina si el usuario está temporalmente bloqueado por
    /// exceder los intentos de verificación MFA.
    /// </summary>
    /// <returns>
    /// true si el lockout está activo (bloqueado). false si no hay lockout o si
    /// la ventana de <c>CodeRetryWindowMinutes</c> ya expiró (en cuyo caso se
    /// resetea el contador y se desbloquea, T9).
    /// </returns>
    private async Task<bool> IsMfaLockedOutAsync(
        UserIdentity user,
        string userId,
        CancellationToken cancellationToken)
    {
        // Sin lockout previo → no bloqueado
        if (user.LockoutEnd is null)
            return false;

        // Lockout activo → bloqueado temporalmente
        if (user.LockoutEnd > DateTimeOffset.UtcNow)
            return true;

        // Lockout expirado → resetear contador y desbloquear (T9)
        _logger.LogInformation("Ventana de reintentos MFA expirada para usuario {UserId}. Reset de contador.", userId);
        await _userStore.ResetMfaFailedAttemptsAsync(userId, cancellationToken);
        await _userStore.SetLockoutEndAsync(userId, null, cancellationToken);
        return false;
    }

    /// <summary>
    /// T8 (P5): Aplica el lockout temporal (LockoutEnd = UtcNow + CodeRetryWindowMinutes)
    /// cuando el contador de intentos fallidos alcanza <c>MaxVerificationAttempts</c>.
    /// </summary>
    /// <remarks>
    /// No sobrescribe un lockout activo existente (p.ej. el lockout de contraseña
    /// gestionado por LockoutManager) para no acortarlo. Si el usuario ya está
    /// bloqueado, se conserva el lockout existente.
    /// </remarks>
    private async Task ApplyMfaLockoutIfNeededAsync(
        int newFailedCount,
        string userId,
        DateTimeOffset? currentLockoutEnd,
        CancellationToken cancellationToken)
    {
        if (newFailedCount < _options.MaxVerificationAttempts)
            return;

        // No sobrescribir un lockout activo existente (no acortar el de contraseña).
        if (currentLockoutEnd is not null && currentLockoutEnd > DateTimeOffset.UtcNow)
            return;

        var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(_options.CodeRetryWindowMinutes);
        await _userStore.SetLockoutEndAsync(userId, lockoutEnd, cancellationToken);
        _logger.LogWarning(
            "Usuario {UserId} bloqueado temporalmente por {Minutes} minutos tras exceder intentos MFA",
            userId,
            _options.CodeRetryWindowMinutes);
    }
}
