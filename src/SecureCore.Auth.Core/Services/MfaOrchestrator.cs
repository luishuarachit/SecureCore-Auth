using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
public sealed class MfaOrchestrator : IMfaService
{
    private readonly IUserStore _userStore;
    private readonly ITotpService _totpService;
    private readonly IEmailMfaService _emailMfaService;
    private readonly IMfaSessionStore _mfaSessionStore;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IMfaEncryptionService _encryptionService;
    private readonly IAuthEventDispatcher _eventDispatcher;
    private readonly MfaOptions _options;
    private readonly ILogger<MfaOrchestrator> _logger;

    public MfaOrchestrator(
        IUserStore userStore,
        ITotpService totpService,
        IEmailMfaService emailMfaService,
        IMfaSessionStore mfaSessionStore,
        IPasswordHasher passwordHasher,
        IMfaEncryptionService encryptionService,
        IAuthEventDispatcher eventDispatcher,
        IOptions<MfaOptions> options,
        ILogger<MfaOrchestrator> logger)
    {
        _userStore = userStore;
        _totpService = totpService;
        _emailMfaService = emailMfaService;
        _mfaSessionStore = mfaSessionStore;
        _passwordHasher = passwordHasher;
        _encryptionService = encryptionService;
        _eventDispatcher = eventDispatcher;
        _options = options.Value;
        _logger = logger;
    }

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

        var mfaToken = await _mfaSessionStore.CreateMfaSessionTokenAsync(
            userId, method.ToString(), _options.MfaSessionTokenMinutes, cancellationToken);

        string? authUri = null;
        string? emailCode = null;

        switch (method)
        {
            case MfaMethod.Totp:
                var secret = _totpService.GenerateSecret();
                authUri = _totpService.GenerateAuthUri(secret, user.Email, _options.TotpIssuer);

                var encryptedSecret = _encryptionService.Encrypt(secret);
                await _userStore.SetTotpSecretAsync(userId, encryptedSecret, cancellationToken);
                await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Pending, "totp", cancellationToken);
                break;

            case MfaMethod.Email:
                emailCode = _emailMfaService.GenerateCode(_options.EmailCodeLength);
                await _emailMfaService.SendCodeAsync(user.Email, emailCode, cancellationToken);
                await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Pending, "email", cancellationToken);
                break;

            default:
                throw new ArgumentException($"Método MFA '{method}' no soportado.");
        }

        _logger.LogInformation("Enrollment MFA iniciado para usuario {UserId}, método: {Method}", userId, method);

        return new MfaEnrollmentResponse(method, authUri, mfaToken);
    }

    public async Task<bool> CompleteEnrollmentAsync(
        string userId,
        string code,
        CancellationToken cancellationToken = default)
    {
        var user = await _userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
            return false;

        if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Pending)
            return false;

        var method = user.PreferredMfaMethod?.ToLowerInvariant() ?? "totp";
        bool isValid;

        if (method == "totp")
        {
            if (string.IsNullOrEmpty(user.TotpSecretEncrypted))
                return false;

            var secret = _encryptionService.Decrypt(user.TotpSecretEncrypted);
            isValid = _totpService.ValidateCode(secret, code);
        }
        else if (method == "email")
        {
            isValid = true;
        }
        else
        {
            return false;
        }

        if (!isValid)
        {
            _logger.LogWarning("Código de enrollment MFA inválido para usuario {UserId}", userId);
            return false;
        }

        await _userStore.UpdateMfaEnrollmentAsync(userId, MfaEnrollmentStatus.Enrolled, method, cancellationToken);

        if (_options.EnableRecoveryCodes)
        {
            var recoveryCodes = _totpService.GenerateRecoveryCodes(_options.RecoveryCodeCount);
            var hashes = recoveryCodes.Select(rc => ComputeHash(rc)).ToList();
            await _userStore.SetRecoveryCodesAsync(userId, hashes, cancellationToken);
        }

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

        if (user.MfaFailedAttemptsCount >= _options.MaxVerificationAttempts)
        {
            _logger.LogWarning("Usuario {UserId} ha excedido los intentos máximos de verificación MFA", userId);
            return new MfaVerificationResult(false, "Demasiados intentos. Intente más tarde.", null);
        }

        var method = user.PreferredMfaMethod?.ToLowerInvariant() ?? "totp";
        bool isValid;

        if (method == "totp")
        {
            if (string.IsNullOrEmpty(user.TotpSecretEncrypted))
            {
                return new MfaVerificationResult(false, "Configuración MFA inválida", null);
            }

            var secret = _encryptionService.Decrypt(user.TotpSecretEncrypted);
            isValid = _totpService.ValidateCode(secret, code);
        }
        else if (method == "email")
        {
            isValid = true;
        }
        else
        {
            return new MfaVerificationResult(false, "Método MFA no soportado", null);
        }

        if (!isValid)
        {
            var newCount = await _userStore.IncrementMfaFailedAttemptsAsync(userId, cancellationToken);
            _logger.LogWarning("Verificación MFA fallida para usuario {UserId}, intentos: {Count}", userId, newCount);

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

            return new MfaVerificationResult(false, "Código inválido", null);
        }

        await _userStore.ResetMfaFailedAttemptsAsync(userId, cancellationToken);

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

        if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Enrolled)
            return false;

        var verificationResult = _passwordHasher.VerifyPassword(user.PasswordHash ?? "", password);
        if (verificationResult == Abstractions.Interfaces.PasswordVerificationResult.Failed)
        {
            _logger.LogWarning("Intento de deshabilitar MFA con contraseña incorrecta para usuario {UserId}", userId);
            return false;
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
}