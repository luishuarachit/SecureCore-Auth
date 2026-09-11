using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador de creación/cambio de contraseña (S3, A-22; NIST SP 800-63B).
/// </summary>
/// <remarks>
/// DIDÁCTICA:
/// - <see cref="CreateAsync"/>: crea la contraseña de una cuenta que no tiene (flujo
///   passwordless → password). Exige la ventana de verify-action (step-up) ABIERTA
///   (M1, auditoría): el OTP ya se consumió en <c>VerifyActionAsync</c>; aquí solo se
///   comprueba <c>IMfaVerifiedSessionStore.IsVerifiedAsync</c>. Así el paso 1
///   (send + verify) y el paso 2 (create) forman un flujo viable sin doble consumo.
/// - <see cref="ChangeAsync"/>: cambia la contraseña validando la contraseña actual.
///
/// ANTI-ABUSO (M4, auditoría): <c>ChangeAsync</c> protege la validación de la contraseña
/// actual con el scope <c>AccountProtectionScope.PasswordChange</c> (S1, opt-in): sin él,
/// un atacante con sesión robada probaría contraseñas sin límite (~100 intentos/s por hilo
/// con Argon2). El login correcto renueva el presupuesto. Además (H3), la contraseña actual
/// se acota a 1024 caracteres ANTES de invocar Argon2 para impedir la amplificación de
/// memoria/CPU con inputs gigantes.
///
/// Tras cualquier cambio exitoso la política es común (NIST SP 800-63B): rotar el
/// SecurityStamp, invalidar la caché del stamp, revocar TODOS los refresh tokens previos
/// (acepta el cierre de sesiones del usuario legítimo y de posibles atacantes) y emitir un
/// par de tokens con el SecurityStamp NUEVO para que el cliente los adopte sin quedar huérfano.
///
/// POLÍTICA DE CONTRASEÑA: mínimo 8 caracteres y máximo 1024 (NIST: sin reglas de
/// composición arbitrarias; longitud larga permitida). La fuerza la decide el Argon2id
/// y la longitud; no imponemos clases de caracteres.
/// </remarks>
public sealed class ChangePasswordOrchestrator(
    IUserStore userStore,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    ISessionStore sessionStore,
    SecurityStampValidator stampValidator,
    IAuthEventDispatcher eventDispatcher,
    IOptions<SecureAuthOptions> options,
    ILogger<ChangePasswordOrchestrator> logger,
    IMfaVerifiedSessionStore? mfaVerifiedSessionStore = null,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null)
{
    private readonly SecureAuthOptions _options = options.Value;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;
    private const int MinPasswordLength = 8;
    private const int MaxPasswordLength = 1024;

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    /// <summary>
    /// Crea la contraseña de una cuenta que aún no tiene, exigiendo la ventana de verify-action abierta.
    /// </summary>
    /// <param name="userId">ID del usuario autenticado.</param>
    /// <param name="newPassword">Nueva contraseña en texto plano.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Resultado con el nuevo par de tokens si la creación fue exitosa.</returns>
    public async Task<ChangePasswordResult> CreateAsync(
        string userId,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(newPassword);

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            logger.LogDebug("CreateAsync sin usuario para {UserId} (sin oráculo)", userId);
            return await Fail(ChangePasswordError.GenericFailure, "No se pudo completar la operación.", userId, cancellationToken);
        }

        if (user.PasswordHash is not null)
        {
            logger.LogDebug("CreateAsync: la cuenta {UserId} ya tiene contraseña", userId);
            return await Fail(ChangePasswordError.PasswordAlreadyExists, "Ya existe una contraseña para esta cuenta.", userId, cancellationToken);
        }

        if (!IsValidNewPassword(newPassword))
        {
            logger.LogDebug("CreateAsync: política de contraseña no cumplida para {UserId}", userId);
            return await Fail(ChangePasswordError.InvalidPasswordPolicy, "La contraseña no cumple la política mínima.", userId, cancellationToken);
        }

        // DIDÁCTICA (M1, auditoría): el step-up de creación es la ventana verify-action
        // abierta (el OTP se entregó y validó en VerifyActionAsync). Releer/consumir el OTP
        // AQUÍ rompía el flujo: el consumo single-use ya ocurrió en VerifyActionAsync y el
        // código nunca sería válido. Fail-closed si la ventana no está abierta.
        if (mfaVerifiedSessionStore is null || !await mfaVerifiedSessionStore.IsVerifiedAsync(userId, cancellationToken))
        {
            logger.LogDebug("CreateAsync: ventana de verify-action cerrada para {UserId}", userId);
            return await Fail(ChangePasswordError.VerifyActionRequired, "Se requiere una verificación previa de acciones sensibles.", userId, cancellationToken);
        }

        return await ApplyPasswordChangeAsync(user, newPassword, cancellationToken);
    }

    /// <summary>
    /// Cambia la contraseña validando la contraseña actual.
    /// </summary>
    /// <param name="userId">ID del usuario autenticado.</param>
    /// <param name="currentPassword">Contraseña actual (una evidencia de factor único).</param>
    /// <param name="newPassword">Nueva contraseña en texto plano.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Resultado con el nuevo par de tokens si el cambio fue exitoso.</returns>
    public async Task<ChangePasswordResult> ChangeAsync(
        string userId,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            logger.LogDebug("ChangeAsync sin usuario para {UserId} (sin oráculo)", userId);
            return await Fail(ChangePasswordError.GenericFailure, "No se pudo completar la operación.", userId, cancellationToken);
        }

        if (AccountProtectionEnabled)
        {
            var check = await _accountProtection!.CheckAsync(AccountProtectionScope.PasswordChange, userId, cancellationToken);
            if (!check.Allowed)
            {
                logger.LogWarning("Cambio de contraseña bloqueado por anti-abuso (nivel {Level}): {UserId}",
                    check.EscalationLevel, userId);
                return await Fail(ChangePasswordError.GenericFailure, "Demasiados intentos. Intente más tarde.", userId, cancellationToken);
            }
        }

        if (user.PasswordHash is null)
        {
            // DIDÁCTICA: el flujo correcto es CreateAsync (con ventana de verify-action previa).
            logger.LogDebug("ChangeAsync: la cuenta {UserId} no tiene contraseña (use el flujo de creación)", userId);
            return await Fail(ChangePasswordError.NoPasswordCreated, "Esta cuenta aún no tiene contraseña.", userId, cancellationToken);
        }

        if (!IsValidNewPassword(newPassword))
        {
            logger.LogDebug("ChangeAsync: política de contraseña no cumplida para {UserId}", userId);
            return await Fail(ChangePasswordError.InvalidPasswordPolicy, "La contraseña no cumple la política mínima.", userId, cancellationToken);
        }

        // DIDÁCTICA (H3, auditoría): acotamos la contraseña actual ANTES de invocar Argon2.
        // Sin este límite, un atacante autenticado amplificaría memoria/CPU por request
        // (típicamente decenas de MB y ~200 ms) enviando inputs de megabytes.
        if (currentPassword.Length > MaxPasswordLength)
        {
            logger.LogDebug("ChangeAsync: contraseña actual fuera de límites para {UserId}", userId);
            return await Fail(ChangePasswordError.InvalidCurrentPassword, "La contraseña actual es incorrecta.", userId, cancellationToken);
        }

        var verification = await passwordHasher.VerifyPasswordAsync(user.PasswordHash, currentPassword, cancellationToken);
        if (verification == PasswordVerificationResult.Failed)
        {
            // DIDÁCTICA (M4, auditoría): cada intento fallido de contraseña actual consume el
            // presupuesto PasswordChange (S1). Evita el oráculo de contraseñas con sesión robada.
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordFailureAsync(AccountProtectionScope.PasswordChange, userId, cancellationToken);
            }

            logger.LogWarning("ChangeAsync: contraseña actual incorrecta para {UserId}", userId);
            return await Fail(ChangePasswordError.InvalidCurrentPassword, "La contraseña actual es incorrecta.", userId, cancellationToken);
        }

        // DIDÁCTICA: SuccessRehashNeeded también procede: ApplyPasswordChangeAsync re-hashea
        // con los parámetros vigentes (mantenimiento del hash actualizado).
        return await ApplyPasswordChangeAsync(user, newPassword, cancellationToken);
    }

    /// <summary>
    /// Aplica el cambio común: hash nuevo, rotación de stamp, revocación y re-emisión.
    /// </summary>
    /// <param name="user">Identidad del usuario (con PasswordHash/SecurityStamp actualizados).</param>
    /// <param name="newPassword">Nueva contraseña en texto plano.</param>
    private async Task<ChangePasswordResult> ApplyPasswordChangeAsync(
        UserIdentity user,
        string newPassword,
        CancellationToken cancellationToken)
    {
        var newHash = await passwordHasher.HashPasswordAsync(newPassword, cancellationToken);

        // DIDÁCTICA: rotación del SecurityStamp → todos los access tokens previos quedan
        // inválidos (por el claim "ssv"). Se revocan también TODOS los refresh tokens:
        // cualquier familia previa (incluida la del dispositivo actual) muere.
        var newSecurityStamp = Guid.NewGuid().ToString();
        await userStore.UpdatePasswordHashAsync(user.Id, newHash, cancellationToken);
        await userStore.UpdateSecurityStampAsync(user.Id, newSecurityStamp, cancellationToken);
        await stampValidator.InvalidateCacheAsync(user.Id, cancellationToken);
        await sessionStore.RevokeAllByUserAsync(user.Id, cancellationToken);

        // DIDÁCTICA: emitimos tokens con el SecurityStamp NUEVO. El cliente los adopta en la
        // respuesta del endpoint; sin esta re-emisión quedaría sin sesión tras el cambio.
        var updatedUser = user with { PasswordHash = newHash, SecurityStamp = newSecurityStamp };
        var tokens = await tokenService.GenerateTokenPairAsync(updatedUser, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
        };
        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        // DIDÁCTICA (S3): tras un cambio exitoso abrimos (o renovamos) la ventana mfa_verified
        // con la causa "change_password". En la creación, el usuario ya demostró verify-action,
        // por lo que no se exige re-verificar aquí; en el cambio, la contraseña actual es la prueba.
        if (mfaVerifiedSessionStore is not null)
        {
            await mfaVerifiedSessionStore.SetVerifiedAsync(user.Id, "change_password", cancellationToken);
        }

        // DIDÁCTICA (M4): el cambio exitoso renueva el presupuesto PasswordChange (paridad
        // con el resto de scopes: el éxito limpia la cuenta de intentos fallidos previos).
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.PasswordChange, user.Id, cancellationToken);
        }

        logger.LogInformation("Contraseña actualizada para el usuario {UserId}. Sesiones previas revocadas.", user.Id);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.SecurityStampChanged,
            UserId = user.Id,
            Metadata = new Dictionary<string, string> { ["reason"] = "password_changed" }
        }, cancellationToken);

        return new ChangePasswordResult(true, Tokens: tokens);
    }

    private async Task<ChangePasswordResult> Fail(
        string errorCode,
        string message,
        string userId,
        CancellationToken cancellationToken)
    {
        logger.LogDebug("Cambio de contraseña fallido para {UserId}: {ErrorCode}", userId, errorCode);

        // DIDÁCTICA: el evento PasswordChangeFailed es informativo y NO se filtra al cliente:
        // el endpoint traduce a mensaje genérico + status. Útil para auditoría y detección
        // de intentos de cambio (el atacante que roba una sesión y prueba contraseñas).
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.PasswordChangeFailed,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["reason"] = errorCode }
        }, cancellationToken);

        return new ChangePasswordResult(false, errorCode, message);
    }

    /// <summary>
    /// Política mínima (NIST SP 800-63B): longitud entre 8 y 1024 caracteres, sin reglas de
    /// composición arbitrarias.
    /// </summary>
    private static bool IsValidNewPassword(string password) =>
        password.Length >= MinPasswordLength && password.Length <= MaxPasswordLength;
}
