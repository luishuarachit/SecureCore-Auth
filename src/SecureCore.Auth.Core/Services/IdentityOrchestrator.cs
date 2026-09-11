using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador principal de identidad. Coordina el flujo completo de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El IdentityOrchestrator sigue el patrón "Orchestrator" (orquestador).
/// No implementa lógica de bajo nivel (hashing, tokens, etc.), sino que coordina
/// los diferentes servicios para ejecutar flujos complejos. Piensa en él como un
/// director de orquesta: no toca ningún instrumento, pero dirige a todos.
///
/// Flujo de login con contraseña:
/// 1. Buscar usuario por email (IUserStore)
/// 2. Verificar si la cuenta no está bloqueada (LockoutManager)
/// 3. Verificar la contraseña (IPasswordHasher)
/// 4. Si falla → incrementar contador de fallos, posiblemente bloquear
/// 5. Si tiene MFA → retornar RequiresTwoFactor
/// 6. Si éxito → resetear contador, generar tokens (ITokenService)
/// 7. Disparar evento de dominio (IAuthEventDispatcher)
/// </remarks>
public sealed class IdentityOrchestrator(
    IUserStore userStore,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    ISessionStore sessionStore,
    LockoutManager lockoutManager,
    IAuthEventDispatcher eventDispatcher,
    IOptions<SecureAuthOptions> options,
    IOptions<MfaOptions> mfaOptions,
    IMfaSessionStore mfaSessionStore,
    IMfaService mfaService,
    ILogger<IdentityOrchestrator> logger,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null,
    IMfaVerifiedSessionStore? mfaVerifiedSessionStore = null,
    RecoveryCodeOrchestrator? recoveryCodeOrchestrator = null,
    SecurityStampValidator? stampValidator = null)
{
    private readonly SecureAuthOptions _options = options.Value;
    private readonly MfaOptions _mfaOptions = mfaOptions.Value;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;
    private readonly IMfaVerifiedSessionStore? _mfaVerifiedSessionStore = mfaVerifiedSessionStore;
    private readonly RecoveryCodeOrchestrator? _recoveryCodeOrchestrator = recoveryCodeOrchestrator;
    private readonly SecurityStampValidator? _stampValidator = stampValidator;

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    /// <summary>
    /// Intenta autenticar un usuario con email y contraseña.
    /// </summary>
    /// <param name="email">Email del usuario.</param>
    /// <param name="password">
    /// Contraseña en texto plano. <c>null</c> significa "login sin credencial" (passwordless):
    /// se devuelve <see cref="SignInResult.PasswordlessRequiresCredential"/> sin consultar el store.
    /// </param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tupla con el resultado del login, los tokens (si fue exitoso), y token MFA (si requiere MFA).</returns>
    public async Task<(SignInResult Result, TokenResponse? Tokens, string? MfaSessionToken)> SignInWithPasswordAsync(
        string email,
        string? password,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);

        // DIDÁCTICA (S6, A-25): sin credencial → señal a nivel de REQUEST, uniforme para todos los
        // emails. Se devuelve ANTES de tocar el store: no distinguimos "email existe y es
        // passwordless" de "email no existe" (eso sería un oráculo de enumeración). VerifyDummyPassword
        // solo aplica con password no nulo (no hay nada que hashear).
        if (password is null)
        {
            logger.LogDebug("Login sin credencial: se requiere una (contraseña o passkey)");
            return (SignInResult.PasswordlessRequiresCredential, null, null);
        }

        var user = await userStore.FindByEmailAsync(email.ToLowerInvariant(), cancellationToken);

        if (user is null || user.PasswordHash is null)
        {
            passwordHasher.VerifyDummyPassword(password);

            logger.LogDebug("Intento de login fallido: usuario no encontrado para email proporcionado");
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.AnonymousLoginFailed,
                TimestampUtc = DateTime.UtcNow
            }, cancellationToken);

            return (SignInResult.Failed, null, null);
        }

        if (lockoutManager.IsLockedOut(user))
        {
            logger.LogWarning("Intento de login en cuenta bloqueada: {UserId}", user.Id);
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.AccountLockedOut,
                UserId = user.Id,
                Metadata = new Dictionary<string, string> { ["reason"] = "lockout_active" }
            }, cancellationToken);

            return (SignInResult.LockedOut, null, null);
        }

        // DIDÁCTICA (S1): Anti-abuso por cuenta — scope Password. Cuando el subsistema está
        // registrado y habilitado, reemplaza el contador en DB (IncrementFailedAccessCountAsync +
        // HandleFailedAttemptAsync) por estado in-memory/distribuido SIN tocar la base de datos.
        // El check de LockoutManager se conserva siempre (cubre lockouts administrativos y legacy).
        if (AccountProtectionEnabled)
        {
            var protectionCheck = await _accountProtection!.CheckAsync(AccountProtectionScope.Password, user.Id, cancellationToken);
            if (!protectionCheck.Allowed)
            {
                logger.LogWarning("Intento de login en cuenta bloqueada por anti-abuso (nivel {Level}): {UserId}",
                    protectionCheck.EscalationLevel, user.Id);
                await eventDispatcher.DispatchAsync(new AuthEvent
                {
                    EventType = AuthEventType.AccountLockedOut,
                    UserId = user.Id,
                    Metadata = new Dictionary<string, string> { ["reason"] = "account_protection_lock", ["scope"] = "password" }
                }, cancellationToken);

                return (SignInResult.LockedOut, null, null);
            }
        }

        var verificationResult = passwordHasher.VerifyPassword(user.PasswordHash, password);

        if (verificationResult == PasswordVerificationResult.Failed)
        {
            // DIDÁCTICA (S1): se registra el fallo en el subsistema. Si este fallo dispara el
            // lockout (alcanza el máximo del scope), se responde LockedOut y se emite el evento
            // AccountLockedOut exactamente cuando se activa el bloqueo.
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordFailureAsync(AccountProtectionScope.Password, user.Id, cancellationToken);

                var protectionCheck = await _accountProtection.CheckAsync(AccountProtectionScope.Password, user.Id, cancellationToken);
                if (!protectionCheck.Allowed)
                {
                    logger.LogWarning("Cuenta {UserId} bloqueada por anti-abuso (contraseña, nivel {Level})",
                        user.Id, protectionCheck.EscalationLevel);
                    await eventDispatcher.DispatchAsync(new AuthEvent
                    {
                        EventType = AuthEventType.AccountLockedOut,
                        UserId = user.Id,
                        Metadata = new Dictionary<string, string>
                        {
                            ["reason"] = "lock_triggered",
                            ["scope"] = "password",
                            ["level"] = protectionCheck.EscalationLevel.ToString()
                        }
                    }, cancellationToken);

                    return (SignInResult.LockedOut, null, null);
                }
            }
            else
            {
                var failedCount = await userStore.IncrementFailedAccessCountAsync(
                    user.Id, cancellationToken);

                await lockoutManager.HandleFailedAttemptAsync(user.Id, failedCount, cancellationToken);

                logger.LogDebug("Contraseña incorrecta para usuario {UserId}. Intentos fallidos: {Count}",
                    user.Id, failedCount);
            }

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.LoginFailed,
                UserId = user.Id,
                Metadata = new Dictionary<string, string>
                {
                    ["failedCount"] = AccountProtectionEnabled
                        ? (await _accountProtection!.CheckAsync(AccountProtectionScope.Password, user.Id, cancellationToken)).RemainingAttempts.ToString()
                        : "0"
                }
            }, cancellationToken);

            return (SignInResult.Failed, null, null);
        }

        var requiresMfa = _mfaOptions.Enabled && (user.TwoFactorEnabled || user.MfaEnrollmentStatus == MfaEnrollmentStatus.Enrolled || _mfaOptions.RequiredByDefault);

        if (requiresMfa)
        {
            // DIDÁCTICA (S1): la contraseña fue correcta → reset del scope Password, aunque el
            // login siga pendiente de MFA (el factor que podría bloquearse es MfaLogin).
            if (AccountProtectionEnabled)
            {
                await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.Password, user.Id, cancellationToken);
            }

            var method = user.PreferredMfaMethod ?? "totp";
            var mfaToken = await mfaSessionStore.CreateMfaSessionTokenAsync(
                user.Id, method, _mfaOptions.MfaSessionTokenMinutes, null, cancellationToken);

            if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Enrolled)
            {
                logger.LogInformation("Usuario {UserId} requiere enrollment MFA", user.Id);
                return (SignInResult.TwoFactorRegistrationRequired, null, mfaToken);
            }

            logger.LogInformation("Usuario {UserId} requiere verificación MFA", user.Id);
            return (SignInResult.TwoFactorRequired, null, mfaToken);
        }

        await userStore.ResetFailedAccessCountAsync(user.Id, cancellationToken);

        // DIDÁCTICA (S1): éxito total → reset del scope Password (limpieza del anti-abuso).
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.Password, user.Id, cancellationToken);
        }

        // DIDÁCTICA (S6, A-25 / RFC 8176): con EmitAmr el login por contraseña expresa el método
        // de autenticación (amr=pwd) de forma consistente con MFA (amr=mfa) y WebAuthn
        // (amr=webauthn). Opt-in: con EmitAmr=false el token no cambia (no-breaking).
        var userWithClaims = user;
        if (_options.EmitAmr)
        {
            var customClaims = new Dictionary<string, string>(user.Claims ?? []);
            customClaims["amr"] = "pwd";
            userWithClaims = user with { Claims = customClaims };
        }

        var tokens = await tokenService.GenerateTokenPairAsync(userWithClaims, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            AuthMethod = _options.EmitAmr ? "pwd" : null
        };

        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        logger.LogInformation("Login exitoso para usuario {UserId}", user.Id);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = user.Id,
            Metadata = new Dictionary<string, string> { ["method"] = "password" }
        }, cancellationToken);

        return (SignInResult.Success, tokens, null);
    }

    /// <summary>
    /// Completa el login tras verificación MFA exitosa.
    /// </summary>
    /// <param name="mfaSessionToken">Token de sesión MFA.</param>
    /// <param name="mfaCode">Código MFA.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tokens de acceso.</returns>
    public async Task<(SignInResult Result, TokenResponse? Tokens)> CompleteMfaLoginAsync(
        string mfaSessionToken,
        string mfaCode,
        CancellationToken cancellationToken = default)
    {
        var userId = await mfaSessionStore.ValidateMfaSessionTokenAsync(mfaSessionToken, cancellationToken);
        if (userId is null)
        {
            logger.LogWarning("Token MFA inválido o expirado");
            return (SignInResult.Failed, null);
        }

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return (SignInResult.Failed, null);
        }

        var mfaResult = await mfaService.VerifyAsync(userId, mfaCode, cancellationToken);
        if (!mfaResult.Success)
        {
            return (SignInResult.Failed, null);
        }

        await mfaSessionStore.ConsumeMfaSessionTokenAsync(mfaSessionToken, cancellationToken);

        await userStore.ResetFailedAccessCountAsync(userId, cancellationToken);

        // DIDÁCTICA (S3): tras una verificación MFA exitosa, se abre (o renueva) la ventana
        // "mfa_verified" del usuario. Los claims amr/mfa_method describen cómo se emitió ESTE
        // par de tokens; la ventana permite al host saber, en peticiones posteriores, que el
        // usuario verificó un factor dentro de MfaVerifiedTtl (step-up, mutaciones sensibles).
        // Si el store no está registrado (sin S3), el comportamiento previo permanece igual.
        if (_mfaVerifiedSessionStore is not null && mfaResult.VerifiedMethod.HasValue)
        {
            await _mfaVerifiedSessionStore.SetVerifiedAsync(
                userId, mfaResult.VerifiedMethod.Value.ToString().ToLowerInvariant(), cancellationToken);
        }

        var customClaims = new Dictionary<string, string>(user.Claims ?? []);
        if (mfaResult.VerifiedMethod.HasValue)
        {
            customClaims["amr"] = "mfa";
            customClaims["mfa_method"] = mfaResult.VerifiedMethod.Value.ToString().ToLowerInvariant();
        }

        var userWithClaims = user with { Claims = customClaims };
        var tokens = await tokenService.GenerateTokenPairAsync(userWithClaims, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            AuthMethod = "mfa",
            MfaMethod = mfaResult.VerifiedMethod.HasValue
                ? mfaResult.VerifiedMethod.Value.ToString().ToLowerInvariant()
                : null
        };

        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        logger.LogInformation("Login con MFA exitoso para usuario {UserId}", userId);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["method"] = "password+mfa" }
        }, cancellationToken);

        return (SignInResult.Success, tokens);
    }

    /// <summary>
    /// Completa el login tras la redención de un recovery code (F5, A-20).
    /// </summary>
    /// <param name="mfaSessionToken">Token de sesión MFA emitido tras el login con contraseña.</param>
    /// <param name="recoveryCode">Recovery code en texto plano a redimir (single-use atómico).</param>
    /// <param name="rotateSecurityStamp">
    /// true para rotar el SecurityStamp y revocar TODAS las sesiones previas (política recomendada
    /// cuando el recovery code se usa por pérdida/robo del dispositivo MFA); false para mantener la
    /// sesión y el stamp actuales (por ejemplo, si el host ya rotó el stamp en su flujo).
    /// </param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tokens de acceso con la marca <c>mfa_method=recovery</c>, o fallo genérico.</returns>
    /// <remarks>
    /// DIDÁCTICA (A1, auditoría F5): <see cref="CompleteMfaLoginAsync"/> exige un <c>mfaCode</c>
    /// que pase <c>mfaService.VerifyAsync</c> (TOTP/email), por lo que NO sirve para un recovery
    /// code. Este método cierra el flujo A-20 completo: valida el token (sin consumirlo),
    /// redime el recovery code (consume el single-use vía <c>RecoveryCodeOrchestrator.UseAsync</c>),
    /// consume el token, emite los tokens con la marca del factor, abre la ventana mfa_verified
    /// (paridad S3) y, según la política del host, rota el SecurityStamp (revocando las sesiones
    /// previas y re-emitiendo con el stamp nuevo).
    ///
    /// El bloqueo S1 (scope Recovery) se traduce a fallo genérico: el cliente no distingue
    /// "código erróneo" de "cuenta bloqueada" en el login.
    /// </remarks>
    public async Task<(SignInResult Result, TokenResponse? Tokens)> CompleteMfaLoginWithRecoveryCodeAsync(
        string mfaSessionToken,
        string recoveryCode,
        bool rotateSecurityStamp,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mfaSessionToken);
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryCode);

        if (_recoveryCodeOrchestrator is null)
        {
            logger.LogWarning("Login por recovery code solicitado sin RecoveryCodeOrchestrator (¿falta AddMfa?)");
            return (SignInResult.Failed, null);
        }

        var userId = await mfaSessionStore.ValidateMfaSessionTokenAsync(mfaSessionToken, cancellationToken);
        if (userId is null)
        {
            logger.LogWarning("Token MFA inválido o expirado (login por recovery code)");
            return (SignInResult.Failed, null);
        }

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            return (SignInResult.Failed, null);
        }

        // DIDÁCTICA (F5): el recovery code se consume AQUÍ (single-use atómico vía S2). Si el
        // scope Recovery está bloqueado, UseAsync devuelve Blocked → fallo genérico de login.
        var useResult = await _recoveryCodeOrchestrator.UseAsync(userId, recoveryCode, cancellationToken);
        if (!useResult.Success)
        {
            logger.LogWarning("Login por recovery code fallido para el usuario {UserId}", userId);
            return (SignInResult.Failed, null);
        }

        await mfaSessionStore.ConsumeMfaSessionTokenAsync(mfaSessionToken, cancellationToken);
        await userStore.ResetFailedAccessCountAsync(userId, cancellationToken);

        var userWithStamp = user;
        if (rotateSecurityStamp)
        {
            // DIDÁCTICA (política del host): rotar el SecurityStamp invalida TODOS los access
            // tokens previos (claim "ssv") y revoca todas las sesiones (refresh tokens). Es la
            // recomendación cuando el recovery code se usa tras pérdida/robo del dispositivo MFA:
            // una sesión robada no debe sobrevivir a la entrada por código de emergencia.
            var newSecurityStamp = Guid.NewGuid().ToString();
            await userStore.UpdateSecurityStampAsync(user.Id, newSecurityStamp, cancellationToken);
            if (_stampValidator is not null)
            {
                await _stampValidator.InvalidateCacheAsync(user.Id, cancellationToken);
            }
            await sessionStore.RevokeAllByUserAsync(user.Id, cancellationToken);
            userWithStamp = user with { SecurityStamp = newSecurityStamp };

            logger.LogInformation("SecurityStamp rotado tras login por recovery code para {UserId}", userId);
        }

        // DIDÁCTICA (S3): paridad con CompleteMfaLoginAsync — el factor verificado abre la ventana
        // mfa_verified (para step-up posterior) con el método "recovery".
        if (_mfaVerifiedSessionStore is not null)
        {
            await _mfaVerifiedSessionStore.SetVerifiedAsync(userId, "recovery", cancellationToken);
        }

        var customClaims = new Dictionary<string, string>(user.Claims ?? []);
        customClaims["amr"] = "mfa";
        customClaims["mfa_method"] = "recovery";

        var userWithClaims = userWithStamp with { Claims = customClaims };
        var tokens = await tokenService.GenerateTokenPairAsync(userWithClaims, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            AuthMethod = "mfa",
            MfaMethod = "recovery"
        };
        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        if (rotateSecurityStamp)
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.SecurityStampChanged,
                UserId = userId,
                Metadata = new Dictionary<string, string> { ["reason"] = "recovery_code_used" }
            }, cancellationToken);
        }

        logger.LogInformation("Login por recovery code exitoso para el usuario {UserId}", userId);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = userId,
            Metadata = new Dictionary<string, string> { ["method"] = "password+mfa", ["factor"] = "recovery" }
        }, cancellationToken);

        return (SignInResult.Success, tokens);
    }

    /// <summary>
    /// Intenta autenticar un usuario mediante un proveedor externo (OAuth).
    /// </summary>
    /// <param name="provider">Nombre del proveedor (ej: "Google").</param>
    /// <param name="providerKey">ID único del usuario en el proveedor.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tupla con el resultado y los tokens.</returns>
    public async Task<(SignInResult Result, TokenResponse? Tokens)> SignInExternalAsync(
        string provider,
        string providerKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);
        ArgumentException.ThrowIfNullOrEmpty(providerKey);

        // Paso 1: Buscar al usuario por proveedor externo
        var user = await userStore.FindByExternalProviderAsync(provider, providerKey, cancellationToken);

        if (user is null)
        {
            logger.LogDebug("Usuario externo no encontrado: {Provider} | {ProviderKey}", provider, providerKey);
            return (SignInResult.Failed, null);
        }

        // Paso 2: Verificar si la cuenta está bloqueada (aunque sea externo, puede estar bloqueada administrativamente)
        if (lockoutManager.IsLockedOut(user))
        {
            logger.LogWarning("Intento de login externo en cuenta bloqueada: {UserId}", user.Id);
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.AccountLockedOut,
                UserId = user.Id,
                Metadata = new Dictionary<string, string> { ["reason"] = "lockout_active", ["provider"] = provider }
            }, cancellationToken);

            return (SignInResult.LockedOut, null);
        }

        // Paso 3: Login exitoso
        await userStore.ResetFailedAccessCountAsync(user.Id, cancellationToken);
        var tokens = await tokenService.GenerateTokenPairAsync(user, cancellationToken);

        // Paso 4: Almacenar la sesión
        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
        };

        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        // Paso 5: Evento
        logger.LogInformation("Login externo exitoso: {UserId} vía {Provider}", user.Id, provider);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = user.Id,
            Metadata = new Dictionary<string, string> { ["method"] = "external", ["provider"] = provider }
        }, cancellationToken);

        return (SignInResult.Success, tokens);
    }
}
