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
    ILogger<IdentityOrchestrator> logger)
{
    private readonly SecureAuthOptions _options = options.Value;
    private readonly MfaOptions _mfaOptions = mfaOptions.Value;

    /// <summary>
    /// Intenta autenticar un usuario con email y contraseña.
    /// </summary>
    /// <param name="email">Email del usuario.</param>
    /// <param name="password">Contraseña en texto plano.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Tupla con el resultado del login, los tokens (si fue exitoso), y token MFA (si requiere MFA).</returns>
    public async Task<(SignInResult Result, TokenResponse? Tokens, string? MfaSessionToken)> SignInWithPasswordAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(email);
        ArgumentNullException.ThrowIfNull(password);

        var user = await userStore.FindByEmailAsync(email.ToLowerInvariant(), cancellationToken);

        if (user is null || user.PasswordHash is null)
        {
            passwordHasher.VerifyDummyPassword(password);

            logger.LogDebug("Intento de login fallido: usuario no encontrado para email proporcionado");
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

        var verificationResult = passwordHasher.VerifyPassword(user.PasswordHash, password);

        if (verificationResult == PasswordVerificationResult.Failed)
        {
            var failedCount = await userStore.IncrementFailedAccessCountAsync(
                user.Id, cancellationToken);

            await lockoutManager.HandleFailedAttemptAsync(user.Id, failedCount, cancellationToken);

            logger.LogDebug("Contraseña incorrecta para usuario {UserId}. Intentos fallidos: {Count}",
                user.Id, failedCount);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.LoginFailed,
                UserId = user.Id,
                Metadata = new Dictionary<string, string>
                {
                    ["failedCount"] = failedCount.ToString()
                }
            }, cancellationToken);

            return (SignInResult.Failed, null, null);
        }

        var requiresMfa = _mfaOptions.Enabled && (user.TwoFactorEnabled || user.MfaEnrollmentStatus == MfaEnrollmentStatus.Enrolled || _mfaOptions.RequiredByDefault);

        if (requiresMfa)
        {
            var method = user.PreferredMfaMethod ?? "totp";
            var mfaToken = await mfaSessionStore.CreateMfaSessionTokenAsync(
                user.Id, method, _mfaOptions.MfaSessionTokenMinutes, cancellationToken);

            if (user.MfaEnrollmentStatus != MfaEnrollmentStatus.Enrolled)
            {
                logger.LogInformation("Usuario {UserId} requiere enrollment MFA", user.Id);
                return (SignInResult.TwoFactorRegistrationRequired, null, mfaToken);
            }

            logger.LogInformation("Usuario {UserId} requiere verificación MFA", user.Id);
            return (SignInResult.TwoFactorRequired, null, mfaToken);
        }

        await userStore.ResetFailedAccessCountAsync(user.Id, cancellationToken);

        var tokens = await tokenService.GenerateTokenPairAsync(user, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
        };

        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        logger.LogInformation("Login exitoso para usuario {UserId}", user.Id);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = user.Id
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

        var customClaims = user.Claims ?? [];
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
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
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
