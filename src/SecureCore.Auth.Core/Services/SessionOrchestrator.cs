using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquesta la gestión de sesiones: rotación de tokens, revocación y cierre global.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El SessionOrchestrator es el componente más crítico para la seguridad
/// de las sesiones. Implementa tres funcionalidades clave:
///
/// 1. ROTACIÓN DE TOKENS (Refresh Token Rotation - RTR):
///    Cada vez que se usa un Refresh Token, se invalida y se emite uno nuevo.
///    Esto limita la ventana de ataque si un token es robado.
///
/// 2. PERIODO DE GRACIA (Grace Period):
///    Si el mismo token se presenta dos veces en 30 segundos, no es un ataque sino
///    una condición de carrera (race condition) del cliente. Se retorna el mismo resultado.
///
/// 3. DETECCIÓN DE REUSO (Replay Detection):
///    Si un token rotado se presenta después del periodo de gracia, es probable que
///    el token original fue robado. Se revocan TODAS las sesiones de la familia
///    y se alerta al sistema.
/// </remarks>
public sealed class SessionOrchestrator(
    ISessionStore sessionStore,
    IUserStore userStore,
    ITokenService tokenService,
    SecurityStampValidator stampValidator,
    IAuthEventDispatcher eventDispatcher,
    IOptions<SecureAuthOptions> options,
    IOperationLock operationLock,
    ILogger<SessionOrchestrator> logger,
    IMfaVerifiedSessionStore? mfaVerifiedSessionStore = null)
{
    private readonly SecureAuthOptions _options = options.Value;
    private readonly TimeSpan _lockTimeout = TimeSpan.FromSeconds(
        options.Value.OperationLock?.TimeoutSeconds ?? 5);

    /// <summary>
    /// Rota un Refresh Token: invalida el actual y emite uno nuevo.
    /// </summary>
    /// <param name="currentRefreshToken">El Refresh Token actual del cliente.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Nuevo par de tokens o null si el token es inválido.</returns>
    public async Task<TokenResponse?> RotateRefreshTokenAsync(
        string currentRefreshToken,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentRefreshToken);

        // Paso 1: Calcular el hash del token recibido y buscar en la DB (solo para el FamilyId).
        var tokenHash = tokenService.HashRefreshToken(currentRefreshToken);
        var existingEntry = await sessionStore.FindByTokenHashAsync(tokenHash, cancellationToken);

        if (existingEntry is null)
        {
            logger.LogWarning("Intento de rotación con token inexistente");
            return null;
        }

        // DIDÁCTICA (auditoría): el lock por familia se adquiere ANTES de las comprobaciones de
        // estado. Sin re-leer dentro del lock, dos peticiones concurrentes con el mismo token
        // observarían ambas el snapshot previo a la rotación y crearían DOS tokens vivos
        // (TOCTOU): un token robado reproducido en paralelo produce dos sesiones válidas sin
        // detección. Dentro del lock se re-lee la entrada fresca y se decide sobre ella.
        using var @lock = await operationLock.AcquireAsync(
            $"rtr:{existingEntry.FamilyId}",
            _lockTimeout,
            cancellationToken);

        var entry = await sessionStore.FindByTokenHashAsync(tokenHash, cancellationToken);
        if (entry is null)
        {
            logger.LogWarning("Token eliminado durante la rotación. FamilyId: {FamilyId}", existingEntry.FamilyId);
            return null;
        }

        // DIDÁCTICA (auditoría): ORDEN de las comprobaciones. Un token ROTADO se marca en el
        // store como "reemplazado" (ReplacedByTokenHash) y, según la implementación, también
        // IsRevoked=true. El grace period solo funciona si el chequeo de "reemplazado" ocurre
        // ANTES que el de "revocado"; de lo contrario el periodo de gracia documentado
        // (AGENTS.md §B) es código muerto y una race condition legítima del cliente revocaría
        // toda la familia.
        if (entry.ReplacedByTokenHash is not null)
        {
            if (entry.ReplacedAtUtc.HasValue)
            {
                var timeSinceReplaced = DateTime.UtcNow - entry.ReplacedAtUtc.Value;

                // Grace Period: si fue reemplazado hace menos de N segundos, es una race
                // condition del cliente. Se devuelve una respuesta idempotente SIN revocar la
                // familia ni rotar de nuevo.
                if (timeSinceReplaced.TotalSeconds <= _options.GracePeriodSeconds)
                {
                    logger.LogDebug(
                        "Token dentro del periodo de gracia ({Seconds}s). Respuesta idempotente.",
                        timeSinceReplaced.TotalSeconds);

                    var user = await userStore.FindByIdAsync(entry.UserId, cancellationToken);
                    if (user is not null)
                    {
                        // DIDÁCTICA (auditoría): con un store de hashes el valor en claro del token de
                        // reemplazo NO es recuperable. Se devuelve un Access Token fresco y el
                        // MISMO refresh token del cliente para mantener viva la sesión durante la
                        // ventana (el cliente adoptará el nuevo token en la siguiente rotación).
                        var accessToken = tokenService.GenerateAccessToken(
                            WithSessionAuthClaims(user, entry.AuthMethod, entry.MfaMethod));
                        return new TokenResponse(
                            accessToken,
                            currentRefreshToken,
                            DateTimeOffset.UtcNow.Add(_options.AccessTokenLifetime));
                    }

                    return null;
                }

                // ⚠️ Fuera del periodo de gracia: REUSO DETECTADO
                logger.LogCritical(
                    "¡REUSO DE TOKEN FUERA DEL PERIODO DE GRACIA! FamilyId: {FamilyId}, UserId: {UserId}",
                    entry.FamilyId, entry.UserId);

                await sessionStore.RevokeByFamilyAsync(entry.FamilyId, cancellationToken);

                await eventDispatcher.DispatchAsync(new AuthEvent
                {
                    EventType = AuthEventType.SuspiciousActivityDetected,
                    UserId = entry.UserId,
                    Metadata = new Dictionary<string, string>
                    {
                        ["reason"] = "token_reuse_outside_grace_period",
                        ["familyId"] = entry.FamilyId,
                        ["secondsSinceReplaced"] = timeSinceReplaced.TotalSeconds.ToString("F0")
                    }
                }, cancellationToken);

                return null;
            }

            // ReplacedByTokenHash no es null pero ReplacedAtUtc es null: no podemos aplicar el
            // grace period de forma segura → tratar como reuso.
            logger.LogCritical(
                "¡REUSO DE TOKEN - FECHA DESCONOCIDA! FamilyId: {FamilyId}, UserId: {UserId}",
                entry.FamilyId, entry.UserId);

            await sessionStore.RevokeByFamilyAsync(entry.FamilyId, cancellationToken);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.SuspiciousActivityDetected,
                UserId = entry.UserId,
                Metadata = new Dictionary<string, string>
                {
                    ["reason"] = "token_reuse_unknown_date",
                    ["familyId"] = entry.FamilyId
                }
            }, cancellationToken);

            return null;
        }

        // Paso 2: Verificar si el token está revocado (logout/revocación explícita; un token
        // rotado ya cayó en el ramo de arriba por ReplacedByTokenHash).
        if (entry.IsRevoked)
        {
            logger.LogCritical(
                "¡REUSO DE TOKEN REVOCADO DETECTADO! FamilyId: {FamilyId}, UserId: {UserId}",
                entry.FamilyId, entry.UserId);

            // ⚠️ ALERTA: Reuso de token revocado = posible robo de sesión
            // Revocar toda la familia de tokens
            await sessionStore.RevokeByFamilyAsync(entry.FamilyId, cancellationToken);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.SuspiciousActivityDetected,
                UserId = entry.UserId,
                Metadata = new Dictionary<string, string>
                {
                    ["reason"] = "revoked_token_reuse",
                    ["familyId"] = entry.FamilyId
                }
            }, cancellationToken);

            return null;
        }

        // Paso 3: Verificar expiración
        if (entry.IsExpired)
        {
            logger.LogDebug("Token expirado. FamilyId: {FamilyId}", entry.FamilyId);
            return null;
        }

        // Paso 4: Token válido → Rotación exitosa
        var newUser = await userStore.FindByIdAsync(entry.UserId, cancellationToken);
        if (newUser is null)
        {
            logger.LogWarning("Usuario {UserId} no encontrado durante rotación", entry.UserId);
            return null;
        }

        // Generar nuevo par de tokens, preservando el aseguramiento (amr/mfa_method) de la sesión.
        var userWithClaims = WithSessionAuthClaims(newUser, entry.AuthMethod, entry.MfaMethod);
        var newTokens = await tokenService.GenerateTokenPairAsync(userWithClaims, cancellationToken);
        var newTokenHash = tokenService.HashRefreshToken(newTokens.RefreshToken);

        // Marcar el token actual como "reemplazado" (no revocado, por el grace period)
        await sessionStore.RevokeAsync(tokenHash, newTokenHash, cancellationToken);

        // Crear la nueva entrada con el mismo FamilyId y el MISMO aseguramiento de sesión.
        var newEntry = new RefreshTokenEntry
        {
            TokenHash = newTokenHash,
            FamilyId = entry.FamilyId,
            UserId = entry.UserId,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime),
            AuthMethod = entry.AuthMethod,
            MfaMethod = entry.MfaMethod
        };

        await sessionStore.CreateAsync(newEntry, cancellationToken);

        logger.LogDebug("Token rotado exitosamente. FamilyId: {FamilyId}", entry.FamilyId);

        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.TokenRotated,
            UserId = entry.UserId,
            Metadata = new Dictionary<string, string>
            {
                ["familyId"] = entry.FamilyId
            }
        }, cancellationToken);

        return newTokens;
    }

    /// <summary>
    /// Re-inyecta el aseguramiento de la sesión (amr/mfa_method) en la identidad usada para
    /// re-emitir tokens durante la rotación.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (auditoría): el <c>amr</c> describe el método de la autenticación ORIGINAL y
    /// debe sobrevivir al refresh. Se clona el diccionario de claims (no mutar el del store).
    /// </remarks>
    private static UserIdentity WithSessionAuthClaims(UserIdentity user, string? authMethod, string? mfaMethod)
    {
        if (authMethod is null)
        {
            return user;
        }

        var claims = new Dictionary<string, string>(user.Claims ?? []);
        claims["amr"] = authMethod;
        if (mfaMethod is not null)
        {
            claims["mfa_method"] = mfaMethod;
        }

        return user with { Claims = claims };
    }

    /// <summary>
    /// Revoca todas las sesiones de un usuario (cierre de sesión global / "botón de pánico").
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este es el "botón de pánico". Cuando se ejecuta:
    /// 1. Se genera un nuevo SecurityStamp (GUID) → invalida todos los Access Tokens
    /// 2. Se invalida la caché del SecurityStamp → efecto inmediato
    /// 3. Se revocan TODOS los Refresh Tokens → no se pueden obtener nuevos Access Tokens
    ///
    /// El resultado es que TODAS las sesiones del usuario (en todos los dispositivos)
    /// se invalidan instantáneamente. Útil cuando el usuario sospecha que su cuenta
    /// fue comprometida.
    /// </remarks>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    public async Task RevokeAllSessionsAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        // Paso 1: Generar nuevo SecurityStamp (invalida todos los Access Tokens)
        var newSecurityStamp = Guid.NewGuid().ToString();
        await userStore.UpdateSecurityStampAsync(userId, newSecurityStamp, cancellationToken);

        // Paso 2: Invalidar caché para efecto inmediato
        await stampValidator.InvalidateCacheAsync(userId, cancellationToken);

        // Paso 3: Revocar todos los Refresh Tokens
        await sessionStore.RevokeAllByUserAsync(userId, cancellationToken);

        // Paso 3b (H2, auditoría): la revocación global debe caer también la ventana de
        // sesión "ya verificada" (mfa_verified). Sin esto, una sesión nueva (ya sin MFA)
        // dentro de MfaVerifiedTtl heredaría silenciosamente el step-up del atacante.
        if (mfaVerifiedSessionStore is not null)
        {
            await mfaVerifiedSessionStore.ClearAsync(userId, cancellationToken);
        }

        logger.LogInformation("Todas las sesiones revocadas para usuario {UserId}", userId);

        // Paso 4: Disparar evento
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.GlobalLogout,
            UserId = userId
        }, cancellationToken);
    }

    /// <summary>
    /// Cierra una sesión individual (revoca un refresh token específico).
    /// </summary>
    /// <param name="refreshToken">El Refresh Token a revocar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    public async Task LogoutAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);

        var tokenHash = tokenService.HashRefreshToken(refreshToken);
        var entry = await sessionStore.FindByTokenHashAsync(tokenHash, cancellationToken);

        if (entry is not null && !entry.IsRevoked)
        {
            await sessionStore.RevokeAsync(tokenHash, cancellationToken: cancellationToken);

            // DIDÁCTICA (H2, auditoría): cerrar la última/una sesión sincronizada con un
            // logout explícito también invalida la ventana mfa_verified compartida de la
            // cuenta. Así una sesión posterior no hereda el paso elevado de acciones sensibles.
            if (mfaVerifiedSessionStore is not null)
            {
                await mfaVerifiedSessionStore.ClearAsync(entry.UserId, cancellationToken);
            }

            logger.LogDebug("Sesión cerrada. FamilyId: {FamilyId}, UserId: {UserId}",
                entry.FamilyId, entry.UserId);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.Logout,
                UserId = entry.UserId
            }, cancellationToken);
        }
    }
}
