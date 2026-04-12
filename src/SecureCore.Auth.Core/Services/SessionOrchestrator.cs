using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    ILogger<SessionOrchestrator> logger)
{
    private readonly SecureAuthOptions _options = options.Value;

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

        // Paso 1: Calcular el hash del token recibido y buscar en la DB
        var tokenHash = tokenService.HashRefreshToken(currentRefreshToken);
        var existingEntry = await sessionStore.FindByTokenHashAsync(tokenHash, cancellationToken);

        if (existingEntry is null)
        {
            logger.LogWarning("Intento de rotación con token inexistente");
            return null;
        }

        // Paso 2: Verificar si el token está revocado
        if (existingEntry.IsRevoked)
        {
            logger.LogCritical(
                "¡REUSO DE TOKEN REVOCADO DETECTADO! FamilyId: {FamilyId}, UserId: {UserId}",
                existingEntry.FamilyId, existingEntry.UserId);

            // ⚠️ ALERTA: Reuso de token revocado = posible robo de sesión
            // Revocar toda la familia de tokens
            await sessionStore.RevokeByFamilyAsync(existingEntry.FamilyId, cancellationToken);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.SuspiciousActivityDetected,
                UserId = existingEntry.UserId,
                Metadata = new Dictionary<string, string>
                {
                    ["reason"] = "revoked_token_reuse",
                    ["familyId"] = existingEntry.FamilyId
                }
            }, cancellationToken);

            return null;
        }

        // Paso 3: Verificar si el token ya fue reemplazado (posible race condition o reuso)
        if (existingEntry.ReplacedByTokenHash is not null)
        {
            var timeSinceReplaced = DateTime.UtcNow - existingEntry.ReplacedAtUtc;

            // Grace Period: si fue reemplazado hace menos de N segundos, es una race condition
            if (timeSinceReplaced.HasValue &&
                timeSinceReplaced.Value.TotalSeconds <= _options.GracePeriodSeconds)
            {
                logger.LogDebug(
                    "Token dentro del periodo de gracia ({Seconds}s). Retornando respuesta existente.",
                    timeSinceReplaced.Value.TotalSeconds);

                // Retornamos el token de reemplazo existente (idempotente)
                var replacementEntry = await sessionStore.FindByTokenHashAsync(
                    existingEntry.ReplacedByTokenHash, cancellationToken);

                if (replacementEntry is not null)
                {
                    var user = await userStore.FindByIdAsync(existingEntry.UserId, cancellationToken);
                    if (user is not null)
                    {
                        // Generamos un nuevo Access Token pero mantenemos la misma sesión
                        var accessToken = tokenService.GenerateAccessToken(user);
                        return new TokenResponse(
                            accessToken,
                            currentRefreshToken, // Mantenemos el mismo refresh token
                            DateTimeOffset.UtcNow.Add(_options.AccessTokenLifetime));
                    }
                }

                return null;
            }

            // ⚠️ Fuera del periodo de gracia: REUSO DETECTADO
            logger.LogCritical(
                "¡REUSO DE TOKEN FUERA DEL PERIODO DE GRACIA! FamilyId: {FamilyId}, UserId: {UserId}",
                existingEntry.FamilyId, existingEntry.UserId);

            await sessionStore.RevokeByFamilyAsync(existingEntry.FamilyId, cancellationToken);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.SuspiciousActivityDetected,
                UserId = existingEntry.UserId,
                Metadata = new Dictionary<string, string>
                {
                    ["reason"] = "token_reuse_outside_grace_period",
                    ["familyId"] = existingEntry.FamilyId,
                    ["secondsSinceReplaced"] = timeSinceReplaced?.TotalSeconds.ToString("F0") ?? "unknown"
                }
            }, cancellationToken);

            return null;
        }

        // Paso 4: Verificar expiración
        if (existingEntry.IsExpired)
        {
            logger.LogDebug("Token expirado. FamilyId: {FamilyId}", existingEntry.FamilyId);
            return null;
        }

        // Paso 5: Token válido → Rotación exitosa
        var newUser = await userStore.FindByIdAsync(existingEntry.UserId, cancellationToken);
        if (newUser is null)
        {
            logger.LogWarning("Usuario {UserId} no encontrado durante rotación", existingEntry.UserId);
            return null;
        }

        // Generar nuevo par de tokens
        var newTokens = await tokenService.GenerateTokenPairAsync(newUser, cancellationToken);
        var newTokenHash = tokenService.HashRefreshToken(newTokens.RefreshToken);

        // Marcar el token actual como "reemplazado" (no revocado, por el grace period)
        await sessionStore.RevokeAsync(tokenHash, newTokenHash, cancellationToken);

        // Crear la nueva entrada con el mismo FamilyId
        var newEntry = new RefreshTokenEntry
        {
            TokenHash = newTokenHash,
            FamilyId = existingEntry.FamilyId,
            UserId = existingEntry.UserId,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
        };

        await sessionStore.CreateAsync(newEntry, cancellationToken);

        logger.LogDebug("Token rotado exitosamente. FamilyId: {FamilyId}", existingEntry.FamilyId);

        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.TokenRotated,
            UserId = existingEntry.UserId,
            Metadata = new Dictionary<string, string>
            {
                ["familyId"] = existingEntry.FamilyId
            }
        }, cancellationToken);

        return newTokens;
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
