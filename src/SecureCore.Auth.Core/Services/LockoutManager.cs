using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Gestiona el bloqueo de cuentas por intentos fallidos de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El bloqueo exponencial es una defensa contra ataques de fuerza bruta.
/// En lugar de bloquear la cuenta permanentemente (lo cual permitiría DoS) o no
/// bloquearla nunca (lo cual permitiría fuerza bruta), incrementamos la duración
/// del bloqueo con cada bloqueo consecutivo:
///
/// 1er bloqueo: 1 minuto → 2do bloqueo: 5 minutos → 3ro: 15 min → 4to: 1 hora
///
/// Tras un login exitoso, se resetea el contador completo.
/// </remarks>
public sealed class LockoutManager(
    IUserStore userStore,
    IOptions<SecureAuthOptions> options,
    ILogger<LockoutManager> logger)
{
    private readonly SecureAuthOptions _options = options.Value;

    /// <summary>
    /// Verifica si un usuario está actualmente bloqueado.
    /// </summary>
    /// <param name="user">La identidad del usuario a verificar.</param>
    /// <returns>true si la cuenta está bloqueada, false en caso contrario.</returns>
    public bool IsLockedOut(UserIdentity user)
    {
        ArgumentNullException.ThrowIfNull(user);

        // Si no tiene fecha de bloqueo, no está bloqueado
        if (user.LockoutEnd is null)
        {
            return false;
        }

        // Si la fecha de bloqueo ya pasó, ya no está bloqueado
        return user.LockoutEnd > DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Maneja un intento fallido de autenticación y bloquea la cuenta si corresponde.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="currentFailedCount">Número actual de intentos fallidos.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    public async Task HandleFailedAttemptAsync(
        string userId,
        int currentFailedCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        // Si no hemos alcanzado el máximo de intentos permitidos, no bloqueamos
        if (currentFailedCount < _options.MaxFailedAttempts)
        {
            return;
        }

        // Calculamos la duración del bloqueo basándonos en cuántas veces
        // se ha bloqueado previamente (bloqueo exponencial)
        var lockoutIndex = (currentFailedCount / _options.MaxFailedAttempts) - 1;
        var lockoutDuration = lockoutIndex < _options.LockoutDurations.Length
            ? _options.LockoutDurations[lockoutIndex]
            : _options.LockoutDurations[^1]; // Usamos la última duración como máximo

        var lockoutEnd = DateTimeOffset.UtcNow.Add(lockoutDuration);
        await userStore.SetLockoutEndAsync(userId, lockoutEnd, cancellationToken);

        logger.LogWarning(
            "Cuenta {UserId} bloqueada por {Duration} minutos. Intentos fallidos: {Count}",
            userId,
            lockoutDuration.TotalMinutes,
            currentFailedCount);
    }
}
