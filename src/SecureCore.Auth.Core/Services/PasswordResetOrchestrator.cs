using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Orquestador para el flujo de recuperación y restablecimiento de contraseñas.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El PasswordResetOrchestrator implementa un flujo de dos pasos altamente seguro:
/// 
/// 1. SOLICITUD CIEGA (Anti-Enumeración): Nunca revela si un email existe. Si el usuario no 
///    existe, se simula el trabajo criptográfico para que el tiempo de respuesta sea idéntico.
/// 
/// 2. TOKENS OPACOS HASHEADOS: A diferencia de los JWT, estos tokens no contienen información 
///    y solo el hash SHA-256 vive en la BD. Esto significa que incluso con acceso a la base 
///    de datos, un atacante no puede generar el token necesario para el email.
/// 3. REVOCACIÓN AUTOMÁTICA: Al completar un reset, se invalidan TODAS las sesiones activas 
///    del usuario, cerrando cualquier acceso persistente (incluyendo posibles atacantes).
/// </remarks>
public sealed class PasswordResetOrchestrator(
    IUserStore userStore,
    IPasswordResetStore passwordResetStore,
    IResetTokenMailer resetTokenMailer,
    IPasswordHasher passwordHasher,
    SessionOrchestrator sessionOrchestrator,
    IAuthEventDispatcher eventDispatcher,
    IOptions<PasswordResetOptions> options,
    ILogger<PasswordResetOrchestrator> logger)
{
    private readonly PasswordResetOptions _options = options.Value;

    /// <summary>
    /// Inicia la solicitud de restablecimiento, genera el token criptográfico y envía el email.
    /// </summary>
    public async Task<bool> RequestPasswordResetAsync(string email, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(email);

        // 1. Buscar usuario. (Simularemos la misma latencia si no existe).
        var user = await userStore.FindByEmailAsync(email, cancellationToken);
        
        if (user is null)
        {
            // Operación de tiempo constante (dummy string de 32 bytes en b64url)
            CreateUrlSafeCSPRNGToken();
            logger.LogDebug("Solicitud de restablecimiento rechazada internamente (Usuario no encontrado)");
            return true; // Anti-enumeración garantizada
        }

        // 2. Control de ráfagas (Rate limit preventivo)
        if (_options.MaxRequestsPerHour > 0)
        {
            var since = DateTime.UtcNow.AddHours(-1);
            var count = await passwordResetStore.CountRecentRequestsAsync(user.Id, since, cancellationToken);
            if (count >= _options.MaxRequestsPerHour)
            {
                logger.LogWarning("Tasa de límite superada para reseteo usando el Id de usuario {UserId}", user.Id);
                return true; // Anti-enumeración: Fallamos silenciósamente
            }
        }

        // 3. Generación del token de un solo uso
        var rawToken = CreateUrlSafeCSPRNGToken(_options.TokenSizeBytes);

        // 4. Calcular el Hash SHA256 que se almacenará
        var tokenHash = ComputeTokenHash(rawToken);

        // 5. Persistir el hash del token
        var entry = new PasswordResetEntry
        {
            TokenHash = tokenHash,
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.AddMinutes(_options.TokenLifetimeMinutes)
        };

        await passwordResetStore.StoreAsync(entry, cancellationToken);

        // 6. Alertar al despachador
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.PasswordResetRequested,
            UserId = user.Id
        }, cancellationToken);

        // 7. Enviar la notificación al cliente real a través de una vía independiente
        logger.LogInformation("Enviando token de reseteo a Email vinculado para el usuario {UserId}", user.Id);
        await resetTokenMailer.SendResetEmailAsync(email, rawToken, cancellationToken);

        return true;
    }

    /// <summary>
    /// Valida un token entrante e intenta ejecutar el proceso de reescritura de credenciales.
    /// </summary>
    public async Task<PasswordResetResult> ConfirmPasswordResetAsync(string rawToken, string newPassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(rawToken);
        ArgumentException.ThrowIfNullOrEmpty(newPassword);

        // 1. Evaluar hash SHA256 para validarlo frente al backend
        var incomingHash = ComputeTokenHash(rawToken);

        // 2. Consultar al manejador de almacenamiento
        var entry = await passwordResetStore.FindByTokenHashAsync(incomingHash, cancellationToken);

        if (entry is null || entry.IsUsed || entry.IsExpired)
        {
            // Ocultamos si ha caducado, ha sido utilizado, o ni siquiera exista
            return PasswordResetResult.InvalidToken;
        }

        // 3. Recuperar usuario final. Teóricamente debería de existir siempre derivado de 'entry.UserId' (Integridad referencial a priori)
        var user = await userStore.FindByIdAsync(entry.UserId, cancellationToken);
        if (user is null)
        {
            return PasswordResetResult.InvalidToken;
        }

        // 4. Emplear nuestro hasher Argon genérico y cambiar la clave en Base de datos
        var newHashedValue = passwordHasher.HashPassword(newPassword);
        await userStore.UpdatePasswordHashAsync(user.Id, newHashedValue, cancellationToken);

        // 5. Rotar tokens de sesión y actualizar cachés (Revoca el SecurityStamp previniendo ataques de Replay o sesiones fantasmas)
        await sessionOrchestrator.RevokeAllSessionsAsync(user.Id, cancellationToken);

        // 6. Bloquear este token de cualquier iteración sucesiva
        await passwordResetStore.MarkAsUsedAsync(incomingHash, cancellationToken);

        // 7. Señalizar el éxito por el dispatcher general
        logger.LogInformation("Cambio verificado exitosamente vía Token de Recarga para el Usuario {UserId}", user.Id);
        await eventDispatcher.DispatchAsync(new AuthEvent 
        {
            EventType = AuthEventType.PasswordResetCompleted,
            UserId = user.Id
        }, cancellationToken);

        return PasswordResetResult.Success;
    }

    /// <summary>
    /// Deriva internamente un vector probabilísticamente seguro a URL seguras compatibles para hiperenlaces de tokens generados desde <see cref="CreateUrlSafeCSPRNGToken"/>
    /// </summary>
    private static string CreateUrlSafeCSPRNGToken(int size = 32)
    {
        var rawBytes = RandomNumberGenerator.GetBytes(size);
        return Base64UrlEncode(rawBytes);
    }

    /// <summary>
    /// Acuña de un token crudo (string UTF-8 base) al estándar derivado y comprobable unificado de la base de tablas.
    /// Todo token validado/creado en este módulo terminará pasando primero por la licuadora antes de confrontar a BD o ser insertado.
    /// </summary>
    private static string ComputeTokenHash(string rawToken)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawToken);
        var hash = SHA256.HashData(bytes);
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }
}
