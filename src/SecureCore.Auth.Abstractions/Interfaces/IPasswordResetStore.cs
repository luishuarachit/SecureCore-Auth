using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para la persistencia de tokens de restablecimiento de contraseña.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Al igual que <see cref="IUserStore"/> o <see cref="ISessionStore"/>,
/// esta interfaz sigue el principio de Inversión de Dependencias (SOLID #5).
/// La librería define QUÉ necesita; el desarrollador decide CÓMO almacenarlo
/// (SQL Server, PostgreSQL, Redis, etc.).
///
/// Los tokens nunca se persisten en texto plano. Solo se almacena su hash SHA-256.
/// Esto protege contra filtraciones de base de datos: si alguien accede a la tabla,
/// los hashes son inútiles sin el token crudo original.
/// </remarks>
public interface IPasswordResetStore
{
    /// <summary>
    /// Persiste una nueva entrada de token de restablecimiento.
    /// </summary>
    /// <param name="entry">La entrada con el hash del token, userId y fecha de expiración.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task StoreAsync(PasswordResetEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca una entrada de reset por el hash SHA-256 del token.
    /// </summary>
    /// <param name="tokenHash">Hash SHA-256 del token crudo (Base64Url).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La entrada si existe, o null si no fue encontrada.</returns>
    ValueTask<PasswordResetEntry?> FindByTokenHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Marca un token como ya utilizado, impidiendo su reuso.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Un token de reset es de "un solo uso". Una vez que el usuario
    /// establece su nueva contraseña, este token debe marcarse como consumido
    /// para prevenir ataques de replay (reproducción del mismo token).
    /// </remarks>
    /// <param name="tokenHash">Hash SHA-256 del token a invalidar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task MarkAsUsedAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Cuenta las solicitudes de reset recientes de un usuario en un periodo de tiempo.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método habilita el rate limiting a nivel de aplicación.
    /// Limitar el número de solicitudes por usuario/email por hora evita que un atacante
    /// bombardee el endpoint de "forgot-password" para agotar recursos o spamear.
    /// El rate limiting es opcional y se controla desde <see cref="Options.PasswordResetOptions.MaxRequestsPerHour"/>.
    /// </remarks>
    /// <param name="userId">ID del usuario a verificar.</param>
    /// <param name="since">Fecha a partir de la cual contar solicitudes.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Número de solicitudes de reset en el periodo indicado.</returns>
    ValueTask<int> CountRecentRequestsAsync(
        string userId,
        DateTime since,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Elimina todos los tokens expirados de la tabla. Útil para tareas de limpieza periódica.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (Nº9): Los tokens con estado <c>Pending</c>/<c>Failed</c> (email no
    /// entregado o en curso) y los <c>Used</c> permanecen huérfanos hasta su expiración
    /// natural. La librería NO programa esa limpieza: es responsabilidad del implementador
    /// invocar <c>DeleteExpiredAsync</c> de forma periódica (ej: Hangfire/BackgroundService
    /// diario) para no acumular filas innecesarias en la tabla de resets.
    /// </remarks>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task DeleteExpiredAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Actualiza el estado de entrega del email de un token de restablecimiento.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Método ADITIVO (default interface member). Las implementaciones existentes
    /// que no lo sobrescriban NO se rompen: el valor devuelto es un no-op y el estado de
    /// entrega quedará en <see cref="Models.PasswordResetDeliveryState.Pending"/>. Sobrescribirlo
    /// permite registrar <c>Dispatched</c>/<c>Failed</c> para auditoría y limpieza de tokens
    /// huérfanos (ver A-09).
    /// </remarks>
    /// <param name="tokenHash">Hash SHA-256 del token crudo (Base64Url).</param>
    /// <param name="state">Nuevo estado de entrega.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task UpdateDeliveryStateAsync(
        string tokenHash,
        Models.PasswordResetDeliveryState state,
        CancellationToken cancellationToken = default)
        => Task.CompletedTask;
}
