using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para la persistencia y consulta de sesiones (Refresh Tokens).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El ISessionStore gestiona el ciclo de vida de los Refresh Tokens.
/// A diferencia del Access Token (JWT) que vive en memoria del cliente y no se persiste,
/// el Refresh Token SÍ se guarda en base de datos para poder revocarlo.
/// Se recomienda que la implementación use una base de datos SQL para persistencia
/// con una capa de caché (Redis) para las verificaciones frecuentes.
/// </remarks>
public interface ISessionStore
{
    /// <summary>
    /// Almacena un nuevo Refresh Token en la base de datos.
    /// </summary>
    /// <param name="entry">La entrada con los datos del token (hash, familia, usuario, fechas).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task CreateAsync(RefreshTokenEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca un Refresh Token por su hash.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Nunca almacenamos el Refresh Token en texto plano. Igual que con
    /// las contraseñas, guardamos un hash (SHA-256) del token. Cuando el cliente
    /// envía su token, lo hasheamos y lo comparamos con el hash almacenado.
    /// </remarks>
    /// <param name="tokenHash">Hash SHA-256 del Refresh Token.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La entrada del token o null si no existe.</returns>
    ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(
        string tokenHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoca (invalida) un Refresh Token específico.
    /// </summary>
    /// <param name="tokenHash">Hash del token a revocar.</param>
    /// <param name="replacedByTokenHash">Hash del token que lo reemplaza (para trazabilidad).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task RevokeAsync(
        string tokenHash,
        string? replacedByTokenHash = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoca todos los Refresh Tokens de una familia (cadena de rotación).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Cada vez que un token se rota, el nuevo token hereda el mismo FamilyId.
    /// Si se detecta un reuso de un token ya rotado (posible robo), se revoca toda la familia
    /// para cortar inmediatamente cualquier acceso del atacante.
    /// </remarks>
    /// <param name="familyId">Identificador de la familia de tokens.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task RevokeByFamilyAsync(string familyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revoca todos los Refresh Tokens de un usuario (cierre de sesión global).
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task RevokeAllByUserAsync(string userId, CancellationToken cancellationToken = default);
}
