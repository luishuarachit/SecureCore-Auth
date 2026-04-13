namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para la persistencia y consulta de usuarios.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta interfaz sigue el patrón "Store" (almacén). La librería nunca accede
/// directamente a la base de datos. En su lugar, define qué operaciones necesita y deja
/// que el desarrollador final implemente esta interfaz con la tecnología que prefiera
/// (Entity Framework, Dapper, MongoDB, etc.). Esto se conoce como "Inversión de Dependencias"
/// (Principio SOLID #5).
/// </remarks>
public interface IUserStore
{
    /// <summary>
    /// Busca un usuario por su identificador único interno.
    /// </summary>
    /// <param name="userId">El ID único del usuario (generalmente un GUID).</param>
    /// <param name="cancellationToken">Token de cancelación para operaciones asíncronas.</param>
    /// <returns>La identidad del usuario o null si no existe.</returns>
    ValueTask<UserIdentity?> FindByIdAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca un usuario por su dirección de correo electrónico.
    /// </summary>
    /// <param name="email">Email del usuario (normalizado a minúsculas).</param>
    /// <param name="cancellationToken">Token de cancelación para operaciones asíncronas.</param>
    /// <returns>La identidad del usuario o null si no existe.</returns>
    ValueTask<UserIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca un usuario por su proveedor de autenticación externo (Google, GitHub, etc.).
    /// </summary>
    /// <param name="provider">Nombre del proveedor (ej: "Google", "GitHub").</param>
    /// <param name="providerKey">Identificador único del usuario en ese proveedor.</param>
    /// <param name="cancellationToken">Token de cancelación para operaciones asíncronas.</param>
    /// <returns>La identidad del usuario o null si no existe.</returns>
    ValueTask<UserIdentity?> FindByExternalProviderAsync(
        string provider,
        string providerKey,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Actualiza el hash de contraseña del usuario.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método permite aplicar cambios legítimos de credenciales,
    /// por ejemplo en el restablecimiento al perder contraseñas, o cuando se demanda
    /// la reactualización del resguardo hash en implementaciones legacy de la base de datos a un cifrado Argon2 actualizado.
    /// </remarks>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="newPasswordHash">El nuevo hash criptográfico a persistir (generalmente Argon2id).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task UpdatePasswordHashAsync(
        string userId,
        string newPasswordHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Actualiza el SecurityStamp de un usuario, invalidando todas sus sesiones activas.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El SecurityStamp es un GUID que actúa como "sello de seguridad".
    /// Cada vez que se cambia este valor, todos los tokens JWT que contengan el valor anterior
    /// en su claim "ssv" serán rechazados automáticamente por el middleware de validación.
    /// Esto permite implementar el "botón de pánico" para cerrar todas las sesiones.
    /// </remarks>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="newSecurityStamp">El nuevo GUID que reemplazará al anterior.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task UpdateSecurityStampAsync(
        string userId,
        string newSecurityStamp,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene el SecurityStamp actual del usuario.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El SecurityStamp actual (GUID como string).</returns>
    ValueTask<string?> GetSecurityStampAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Incrementa el contador de intentos fallidos de login.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este contador es fundamental para la protección contra fuerza bruta.
    /// Cada intento fallido incrementa el contador. Cuando alcanza el umbral configurado,
    /// la cuenta se bloquea temporalmente con duración exponencial.
    /// </remarks>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El número actualizado de intentos fallidos.</returns>
    Task<int> IncrementFailedAccessCountAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resetea el contador de intentos fallidos a cero (tras un login exitoso).
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task ResetFailedAccessCountAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Establece la fecha de fin del bloqueo de cuenta.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="lockoutEnd">Fecha/hora UTC en que expira el bloqueo. Null para desbloquear.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task SetLockoutEndAsync(
        string userId,
        DateTimeOffset? lockoutEnd,
        CancellationToken cancellationToken = default);
}
