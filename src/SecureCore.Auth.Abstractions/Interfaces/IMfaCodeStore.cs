namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para almacenar y validar códigos MFA temporales.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta interfaz sigue el patrón de Store Pattern usado en todo el
/// framework (IUserStore, ISessionStore, etc.). Permite al consumidor decidir
/// dónde y cómo almacenar los códigos: en memoria, Redis, base de datos, etc.
///
/// La implementación por defecto es DistributedCacheMfaCodeStore, que usa
/// IDistributedCache (compatible con MemoryCache, Redis, SQL Server).
///
/// SEGURIDAD: El código NUNCA se almacena en texto plano. Se recibe ya hasheado
/// (SHA-256) y se compara con CryptographicOperations.FixedTimeEquals para
/// prevenir timing attacks.
/// </remarks>
public interface IMfaCodeStore
{
    /// <summary>
    /// Almacena el hash de un código MFA con tiempo de expiración.
    /// </summary>
    /// <param name="key">Clave única (formato: "mfa_email_code:{userId}:{sessionToken}").</param>
    /// <param name="codeHash">Hash SHA-256 del código en formato hex.</param>
    /// <param name="ttl">Tiempo de vida del código.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task StoreCodeHashAsync(string key, string codeHash, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>
    /// Valida un código contra el hash almacenado y lo elimina (single-use).
    /// </summary>
    /// <param name="key">Clave única.</param>
    /// <param name="code">Código en texto plano proporcionado por el usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si el código es válido y fue eliminado; false si no existe o no coincide.</returns>
    Task<bool> ValidateAndRemoveCodeAsync(string key, string code, CancellationToken cancellationToken = default);
}
