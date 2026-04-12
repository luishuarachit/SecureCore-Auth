namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para la persistencia de credenciales WebAuthn (Passkeys).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Las Passkeys (FIDO2/WebAuthn) requieren almacenar datos criptográficos
/// del dispositivo del usuario: la clave pública, el ID de la credencial, y un contador
/// de firmas que se incrementa en cada uso (para detectar clonación de dispositivos).
/// </remarks>
public interface ICredentialStore
{
    /// <summary>
    /// Almacena una nueva credencial WebAuthn tras el registro exitoso.
    /// </summary>
    /// <param name="credential">Datos de la credencial registrada.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task CreateAsync(StoredCredential credential, CancellationToken cancellationToken = default);

    /// <summary>
    /// Busca una credencial por su identificador único.
    /// </summary>
    /// <param name="credentialId">ID de la credencial (bytes codificados en base64url).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La credencial o null si no existe.</returns>
    ValueTask<StoredCredential?> FindByCredentialIdAsync(
        byte[] credentialId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene todas las credenciales registradas de un usuario.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Lista de credenciales del usuario.</returns>
    ValueTask<IReadOnlyList<StoredCredential>> FindByUserIdAsync(
        string userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Actualiza el contador de firmas de una credencial.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El contador de firmas es un mecanismo anti-clonación de FIDO2.
    /// Cada vez que un autenticador (ej: llave USB, huella dactilar) firma un challenge,
    /// incrementa su contador interno. Si el servidor recibe un contador menor o igual
    /// al almacenado, podría indicar que el dispositivo fue clonado.
    /// </remarks>
    /// <param name="credentialId">ID de la credencial.</param>
    /// <param name="newSignatureCount">Nuevo valor del contador.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task UpdateSignatureCountAsync(
        byte[] credentialId,
        uint newSignatureCount,
        CancellationToken cancellationToken = default);
}
