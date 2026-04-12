namespace SecureCore.Auth.Abstractions;

/// <summary>
/// Credencial WebAuthn almacenada en la base de datos.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Cada vez que un usuario registra un dispositivo biométrico o llave de seguridad,
/// se genera un par de claves criptográficas. La clave privada queda en el dispositivo
/// (nunca sale de ahí), y la clave pública se almacena en el servidor usando este record.
/// </remarks>
public record StoredCredential
{
    /// <summary>
    /// ID único de la credencial asignado por el autenticador.
    /// </summary>
    public required byte[] CredentialId { get; init; }

    /// <summary>
    /// Clave pública del par criptográfico (la privada queda en el dispositivo).
    /// </summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// ID del usuario propietario de la credencial.
    /// </summary>
    public required string UserId { get; init; }

    /// <summary>
    /// Contador de firmas para detección de clonación.
    /// </summary>
    public uint SignatureCount { get; init; }

    /// <summary>
    /// Tipo de credencial (ej: "public-key").
    /// </summary>
    public string CredentialType { get; init; } = "public-key";

    /// <summary>
    /// Fecha de registro de la credencial.
    /// </summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// GUID del autenticador (para identificar el tipo de dispositivo).
    /// </summary>
    public Guid AaGuid { get; init; }

    /// <summary>
    /// Nombre amigable dado por el usuario al dispositivo (ej: "Mi iPhone", "YubiKey").
    /// </summary>
    public string? DeviceNickname { get; init; }
}
