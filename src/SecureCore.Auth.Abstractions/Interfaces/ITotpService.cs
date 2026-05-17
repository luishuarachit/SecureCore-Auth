namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para operaciones TOTP (Time-based One-Time Password).
/// </summary>
/// <remarks>
/// DIDÁCTICA: TOTP está basado en el estándar RFC 6238. Usa el algoritmo HMAC
/// con una clave secreta de 20 bytes (Base32) y el timestamp actual en intervalos
/// de 30 segundos. El código generado es de 6 dígitos.
///
/// La librería no implementa crypto - delegamos al estándar RFC 6238 puro
/// usando System.Security.Cryptography (HMACSHA1).
/// </remarks>
public interface ITotpService
{
    /// <summary>
    /// Genera un secreto TOTP aleatorio de 20 bytes (Base32).
    /// </summary>
    /// <returns>Secreto en formato Base32 (string de 32 caracteres).</returns>
    string GenerateSecret();

    /// <summary>
    /// Genera el URI otpauth:// para QR code o entrada manual.
    /// </summary>
    /// <param name="secret">Secreto Base32.</param>
    /// <param name="accountName">Email/nombre del usuario.</param>
    /// <param name="issuer">Nombre de la aplicación (shown en el app).</param>
    /// <returns>URI otpauth://totp/...</returns>
    string GenerateAuthUri(string secret, string accountName, string issuer);

    /// <summary>
    /// Valida un código TOTP, aceptando ventana de ±1 paso (30 segundos).
    /// </summary>
    /// <param name="secret">Secreto Base32.</param>
    /// <param name="code">Código de 6 dígitos.</param>
    /// <returns>True si el código es válido.</returns>
    bool ValidateCode(string secret, string code);

    /// <summary>
    /// Genera códigos de recuperación (one-time use).
    /// </summary>
    /// <param name="count">Cantidad de códigos.</param>
    /// <returns>Lista de códigos legibles (no hasheados).</returns>
    List<string> GenerateRecoveryCodes(int count);
}