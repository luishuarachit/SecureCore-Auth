using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para la generación y validación de tokens (JWT + Refresh Tokens).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta interfaz separa la lógica de tokens del resto del sistema.
/// El Access Token (JWT) es un token corto (15 min por defecto) que el cliente
/// envía en cada petición. El Refresh Token es un token largo (7 días) que solo
/// se usa para obtener un nuevo Access Token cuando el anterior expira.
/// </remarks>
public interface ITokenService
{
    /// <summary>
    /// Genera un par de tokens (Access + Refresh) para un usuario autenticado.
    /// </summary>
    /// <param name="user">La identidad del usuario autenticado.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La respuesta con ambos tokens y su fecha de expiración.</returns>
    Task<TokenResponse> GenerateTokenPairAsync(
        UserIdentity user,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Genera únicamente un Access Token (JWT) para el usuario.
    /// </summary>
    /// <param name="user">La identidad del usuario.</param>
    /// <returns>El JWT como string codificado.</returns>
    string GenerateAccessToken(UserIdentity user);

    /// <summary>
    /// Genera un Refresh Token criptográficamente seguro.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El Refresh Token se genera con 32 bytes aleatorios usando
    /// RandomNumberGenerator (criptográficamente seguro) y se codifica en base64url.
    /// Nunca se almacena en texto plano; se guarda su hash SHA-256 en la base de datos.
    /// </remarks>
    /// <returns>El Refresh Token como string en base64url.</returns>
    string GenerateRefreshToken();

    /// <summary>
    /// Calcula el hash SHA-256 de un Refresh Token para almacenamiento seguro.
    /// </summary>
    /// <param name="refreshToken">El Refresh Token en texto plano.</param>
    /// <returns>El hash SHA-256 como string hexadecimal.</returns>
    string HashRefreshToken(string refreshToken);
}
