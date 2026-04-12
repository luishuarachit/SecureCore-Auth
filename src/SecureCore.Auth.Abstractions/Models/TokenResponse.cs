namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Respuesta que contiene el par de tokens generados tras una autenticación exitosa.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta respuesta contiene todo lo que el cliente necesita para mantener
/// una sesión autenticada:
/// - AccessToken (JWT): token corto que se envía en cada petición (header Authorization).
/// - RefreshToken: token largo que solo se usa para obtener un nuevo AccessToken.
/// - ExpiresAt: momento exacto en que el AccessToken expira (el cliente puede anticiparse).
/// </remarks>
public record TokenResponse(
    string AccessToken,
    string RefreshToken,
    DateTimeOffset ExpiresAt);
