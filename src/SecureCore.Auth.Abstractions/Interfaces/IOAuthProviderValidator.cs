using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Contrato que deben implementar los proveedores OAuth (Google, GitHub, etc.) para integrarse con AuthCore.
/// Requiere altos estándares de seguridad (ej. validación JWKS, verificación de nonce).
/// </summary>
public interface IOAuthProviderValidator
{
    /// <summary>
    /// El nombre único del proveedor (ej. "Google", "GitHub").
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Flujo B: Valida un id_token emitido directamente por el proveedor al frontend.
    /// Solo verifica la firma JWKS + claims estándar (iss, aud, exp, nonce).
    /// </summary>
    Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Flujo A (Paso 1): Construye la URL de autorización a la cual redirigir al usuario.
    /// El state y nonce deben ser generados externamente por el orquestador (protección anti-replay).
    /// </summary>
    OAuthAuthorizationUrl BuildAuthorizationUrl(string redirectUri, string[] scopes, string state, string nonce);

    /// <summary>
    /// Flujo A (Paso 2): Intercambia un authorization_code temporal por tokens persistentes.
    /// Realiza una solicitud servidor a servidor (ej. /oauth2/token).
    /// </summary>
    Task<OAuthIdentityResult> ExchangeCodeAsync(string authorizationCode, string redirectUri, string? expectedNonce = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Renueva el access_token del proveedor usando su refresh_token.
    /// Retorna null si el proveedor no soporta renovación o el token fue revocado.
    /// </summary>
    Task<ExternalTokenRefreshResult> RefreshProviderAccessTokenAsync(string refreshToken, CancellationToken cancellationToken = default);
}
