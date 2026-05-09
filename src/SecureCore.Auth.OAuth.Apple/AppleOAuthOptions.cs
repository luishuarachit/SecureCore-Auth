using System;

namespace SecureCore.Auth.OAuth.Apple;

/// <summary>
/// Opciones de configuración para el proveedor de Apple.
/// </summary>
public class AppleOAuthOptions
{
    /// <summary>
    /// El "Services ID" registrado en el Apple Developer Portal.
    /// Ejemplo: "com.tuempresa.auth"
    /// </summary>
    public required string ClientId { get; set; }

    /// <summary>
    /// Tu Apple Team ID (10 caracteres).
    /// </summary>
    public required string TeamId { get; set; }

    /// <summary>
    /// El ID de la llave privada (.p8) generada en el portal.
    /// </summary>
    public required string KeyId { get; set; }

    /// <summary>
    /// El contenido de la llave privada en formato PEM.
    /// </summary>
    public required string PrivateKey { get; set; }

    /// <summary>
    /// Scopes por defecto. Apple usualmente requiere "name" y "email".
    /// </summary>
    public string[] DefaultScopes { get; set; } = ["name", "email"];
}
