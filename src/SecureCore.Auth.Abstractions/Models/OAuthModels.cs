using System;

namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Representa los tokens persistidos de un proveedor externo para un usuario.
/// </summary>
public record ExternalTokenEntry
{
    public required string UserId { get; init; }
    public required string Provider { get; init; } // ej. "Google", "GitHub"
    public required string ProviderKey { get; init; } // El 'sub' o ID del usuario en el proveedor
    public required string AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public required string[] Scopes { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Resultado de un intento de validar la identidad con un proveedor externo.
/// </summary>
public record OAuthIdentityResult
{
    public bool Succeeded { get; init; }
    public string? ProviderKey { get; init; } // "sub" del proveedor
    public string? Email { get; init; }
    public string? DisplayName { get; init; }
    public string? AvatarUrl { get; init; }
    public bool EmailVerified { get; init; }

    // Tokens del PROVEEDOR
    public string? AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public string[]? Scopes { get; init; }
    public DateTimeOffset? TokenExpiresAt { get; init; }

    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }

    public static OAuthIdentityResult Failure(string code, string message) =>
        new() { Succeeded = false, ErrorCode = code, ErrorMessage = message };
}

/// <summary>
/// Resultado del proceso de renovar el token de un proveedor externo.
/// </summary>
public record ExternalTokenRefreshResult(
    bool Succeeded,
    string? NewAccessToken,
    DateTimeOffset? ExpiresAt,
    string? ErrorMessage);

/// <summary>
/// Representa la solicitud de validación que llega desde el frontend.
/// Puede ser un código de autorización (Flujo A) o un id_token (Flujo B).
/// </summary>
public record OAuthValidationRequest
{
    /// <summary>
    /// Flujo A: Código de autorización
    /// </summary>
    public string? Code { get; init; }

    /// <summary>
    /// Flujo A: State original (para validar)
    /// </summary>
    public string? State { get; init; }
    
    /// <summary>
    /// Flujo A: La URI de redirección que se usó.
    /// </summary>
    public string? RedirectUri { get; init; }

    /// <summary>
    /// Flujo A: Nonce original que fue almacenado junto al State para validación anti-replay.
    /// </summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// Flujo B: Token del proveedor emitido al frontend.
    /// </summary>
    public string? IdToken { get; init; }
}

/// <summary>
/// Representa la URL generada para redirigir al usuario al proveedor.
/// </summary>
public record OAuthAuthorizationUrl(string Url);

/// <summary>
/// Opciones configuradas al procesar el inicio de sesión OAuth.
/// </summary>
public class OAuthSignInOptions
{
    public bool AllowImplicitRegistration { get; set; }
    public bool PersistProviderTokens { get; set; }
    public Type? UserFactoryType { get; set; }
}

/// <summary>
/// Resultado de un proceso de SignIn or Register mediante OAuth.
/// </summary>
public record OAuthSignInResult
{
    public bool Succeeded { get; init; }
    public TokenResponse? Tokens { get; init; }
    public string? UserId { get; init; }
    public bool IsNewUser { get; init; }
    public bool IsLockedOut { get; init; }
    public string? ErrorMessage { get; init; }

    public static OAuthSignInResult Success(TokenResponse tokens, string userId, bool isNewUser) =>
        new() { Succeeded = true, Tokens = tokens, UserId = userId, IsNewUser = isNewUser };
        
    public static OAuthSignInResult Failure(string message) =>
        new() { Succeeded = false, ErrorMessage = message };
        
    public static OAuthSignInResult ProviderNotConfigured(string provider) =>
        new() { Succeeded = false, ErrorMessage = $"Provider '{provider}' is not configured." };
        
    public static OAuthSignInResult LockedOutResult() =>
        new() { Succeeded = false, IsLockedOut = true, ErrorMessage = "User is locked out." };
        
    public static OAuthSignInResult UserNotFoundResult() =>
        new() { Succeeded = false, ErrorMessage = "User not found and implicit registration is disabled." };
}
