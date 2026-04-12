namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Entrada de un Refresh Token almacenada en la base de datos.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los Refresh Tokens se organizan en "familias" (FamilyId).
/// Cuando se rota un token, el nuevo hereda el FamilyId del anterior.
/// Esto permite revocar toda la cadena si se detecta un reuso sospechoso.
///
/// Flujo de rotación:
/// Token_A (FamilyId: "abc") → se rota → Token_B (FamilyId: "abc") → se rota → Token_C (FamilyId: "abc")
/// Si alguien reusa Token_A → se revocan Token_A, Token_B y Token_C (toda la familia "abc").
/// </remarks>
public record RefreshTokenEntry
{
    /// <summary>
    /// Hash SHA-256 del Refresh Token (nunca se almacena en texto plano).
    /// </summary>
    public required string TokenHash { get; init; }

    /// <summary>
    /// Identificador de la familia de rotación (todos los tokens derivados comparten este ID).
    /// </summary>
    public required string FamilyId { get; init; }

    /// <summary>
    /// ID del usuario propietario de la sesión.
    /// </summary>
    public required string UserId { get; init; }

    /// <summary>
    /// Fecha/hora UTC de creación del token.
    /// </summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// Fecha/hora UTC de expiración del token.
    /// </summary>
    public required DateTime ExpiresAtUtc { get; init; }

    /// <summary>
    /// Indica si el token ha sido revocado.
    /// </summary>
    public bool IsRevoked { get; init; }

    /// <summary>
    /// Hash del token que reemplazó a este (para trazabilidad en la cadena de rotación).
    /// </summary>
    public string? ReplacedByTokenHash { get; init; }

    /// <summary>
    /// Fecha/hora UTC en que fue reemplazado (para calcular el periodo de gracia).
    /// </summary>
    public DateTime? ReplacedAtUtc { get; init; }

    /// <summary>
    /// Verifica si el token ha expirado.
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;

    /// <summary>
    /// Verifica si el token es activo (no revocado, no expirado, no reemplazado).
    /// </summary>
    public bool IsActive => !IsRevoked && !IsExpired && ReplacedByTokenHash is null;
}
