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
    /// Método de autenticación con el que se creó la sesión (valor del claim "amr", RFC 8176).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (auditoría): el claim <c>amr</c> describe CÓMO se autenticó el sujeto y debe
    /// sobrevivir a la rotación del refresh token: sin esto, una sesión iniciada con MFA o
    /// passkey se re-emite tras el primer refresh SIN <c>amr</c>, degradando el aseguramiento
    /// que un resource server autoriza por ese claim. Se persiste en la sesión y se propaga en
    /// cada rotación.
    /// </remarks>
    public string? AuthMethod { get; init; }

    /// <summary>
    /// Detalle del método MFA (valor del claim "mfa_method") con el que se creó la sesión.
    /// </summary>
    public string? MfaMethod { get; init; }

    /// <summary>
    /// Verifica si el token ha expirado.
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiresAtUtc;

    /// <summary>
    /// Verifica si el token es activo (no revocado, no expirado, no reemplazado).
    /// </summary>
    public bool IsActive => !IsRevoked && !IsExpired && ReplacedByTokenHash is null;
}
