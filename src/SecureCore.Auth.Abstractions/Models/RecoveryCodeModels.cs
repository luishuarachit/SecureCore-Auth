namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Estado de un recovery code consultado sin consumirlo (Fase 5, A-20).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El host recibe este tri-estado del orquestador (<c>RecoveryCodeOrchestrator.VerifyAsync</c>)
/// para decidir su lógica, pero NO debe exponerlo tal cual a clientes no autenticados: distinguir
/// "consumido" de "inválido" es información que facilita la enumeración y el replay tracking.
/// Los endpoints del framework responden solo válido/no-válido.
/// </remarks>
public enum RecoveryCodeStatus
{
    /// <summary>El código existe, está pendiente y puede redimirse.</summary>
    Valid,

    /// <summary>El código fue emitido en algún momento pero ya fue consumido (single-use).</summary>
    AlreadyUsed,

    /// <summary>El código nunca fue emitido, expiró o su lote fue invalidado.</summary>
    Invalid
}

/// <summary>
/// Resultado de la generación de un lote de recovery codes.
/// </summary>
/// <remarks>
/// DIDÁCTICA: la respuesta solo se envía UNA vez (la generación es el único momento en que el
/// texto plano de los códigos existe en memoria); el store persiste únicamente los hashes SHA-256.
/// </remarks>
/// <param name="Success">true si se generó un lote nuevo válido.</param>
/// <param name="Codes">Lista de códigos en texto plano (solo en el éxito y una única vez).
/// Null si el lote no se generó.</param>
/// <param name="ErrorMessage">Mensaje de error genérico, no-nulo solo cuando Success es false.</param>
public sealed record RecoveryCodeGenerationResult(
    bool Success,
    IReadOnlyList<string>? Codes = null,
    string? ErrorMessage = null)
{
    public static RecoveryCodeGenerationResult Ok(IReadOnlyList<string> codes) => new(true, codes);

    public static RecoveryCodeGenerationResult Fail(string message) => new(false, null, message);
}

/// <summary>
/// Resultado de la verificación de un recovery code sin consumirlo.
/// </summary>
/// <param name="IsValid">true si el código es <see cref="RecoveryCodeStatus.Valid"/> (redimible).</param>
/// <param name="Status">Estado detallado (válido/consumido/inválido) para el host.</param>
public sealed record RecoveryCodeVerificationResult(
    bool IsValid,
    RecoveryCodeStatus Status = RecoveryCodeStatus.Invalid)
{
    public static RecoveryCodeVerificationResult FromStatus(RecoveryCodeStatus status) =>
        new(status == RecoveryCodeStatus.Valid, status);
}

/// <summary>
/// Resultado de la redención (consumo single-use) de un recovery code.
/// </summary>
/// <remarks>
/// DIDÁCTICA: el éxito del <c>use</c> dispara el evento <c>RecoveryCodeRedeemed</c>; el host
/// decide entonces si rota el SecurityStamp o revoca sesiones (patrón de negocio, fuera del
/// framework). <c>LockedOut</c> permite al endpoint responder 429 sin revelar por qué.
/// </remarks>
/// <param name="Success">true si el código se consumió correctamente.</param>
/// <param name="LockedOut">true si la cuenta fue bloqueada temporalmente por anti-abuso (S1).</param>
/// <param name="ErrorMessage">Mensaje de error genérico, no-nulo solo cuando Success es false.</param>
public sealed record RecoveryCodeUseResult(
    bool Success,
    bool LockedOut = false,
    string? ErrorMessage = null)
{
    public static RecoveryCodeUseResult Ok() => new(true);

    public static RecoveryCodeUseResult Blocked() =>
        new(false, LockedOut: true, ErrorMessage: "Demasiados intentos. Intente más tarde.");

    public static RecoveryCodeUseResult Failed(string message) => new(false, ErrorMessage: message);
}
