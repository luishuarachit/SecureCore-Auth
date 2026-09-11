namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Resultado del envío de un código OTP de step-up (verify-action).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El cliente autenticado recibe un resultado explícito, pero los
/// mensajes de error son genéricos (sin oráculo de enumeración ni de estado del
/// usuario). Un "false" puede indicar usuario inexistente, canal no soportado,
/// rate limiting o fallo de entrega; el host no debe distinguirlos en la UI.
/// </remarks>
public sealed record VerifyActionSendResult(
    bool Success,
    string? ErrorMessage = null);

/// <summary>
/// Resultado de la validación de un código OTP de step-up (verify-action).
/// </summary>
/// <remarks>
/// DIDÁCTICA: "Código inválido" es la respuesta única para código equivocado,
/// expirado o ya consumido (single-use). No se distingue cuál de los tres casos
/// ocurrió, para no orientar al atacante.
/// </remarks>
public sealed record VerifyActionVerifyResult(
    bool Success,
    string? ErrorMessage = null);
