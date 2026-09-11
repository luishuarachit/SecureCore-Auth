namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Códigos de error del flujo de creación/cambio de contraseña (S3, A-22).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los endpoints traducen estos códigos a respuestas HTTP y mensajes
/// genéricos. El código es para que el host distinga programáticamente la rama
/// (crear vs cambiar, OTP inválido vs política), sin depender del texto.
/// </remarks>
public static class ChangePasswordError
{
    /// <summary>Se requiere una verificación previa (verify-action) para crear la contraseña.</summary>
    public const string VerifyActionRequired = "verify_action_required";

    /// <summary>La cuenta ya tiene una contraseña: use el flujo de cambio, no el de creación.</summary>
    public const string PasswordAlreadyExists = "password_already_exists";

    /// <summary>La cuenta no tiene contraseña: use el flujo de creación con verificación previa.</summary>
    public const string NoPasswordCreated = "no_password_created";

    /// <summary>La contraseña actual no coincide.</summary>
    public const string InvalidCurrentPassword = "invalid_current_password";

    /// <summary>La nueva contraseña no cumple la política mínima.</summary>
    public const string InvalidPasswordPolicy = "invalid_password_policy";

    /// <summary>Fallo genérico (usuario inexistente, etc.) — sin distinguir la causa.</summary>
    public const string GenericFailure = "change_password_failed";
}

/// <summary>
/// Resultado del flujo de creación/cambio de contraseña (S3, A-22).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Tras un cambio exitoso se rota el SecurityStamp y se revocan todas
/// las sesiones previas (cierra posibles atacantes). El resultado incluye el nuevo
/// par de tokens, emitido con el SecurityStamp NUEVO, para que el cliente los
/// adopte inmediatamente y no quede huérfano de la revocación.
/// </remarks>
public sealed record ChangePasswordResult(
    bool Success,
    string? ErrorCode = null,
    string? ErrorMessage = null,
    TokenResponse? Tokens = null);
