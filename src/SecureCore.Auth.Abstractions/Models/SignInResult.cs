namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Representa el resultado de un intento de inicio de sesión.
/// </summary>
/// <remarks>
/// DIDÁCTICA: La autenticación no es simplemente "éxito" o "fallo". Existen estados
/// intermedios como "necesita segundo factor" o "cuenta bloqueada". Usar un record
/// con propiedades estáticas predefinidas nos da un patrón similar a un enum pero
/// con la flexibilidad de agregar datos adicionales al resultado.
///
/// DIDÁCTICA (F6, A-25): <see cref="ErrorCode"/> (tipado por <see cref="SignInErrorCode"/>)
/// es una señal estructurada para el HOST. No exponerla a clientes no autenticados: distinguir
/// los códigos sería un oráculo de enumeración (p. ej. "esta cuenta no tiene contraseña").
/// </remarks>
public record SignInResult
{
    /// <summary>
    /// Indica si la autenticación fue completamente exitosa.
    /// </summary>
    public bool Succeeded { get; init; }

    /// <summary>
    /// Indica si se requiere un segundo factor de autenticación.
    /// </summary>
    public bool RequiresTwoFactor { get; init; }

    /// <summary>
    /// Indica si la cuenta está bloqueada temporalmente.
    /// </summary>
    public bool IsLockedOut { get; init; }

    /// <summary>
    /// Indica si el usuario debe registrar un método MFA antes de continuar.
    /// </summary>
    public bool RequiresTwoFactorRegistration { get; init; }

    /// <summary>
    /// Indica que la solicitud no envió ninguna credencial (password null). Señal de REQUEST
    /// uniforme: no revela si la cuenta es o no passwordless (F6, A-25).
    /// </summary>
    public bool RequiresPasswordlessCredential { get; init; }

    /// <summary>
    /// Código de error tipado para el HOST (F6, A-25). Serializable como string; aditivo.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: NO devolver este código a clientes no autenticados (oráculo de enumeración).
    /// </remarks>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Mensaje descriptivo del resultado (genérico para evitar enumeración de usuarios).
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Autenticación completamente exitosa.
    /// </summary>
    public static SignInResult Success => new()
    {
        Succeeded = true,
        ErrorCode = SignInErrorCode.None.ToString()
    };

    /// <summary>
    /// Credencial primaria válida, pero se requiere un segundo factor.
    /// </summary>
    public static SignInResult TwoFactorRequired => new()
    {
        RequiresTwoFactor = true,
        ErrorCode = SignInErrorCode.TwoFactorRequired.ToString()
    };

    /// <summary>
    /// Cuenta bloqueada temporalmente por demasiados intentos fallidos.
    /// </summary>
    public static SignInResult LockedOut => new()
    {
        IsLockedOut = true,
        ErrorCode = SignInErrorCode.AccountLockedOut.ToString(),
        Message = "La cuenta ha sido bloqueada temporalmente. Intente más tarde."
    };

    /// <summary>
    /// El usuario debe registrar un método MFA antes de poder continuar.
    /// </summary>
    public static SignInResult TwoFactorRegistrationRequired => new()
    {
        RequiresTwoFactorRegistration = true,
        ErrorCode = SignInErrorCode.TwoFactorRegistrationRequired.ToString()
    };

    /// <summary>
    /// No se envió ninguna credencial (password null). Señal de REQUEST uniforme (F6, A-25).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: el resultado NO depende del email consultado — se devuelve ANTES de tocar el
    /// store —, por lo que no constituye un oráculo de enumeración (mismo resultado para emails
    /// existentes o no). El host decide cómo continuar (p. ej. redirigir a la ceremonia passkey).
    /// </remarks>
    public static SignInResult PasswordlessRequiresCredential => new()
    {
        RequiresPasswordlessCredential = true,
        ErrorCode = SignInErrorCode.PasswordlessRequiresCredential.ToString(),
        Message = "Se requiere una credencial para iniciar sesión."
    };

    /// <summary>
    /// Credenciales inválidas. Mensaje genérico para evitar enumeración de usuarios.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: NUNCA decimos "el email no existe" o "la contraseña es incorrecta".
    /// Usamos un mensaje genérico para evitar que un atacante descubra si un email
    /// está registrado o no (ataque de enumeración de usuarios).
    /// </remarks>
    public static SignInResult Failed => new()
    {
        ErrorCode = SignInErrorCode.InvalidCredentials.ToString(),
        Message = "Usuario o contraseña incorrectos."
    };
}
