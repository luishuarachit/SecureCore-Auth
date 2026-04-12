namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Representa el resultado de un intento de inicio de sesión.
/// </summary>
/// <remarks>
/// DIDÁCTICA: La autenticación no es simplemente "éxito" o "fallo". Existen estados
/// intermedios como "necesita segundo factor" o "cuenta bloqueada". Usar un record
/// con propiedades estáticas predefinidas nos da un patrón similar a un enum pero
/// con la flexibilidad de agregar datos adicionales al resultado.
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
    /// Mensaje descriptivo del resultado (genérico para evitar enumeración de usuarios).
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Autenticación completamente exitosa.
    /// </summary>
    public static SignInResult Success => new() { Succeeded = true };

    /// <summary>
    /// Credencial primaria válida, pero se requiere un segundo factor.
    /// </summary>
    public static SignInResult TwoFactorRequired => new() { RequiresTwoFactor = true };

    /// <summary>
    /// Cuenta bloqueada temporalmente por demasiados intentos fallidos.
    /// </summary>
    public static SignInResult LockedOut => new()
    {
        IsLockedOut = true,
        Message = "La cuenta ha sido bloqueada temporalmente. Intente más tarde."
    };

    /// <summary>
    /// El usuario debe registrar un método MFA antes de poder continuar.
    /// </summary>
    public static SignInResult TwoFactorRegistrationRequired => new()
    {
        RequiresTwoFactorRegistration = true
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
        Message = "Usuario o contraseña incorrectos."
    };
}
