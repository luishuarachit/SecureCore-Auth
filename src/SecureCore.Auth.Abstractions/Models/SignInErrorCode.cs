namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Código de error tipado del resultado de un intento de inicio de sesión (F6, A-25).
/// </summary>
/// <remarks>
/// DIDÁCTICA (S6): el <c>ErrorCode</c> de <see cref="SignInResult"/> es una señal estructurada
/// para el HOST (programática, sin parsear mensajes). NO debe exponerse tal cual a clientes no
/// autenticados: distinguir <c>InvalidCredentials</c> de <c>PasswordlessRequiresCredential</c>
/// revelaría si una cuenta tiene o no contraseña (oráculo de enumeración). El framework mantiene
/// sus respuestas HTTP uniformes; este código es para que el host decida su UX con seguridad.
///
/// Es aditivo y no-breaking: los estados booleanos pre-existentes de <see cref="SignInResult"/>
/// se conservan; <c>ErrorCode</c> es un valor por propiedad, serializable como string.
/// </remarks>
public enum SignInErrorCode
{
    /// <summary>Login exitoso (sin error).</summary>
    None,

    /// <summary>Credenciales inválidas (usuario desconocido o contraseña incorrecta; indistinguible por diseño).</summary>
    InvalidCredentials,

    /// <summary>Cuenta bloqueada temporalmente (LockoutManager o S1).</summary>
    AccountLockedOut,

    /// <summary>Credencial primaria válida; se requiere el segundo factor.</summary>
    TwoFactorRequired,

    /// <summary>Credencial primaria válida; el usuario debe registrar un método MFA antes de continuar.</summary>
    TwoFactorRegistrationRequired,

    /// <summary>
    /// No se envió ninguna credencial en la solicitud (password null). Es una señal a nivel de
    /// REQUEST, uniforme para todos los emails: nunca revela si la cuenta es o no passwordless.
    /// </summary>
    PasswordlessRequiresCredential,

    /// <summary>Fallo genérico no clasificado.</summary>
    GenericFailure
}
