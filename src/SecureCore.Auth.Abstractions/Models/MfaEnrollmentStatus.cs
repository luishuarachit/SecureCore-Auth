using System.Text.Json.Serialization;

namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Estado del enrollment de autenticación multifactor (MFA).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F6): se serializa como string en JSON (JsonStringEnumConverter) para que las
/// respuestas del framework (p. ej. <c>GET /auth/me</c>) expongan "Enrolled"/"Pending" y no
/// enteros opacos al consumidor.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum MfaEnrollmentStatus
{
    /// <summary>
    /// El usuario no ha iniciado enrollment MFA.
    /// </summary>
    None = 0,

    /// <summary>
    /// Enrollment en proceso (TOTP/email no verificado).
    /// </summary>
    Pending = 1,

    /// <summary>
    /// MFA activo y verificado.
    /// </summary>
    Enrolled = 2,

    /// <summary>
    /// MFA deshabilitado por el usuario.
    /// </summary>
    Disabled = 3
}
