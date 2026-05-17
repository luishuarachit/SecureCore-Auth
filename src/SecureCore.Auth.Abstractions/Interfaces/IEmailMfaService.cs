namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para envío de códigos MFA por email.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este servicio usa IEmailService (reemplazo de IResetTokenMailer)
/// para enviar el código. El código se genera y guarda con hash SHA-256 en
/// la sesión MFA temporal.
/// </remarks>
public interface IEmailMfaService
{
    /// <summary>
    /// Genera un código numérico aleatorio de la longitud especificada.
    /// </summary>
    /// <param name="length">Número de dígitos (6-8).</param>
    /// <returns>Código numérico como string.</returns>
    string GenerateCode(int length = 6);

    /// <summary>
    /// Envía el código MFA por email al usuario.
    /// </summary>
    /// <param name="toEmail">Email del destinatario.</param>
    /// <param name="code">Código a enviar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task SendCodeAsync(string toEmail, string code, CancellationToken cancellationToken = default);
}