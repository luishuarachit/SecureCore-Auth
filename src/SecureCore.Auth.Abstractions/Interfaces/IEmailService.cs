namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para envío de emails genérico.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta interfaz reemplaza y extiende IResetTokenMailer. Unifica
/// el envío de emails para password reset, códigos MFA, y otras notificaciones.
///
/// El implementador puede usar SendGrid, MailKit, AWS SES, etc.
///
/// REQUISITO DE REGISTRO: SecureCore NO registra una implementación real.
/// Si no registras la tuya, se usa NullEmailService por defecto (registrado con
/// TryAddScoped), que NO envía y lanza InvalidOperationException al intentar
/// usarlo. Registra tu implementación ANTES de AddMfa()/AddPasswordAuthentication():
///   services.AddScoped<IEmailService, MyEmailService>();
/// </remarks>
public interface IEmailService
{
    /// <summary>
    /// Envía un email con contenido HTML o texto plano.
    /// </summary>
    /// <param name="to">Destinatario.</param>
    /// <param name="subject">Asunto.</param>
    /// <param name="htmlBody">Cuerpo en HTML (alternativo a textBody).</param>
    /// <param name="textBody">Cuerpo en texto plano.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task SendAsync(
        string to,
        string subject,
        string? htmlBody = null,
        string? textBody = null,
        CancellationToken cancellationToken = default);
}
