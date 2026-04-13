namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para el envío de emails de restablecimiento de contraseña.
/// </summary>
/// <remarks>
/// DIDÁCTICA: La librería es completamente agnóstica al proveedor de email.
/// No incluye ninguna dependencia de SendGrid, MailKit, SMTP u otro servicio externo.
/// En su lugar, define este contrato y delega la responsabilidad al integrador.
///
/// Ejemplo de implementación con SendGrid:
/// <code>
/// public class SendGridResetMailer : IResetTokenMailer
/// {
///     public async Task SendResetEmailAsync(string toEmail, string rawToken, CancellationToken ct)
///     {
///         var resetUrl = $"https://miapp.com/reset-password?token={rawToken}";
///         // ... enviar email con la URL de reset
///     }
/// }
/// </code>
///
/// Registro en Program.cs:
/// <code>
/// builder.Services.AddScoped&lt;IResetTokenMailer, SendGridResetMailer&gt;();
/// </code>
/// </remarks>
public interface IResetTokenMailer
{
    /// <summary>
    /// Envía un email con el token de restablecimiento al usuario.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El parámetro <paramref name="rawToken"/> es el token en texto plano,
    /// codificado en Base64Url. Este es el único momento en que el sistema expone el
    /// token crudo. Inmediatamente después de esta llamada, solo el hash SHA-256
    /// permanece en la base de datos.
    ///
    /// El implementador debe incluir <paramref name="rawToken"/> en un enlace tipo:
    /// <c>https://miapp.com/reset-password?token={rawToken}</c>
    ///
    /// IMPORTANTE: Si este método lanza una excepción, el token NO se guardará en la
    /// base de datos, y el usuario deberá realizar una nueva solicitud. Esto asegura
    /// que never haya un token válido en la BD sin que el email haya llegado al usuario.
    /// </remarks>
    /// <param name="toEmail">Dirección de correo del destinatario.</param>
    /// <param name="rawToken">El token de reset en texto plano (Base64Url, 32+ bytes).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task SendResetEmailAsync(
        string toEmail,
        string rawToken,
        CancellationToken cancellationToken = default);
}
