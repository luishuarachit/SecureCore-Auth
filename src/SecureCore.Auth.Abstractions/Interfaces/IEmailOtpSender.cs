namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Canal de entrega del código OTP de step-up (verify-action).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Contrato mínimo y enfocado para el envío del código de verificación
/// de acciones sensibles. El orquestador <c>VerifyActionOrchestrator</c> ya conoce
/// la dirección de destino (la obtiene del usuario); este SPI solo transporta el
/// código. Implementaciones típicas: SMTP/SendGrid, o el adaptador por defecto que
/// delega en <see cref="IEmailService"/>.
/// </remarks>
public interface IEmailOtpSender
{
    /// <summary>
    /// Envía el código de verificación al destinatario.
    /// </summary>
    /// <param name="email">Correo del usuario al que enviar el código.</param>
    /// <param name="code">Código OTP en texto plano (solo viaja por el canal; nunca se persiste).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task SendAsync(string email, string code, CancellationToken cancellationToken = default);
}
