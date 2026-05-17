using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación de IEmailMfaService.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este servicio genera códigos numéricos aleatorios y los envía
/// por email usando IEmailService (interfaz que el implementador debe proporcionar).
///
/// CÓMO GENERAR EL CÓDIGO:
/// - Usa RNGCryptoServiceProvider para obtener números criptográficamente seguros
/// - Longitud configurable (6-8 dígitos, por defecto 6)
/// - El código NO se almacena en la BD - se verifica directamente en memoria
///
/// SEGURIDAD:
/// - El código tiene tiempo de vida limitado (configurable, default 5 min)
/// - El email incluye instrucciones claras para el usuario
/// - El diseño es simple para evitar fugas de información
/// </remarks>
public sealed class EmailMfaService : IEmailMfaService
{
    private readonly IEmailService _emailService;
    private readonly MfaOptions _options;
    private readonly ILogger<EmailMfaService> _logger;

    public EmailMfaService(
        IEmailService emailService,
        IOptions<MfaOptions> options,
        ILogger<EmailMfaService> logger)
    {
        _emailService = emailService;
        _options = options.Value;
        _logger = logger;
    }

    public string GenerateCode(int length = 6)
    {
        var maxValue = (int)Math.Pow(10, length);
        var bytes = new byte[4];
        RandomNumberGenerator.Fill(bytes);
        var value = BitConverter.ToUInt32(bytes, 0) % maxValue;
        return value.ToString().PadLeft(length, '0');
    }

    public async Task SendCodeAsync(string toEmail, string code, CancellationToken cancellationToken = default)
    {
        var subject = $"Código de verificación - {_options.TotpIssuer}";
        var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .code {{ font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; 
                padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 20px 0; }}
        .footer {{ font-size: 12px; color: #666; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class='container'>
        <h2>Código de verificación MFA</h2>
        <p>Su código de verificación es:</p>
        <div class='code'>{code}</div>
        <p>Este código expira en {_options.EmailCodeLifetimeMinutes} minutos.</p>
        <div class='footer'>
            <p>Si no solicitó este código, ignore este mensaje.</p>
            <p>Generado por {_options.TotpIssuer}</p>
        </div>
    </div>
</body>
</html>";

        await _emailService.SendAsync(toEmail, subject, htmlBody, null, cancellationToken);

        _logger.LogDebug("Código MFA enviado a {Email}", toEmail);
    }
}