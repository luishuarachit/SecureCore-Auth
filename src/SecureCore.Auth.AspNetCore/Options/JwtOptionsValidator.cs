using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.AspNetCore.Options;

/// <summary>
/// Validador personalizado para JwtOptions que falla rápido en startup.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este validador implementa IValidateOptions<JwtOptions> para detectar
/// errores de configuración en tiempo de startup, no en runtime cuando se genere
/// el primer token. Esto permite que el desarrollador detecte el error inmediatamente
/// durante el development, no en producción con usuarios en espera.
///
/// Validaciones realizadas:
/// - Issuer y Audience no son nulos/whitespace
/// - Algoritmo es soportado (HS256, RS256, ES256, ES384, ES512)
/// - SigningKey (HS256) tiene longitud mínima 32 caracteres
/// - PublicKey (RS256/ES256) está presente en validación
/// - PrivateKey (generación) tiene formato PEM válido
/// </remarks>
public class JwtOptionsValidator : IValidateOptions<JwtOptions>
{
    private const int MinSigningKeyLength = 32;
    private const string DevelopmentKeyPattern = "SuperSecretKeyForDevelopment";

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail("JwtOptions no puede ser null.");
        }

        var errors = new List<string>();

        // 1. Validar Issuer
        if (string.IsNullOrWhiteSpace(options.Issuer))
        {
            errors.Add("Jwt:Issuer es requerido y no puede estar vacío.");
        }

        // 2. Validar Audience
        if (string.IsNullOrWhiteSpace(options.Audience))
        {
            errors.Add("Jwt:Audience es requerido y no puede estar vacío.");
        }

        // 3. Validar Algoritmo
        if (string.IsNullOrWhiteSpace(options.Algorithm))
        {
            errors.Add("Jwt:Algorithm es requerido. Use HS256, RS256, ES256, ES384 o ES512.");
        }
        else
        {
            var algo = options.Algorithm.ToUpperInvariant();
            var supportedAlgorithms = new[] { "HS256", "RS256", "ES256", "ES384", "ES512" };
            if (!supportedAlgorithms.Contains(algo))
            {
                errors.Add($"Jwt:Algorithm '{options.Algorithm}' no es soportado. " +
                    $"Use uno de: {string.Join(", ", supportedAlgorithms)}");
            }

            // 4. Validar claves según el algoritmo
            if (algo == "HS256")
            {
                if (string.IsNullOrEmpty(options.SigningKey))
                {
                    errors.Add("Jwt:SigningKey es requerido para HS256.");
                }
                else if (options.SigningKey.Length < MinSigningKeyLength)
                {
                    errors.Add($"Jwt:SigningKey debe tener mínimo {MinSigningKeyLength} caracteres para HS256. " +
                        $"Actual: {options.SigningKey.Length}.");
                }

                // Advertencia: Detectar clave de desarrollo
                if (options.SigningKey.Contains(DevelopmentKeyPattern, StringComparison.OrdinalIgnoreCase))
                {
                    errors.Add($"⚠️  CRÍTICO: Estás usando una clave de DESARROLLO en Jwt:SigningKey. " +
                        $"Esta clave NO es segura para producción. Reemplázala con un valor único y secreto.");
                }
            }
            else if (algo.StartsWith("RS") || algo.StartsWith("ES"))
            {
                // RS256, ES256, ES384, ES512 requieren claves asimétricas
                if (string.IsNullOrEmpty(options.PrivateKey))
                {
                    errors.Add($"Jwt:PrivateKey es requerido para {options.Algorithm}.");
                }
                else if (!IsValidPemFormat(options.PrivateKey))
                {
                    errors.Add($"Jwt:PrivateKey no tiene formato PEM válido. " +
                        $"Debe comenzar con -----BEGIN RSA PRIVATE KEY----- o -----BEGIN EC PRIVATE KEY-----");
                }

                // Para validación en lado cliente, se puede requerir PublicKey
                // Pero es opcional si solo se usa para generar tokens
                if (!string.IsNullOrEmpty(options.PublicKey) && !IsValidPemFormat(options.PublicKey))
                {
                    errors.Add("Jwt:PublicKey no tiene formato PEM válido.");
                }
            }
        }

        if (errors.Count > 0)
        {
            return ValidateOptionsResult.Fail(string.Join(" ", errors));
        }

        return ValidateOptionsResult.Success;
    }

    /// <summary>
    /// Valida que el formato PEM sea reconocible (no valida el contenido real, solo el formato).
    /// </summary>
    private static bool IsValidPemFormat(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem))
        {
            return false;
        }

        // PEM debe contener las líneas de inicio/fin
        var validPemHeaders = new[]
        {
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----"
        };

        return validPemHeaders.Any(header => pem.Contains(header));
    }
}

/// <summary>
/// Validador adicional para detectar configuraciones inseguras en producción.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este validador es un extra que verifica el entorno (environment)
/// para alertar sobre configuraciones inseguras en producción.
/// Por ejemplo, usar HS256 en lugar de RS256/ES256 puede ser aceptable para
/// desarrollo pero riesgoso para producción distribuida.
/// </remarks>
public class JwtProductionSecurityValidator : IValidateOptions<JwtOptions>
{
    private readonly string _environment;

    public JwtProductionSecurityValidator(string environment = "Production")
    {
        _environment = environment;
    }

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, JwtOptions options)
    {
        if (options is null || _environment != "Production")
        {
            return ValidateOptionsResult.Success;
        }

        var warnings = new List<string>();

        // En producción, se recomienda RS256/ES256 sobre HS256
        if (options.Algorithm?.ToUpperInvariant() == "HS256")
        {
            warnings.Add("⚠️  En producción, se recomienda usar RS256 o ES256 (asimétrico) en lugar de HS256 (simétrico). " +
                "HS256 requiere compartir la misma clave entre múltiples servicios.");
        }

        // Log warnings pero no fallar (cambiar a return Success con logging)
        if (warnings.Count > 0)
        {
            System.Diagnostics.Debug.WriteLine("JWT Security Warnings: " + string.Join(" ", warnings));
        }

        return ValidateOptionsResult.Success;
    }
}
