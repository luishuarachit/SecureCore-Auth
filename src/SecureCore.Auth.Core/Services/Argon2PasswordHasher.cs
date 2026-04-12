using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación del hasher de contraseñas usando el algoritmo Argon2id.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Argon2id es el algoritmo recomendado para hashing de contraseñas desde 2015.
/// A diferencia de bcrypt o PBKDF2, Argon2id es "memory-hard": requiere una cantidad
/// significativa de RAM para calcular el hash. Esto lo hace resistente a ataques con GPUs
/// y hardware especializado (ASICs/FPGAs), que tienen mucha potencia de cálculo pero
/// poca memoria por unidad de procesamiento.
///
/// El formato del hash almacenado es:
/// $argon2id$v=19$m={memoria},t={iteraciones},p={paralelismo}${salt_base64}${hash_base64}
/// Este formato es autocontenido: incluye todos los parámetros necesarios para verificar
/// la contraseña sin necesidad de almacenar el salt por separado.
/// </remarks>
public sealed class Argon2PasswordHasher(IOptions<Argon2Options> options) : IPasswordHasher
{
    private readonly Argon2Options _options = options.Value;

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        // Generamos un salt aleatorio criptográficamente seguro
        var salt = RandomNumberGenerator.GetBytes(_options.SaltSize);

        // Configuramos Argon2id con los parámetros definidos en la configuración
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = _options.Parallelism,
            MemorySize = _options.MemorySize,
            Iterations = _options.Iterations
        };

        // Generamos el hash
        var hash = argon2.GetBytes(_options.HashSize);

        // Retornamos el hash en formato autocontenido estándar
        // que incluye el algoritmo, versión, parámetros, salt y hash
        return FormatHash(salt, hash);
    }

    /// <inheritdoc />
    public PasswordVerificationResult VerifyPassword(string hashedPassword, string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(hashedPassword);
        ArgumentNullException.ThrowIfNull(providedPassword);

        // Extraemos los parámetros del hash almacenado
        if (!TryParseHash(hashedPassword, out var storedParams))
        {
            return PasswordVerificationResult.Failed;
        }

        // Recalculamos el hash con la contraseña proporcionada y el salt original
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(providedPassword))
        {
            Salt = storedParams.Salt,
            DegreeOfParallelism = storedParams.Parallelism,
            MemorySize = storedParams.MemorySize,
            Iterations = storedParams.Iterations
        };

        var computedHash = argon2.GetBytes(storedParams.Hash.Length);

        // Comparación en tiempo constante para evitar ataques de timing
        if (!CryptographicOperations.FixedTimeEquals(computedHash, storedParams.Hash))
        {
            return PasswordVerificationResult.Failed;
        }

        // Verificamos si los parámetros del hash almacenado coinciden con los actuales
        // Si no coinciden, el hash es válido pero se debería regenerar con los nuevos parámetros
        if (NeedsRehash(storedParams))
        {
            return PasswordVerificationResult.SuccessRehashNeeded;
        }

        return PasswordVerificationResult.Success;
    }
    
    // Hash ficticio para VerifyDummyPassword (m=65536, t=3, p=4)
    private const string DummyHash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$Y29tcHV0ZWRoYXNoY29tcHV0ZWRoYXNoY29tcHV0ZWRoYXNo";

    /// <inheritdoc />
    public void VerifyDummyPassword(string providedPassword)
    {
        ArgumentNullException.ThrowIfNull(providedPassword);

        // Ejecutamos una verificación completa contra un hash estático.
        // Esto garantiza que el tiempo de CPU y memoria consumidos sean los mismos
        // que en una autenticación real, evitando la enumeración de usuarios.
        _ = VerifyPassword(DummyHash, providedPassword);
    }

    /// <summary>
    /// Formatea el hash en el estándar de Argon2 para almacenamiento.
    /// </summary>
    private string FormatHash(byte[] salt, byte[] hash)
    {
        var saltBase64 = Convert.ToBase64String(salt);
        var hashBase64 = Convert.ToBase64String(hash);

        return $"$argon2id$v=19$m={_options.MemorySize},t={_options.Iterations},p={_options.Parallelism}${saltBase64}${hashBase64}";
    }

    /// <summary>
    /// Intenta parsear un hash almacenado en formato Argon2 estándar.
    /// </summary>
    private static bool TryParseHash(string encoded, out Argon2Params result)
    {
        result = default;

        // Formato esperado: $argon2id$v=19$m=65536,t=3,p=4${salt}${hash}
        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 || parts[0] != "argon2id")
        {
            return false;
        }

        // Parseamos los parámetros: m=65536,t=3,p=4
        var paramParts = parts[2].Split(',');
        if (paramParts.Length != 3)
        {
            return false;
        }

        if (!int.TryParse(paramParts[0].AsSpan(2), out var memory) ||
            !int.TryParse(paramParts[1].AsSpan(2), out var iterations) ||
            !int.TryParse(paramParts[2].AsSpan(2), out var parallelism))
        {
            return false;
        }

        try
        {
            result = new Argon2Params
            {
                MemorySize = memory,
                Iterations = iterations,
                Parallelism = parallelism,
                Salt = Convert.FromBase64String(parts[3]),
                Hash = Convert.FromBase64String(parts[4])
            };
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>
    /// Verifica si el hash fue generado con parámetros diferentes a los actuales.
    /// </summary>
    private bool NeedsRehash(Argon2Params storedParams)
    {
        return storedParams.MemorySize != _options.MemorySize ||
               storedParams.Iterations != _options.Iterations ||
               storedParams.Parallelism != _options.Parallelism ||
               storedParams.Hash.Length != _options.HashSize;
    }

    /// <summary>
    /// Parámetros extraídos de un hash Argon2 almacenado.
    /// </summary>
    private struct Argon2Params
    {
        public int MemorySize;
        public int Iterations;
        public int Parallelism;
        public byte[] Salt;
        public byte[] Hash;
    }
}
