using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests para Argon2PasswordHasher — hashing y verificación de contraseñas.
/// </summary>
public class Argon2PasswordHasherTests
{
    private readonly Argon2PasswordHasher _hasher;

    public Argon2PasswordHasherTests()
    {
        // Usamos parámetros reducidos para que los tests ejecuten rápido
        var options = Options.Create(new Argon2Options
        {
            MemorySize = 1024,  // 1 MB (mínimo para tests)
            Iterations = 1,
            Parallelism = 1,
            SaltSize = 16,
            HashSize = 32
        });
        _hasher = new Argon2PasswordHasher(options);
    }

    [Fact]
    public void HashPassword_ReturnsArgon2idFormat()
    {
        // Act
        var hash = _hasher.HashPassword("TestPassword123!");

        // Assert — debe seguir el formato: $argon2id$v=19$m=...,t=...,p=...${salt}${hash}
        Assert.StartsWith("$argon2id$v=19$", hash);
        Assert.Equal(5, hash.Split('$', StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Fact]
    public void HashPassword_GeneratesUniqueSalts()
    {
        // Act — hashear la misma contraseña dos veces
        var hash1 = _hasher.HashPassword("SamePassword!");
        var hash2 = _hasher.HashPassword("SamePassword!");

        // Assert — los hashes deben ser diferentes (salt aleatorio)
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void VerifyPassword_CorrectPassword_ReturnsSuccess()
    {
        // Arrange
        var password = "MySecurePassword!123";
        var hash = _hasher.HashPassword(password);

        // Act
        var result = _hasher.VerifyPassword(hash, password);

        // Assert
        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void VerifyPassword_WrongPassword_ReturnsFailed()
    {
        // Arrange
        var hash = _hasher.HashPassword("CorrectPassword!");

        // Act
        var result = _hasher.VerifyPassword(hash, "WrongPassword!");

        // Assert
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void VerifyPassword_InvalidHashFormat_ReturnsFailed()
    {
        // Act
        var result = _hasher.VerifyPassword("not_a_valid_hash", "password");

        // Assert
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    [Fact]
    public void VerifyPassword_ParametersChanged_ReturnsSuccessRehashNeeded()
    {
        // Arrange — crear hash con parámetros originales
        var password = "TestRehash!123";
        var hash = _hasher.HashPassword(password);

        // Crear un nuevo hasher con parámetros diferentes
        var newOptions = Options.Create(new Argon2Options
        {
            MemorySize = 2048,  // Parámetro cambiado
            Iterations = 1,
            Parallelism = 1,
            SaltSize = 16,
            HashSize = 32
        });
        var newHasher = new Argon2PasswordHasher(newOptions);

        // Act — verificar con el nuevo hasher
        var result = newHasher.VerifyPassword(hash, password);

        // Assert — la contraseña es correcta, pero necesita rehash
        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, result);
    }

    [Fact]
    public void HashPassword_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => _hasher.HashPassword(null!));
    }

    [Fact]
    public void VerifyDummyPassword_DoesNotThrow()
    {
        // Act & Assert
        _hasher.VerifyDummyPassword("any_password");
    }

    [Fact]
    public void VerifyDummyPassword_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => _hasher.VerifyDummyPassword(null!));
    }
}
