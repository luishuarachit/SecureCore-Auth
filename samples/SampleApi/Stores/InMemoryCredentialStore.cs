using System.Collections.Concurrent;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SampleApi.Stores;

/// <summary>
/// Implementación en memoria del ICredentialStore para la API de ejemplo.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este store gestiona las credenciales WebAuthn (Passkeys).
/// El CredentialId es un byte[] único generado por el autenticador del usuario.
/// Para usarlo como clave del diccionario, lo convertimos a Base64.
/// </remarks>
public sealed class InMemoryCredentialStore : ICredentialStore
{
    private readonly ConcurrentDictionary<string, StoredCredential> _credentials = new();

    private static string ToKey(byte[] credentialId) => Convert.ToBase64String(credentialId);

    /// <inheritdoc />
    public Task CreateAsync(StoredCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        _credentials[ToKey(credential.CredentialId)] = credential;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<StoredCredential?> FindByCredentialIdAsync(
        byte[] credentialId, CancellationToken cancellationToken = default)
    {
        _credentials.TryGetValue(ToKey(credentialId), out var credential);
        return ValueTask.FromResult(credential);
    }

    /// <inheritdoc />
    public ValueTask<IReadOnlyList<StoredCredential>> FindByUserIdAsync(
        string userId, CancellationToken cancellationToken = default)
    {
        var credentials = _credentials.Values
            .Where(c => c.UserId == userId)
            .ToList();

        return ValueTask.FromResult<IReadOnlyList<StoredCredential>>(credentials.AsReadOnly());
    }

    /// <inheritdoc />
    public Task UpdateSignatureCountAsync(
        byte[] credentialId,
        uint newSignatureCount,
        CancellationToken cancellationToken = default)
    {
        var key = ToKey(credentialId);
        if (_credentials.TryGetValue(key, out var credential))
        {
            var updated = credential with { SignatureCount = newSignatureCount };
            _credentials[key] = updated;
        }
        return Task.CompletedTask;
    }
}
