using System.Collections.Concurrent;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SampleApi.Stores;

/// <summary>
/// Implementación en memoria del ISessionStore para la API de ejemplo.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este store gestiona los Refresh Tokens. En producción,
/// se implementaría con una base de datos que soporte TTL automático
/// (ej: Redis con EXPIRE, o una tabla SQL con un job de limpieza).
///
/// El FamilyId es crucial: agrupa todos los tokens de una cadena de rotación.
/// Si se detecta reuso de un token rotado, se revocan TODOS los tokens
/// con el mismo FamilyId para cortar la cadena de un posible ataque.
/// </remarks>
public sealed class InMemorySessionStore : ISessionStore
{
    private readonly ConcurrentDictionary<string, RefreshTokenEntry> _tokens = new();

    /// <inheritdoc />
    public Task CreateAsync(RefreshTokenEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _tokens[entry.TokenHash] = entry;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        _tokens.TryGetValue(tokenHash, out var entry);
        return ValueTask.FromResult(entry);
    }

    /// <inheritdoc />
    public Task RevokeAsync(
        string tokenHash,
        string? replacedByTokenHash = null,
        CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(tokenHash, out var entry))
        {
            var updated = entry with
            {
                IsRevoked = true,
                ReplacedByTokenHash = replacedByTokenHash,
                ReplacedAtUtc = DateTime.UtcNow
            };
            _tokens[tokenHash] = updated;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeByFamilyAsync(string familyId, CancellationToken cancellationToken = default)
    {
        var familyTokens = _tokens.Values
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToList();

        foreach (var token in familyTokens)
        {
            var revoked = token with { IsRevoked = true };
            _tokens[token.TokenHash] = revoked;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokeAllByUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        var userTokens = _tokens.Values
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToList();

        foreach (var token in userTokens)
        {
            var revoked = token with { IsRevoked = true };
            _tokens[token.TokenHash] = revoked;
        }
        return Task.CompletedTask;
    }
}
