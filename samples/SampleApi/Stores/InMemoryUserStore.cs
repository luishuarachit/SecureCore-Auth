using System.Collections.Concurrent;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SampleApi.Stores;

/// <summary>
/// Implementación en memoria del IUserStore para la API de ejemplo.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta es una implementación de ejemplo del patrón Store que define
/// la librería. En producción, esta clase sería reemplazada por una implementación
/// que use Entity Framework Core, Dapper, MongoDB, o la tecnología de persistencia
/// que el desarrollador prefiera.
///
/// Notas importantes:
/// - Usamos ConcurrentDictionary para thread-safety en un entorno web.
/// - Los datos se pierden al reiniciar la aplicación (es solo para demo).
/// - Se incluye un usuario de prueba pre-cargado para facilitar las demos.
/// - Retornamos ValueTask porque la interfaz lo requiere (rendimiento).
/// </remarks>
public sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, UserIdentity> _usersById = new();
    private readonly ConcurrentDictionary<string, string> _emailToIdIndex = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Agrega un usuario al store (usado en seeding y registro).
    /// </summary>
    public void SeedUser(UserIdentity user)
    {
        _usersById[user.Id] = user;
        _emailToIdIndex[user.Email] = user.Id;
    }

    /// <inheritdoc />
    public ValueTask<UserIdentity?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        _usersById.TryGetValue(userId, out var user);
        return ValueTask.FromResult(user);
    }

    /// <inheritdoc />
    public ValueTask<UserIdentity?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (_emailToIdIndex.TryGetValue(email, out var userId))
        {
            _usersById.TryGetValue(userId, out var user);
            return ValueTask.FromResult(user);
        }
        return ValueTask.FromResult<UserIdentity?>(null);
    }

    /// <inheritdoc />
    public ValueTask<UserIdentity?> FindByExternalProviderAsync(
        string providerName, string providerKey, CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult<UserIdentity?>(null);
    }

    /// <inheritdoc />
    public Task CreateAsync(UserIdentity user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        _usersById[user.Id] = user;
        _emailToIdIndex[user.Email] = user.Id;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task UpdateAsync(UserIdentity user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        _usersById[user.Id] = user;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<string?> GetSecurityStampAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (_usersById.TryGetValue(userId, out var user))
        {
            return ValueTask.FromResult<string?>(user.SecurityStamp);
        }
        return ValueTask.FromResult<string?>(null);
    }

    /// <inheritdoc />
    public Task UpdateSecurityStampAsync(string userId, string newStamp, CancellationToken cancellationToken = default)
    {
        if (_usersById.TryGetValue(userId, out var user))
        {
            var updated = user with { SecurityStamp = newStamp };
            _usersById[userId] = updated;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<int> IncrementFailedAccessCountAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (_usersById.TryGetValue(userId, out var user))
        {
            var newCount = user.FailedAccessCount + 1;
            var updated = user with { FailedAccessCount = newCount };
            _usersById[userId] = updated;
            return Task.FromResult(newCount);
        }
        return Task.FromResult(0);
    }

    /// <inheritdoc />
    public Task ResetFailedAccessCountAsync(string userId, CancellationToken cancellationToken = default)
    {
        if (_usersById.TryGetValue(userId, out var user))
        {
            var updated = user with { FailedAccessCount = 0 };
            _usersById[userId] = updated;
        }
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SetLockoutEndAsync(string userId, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default)
    {
        if (_usersById.TryGetValue(userId, out var user))
        {
            var updated = user with { LockoutEnd = lockoutEnd };
            _usersById[userId] = updated;
        }
        return Task.CompletedTask;
    }
}
