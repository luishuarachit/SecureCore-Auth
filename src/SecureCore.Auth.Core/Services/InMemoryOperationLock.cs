using System.Collections.Concurrent;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// In-memory implementation of IOperationLock using SemaphoreSlim.
/// </summary>
/// <remarks>
/// DIDÁCTICA: This implementation is suitable for single-instance deployments.
/// It uses a ConcurrentDictionary to store SemaphoreSlim instances per key,
/// allowing concurrent access to different keys while serializing access to the same key.
///
/// HOW IT WORKS:
/// 1. Each unique key gets its own SemaphoreSlim initialized to 1 permit
/// 2. When AcquireAsync is called, we wait for the semaphore with a timeout
/// 3. On success, we return a LockReleaser that calls Release() on dispose
/// 4. This ensures that only one thread can hold the lock for a given key
///
/// LIMITATIONS:
/// ⚠️ This implementation does NOT work across multiple server instances.
/// In a load-balanced environment, each server has its own in-memory lock,
/// so two requests hitting different servers could still create race conditions.
///
/// For distributed systems, you MUST implement IOperationLock with a distributed
/// locking mechanism like Redis SETNX or database row locking.
///
/// EXAMPLE OF DISTRIBUTED IMPLEMENTATION:
/// <code>
/// // For production with multiple instances, implement IOperationLock like:
/// public class RedisOperationLock : IOperationLock
/// {
///     private readonly IConnectionMultiplexer _redis;
///     public async Task&lt;IDisposable&gt; AcquireAsync(string key, TimeSpan timeout, CancellationToken ct)
///     {
///         var db = _redis.GetDatabase();
///         var lockKey = $"securecore:lock:{key}";
///         
///         // SET NX with expiration = atomic lock acquisition
///         var acquired = await db.StringSetAsync(lockKey, "1", timeout, When.NotExists);
///         if (!acquired) throw new TimeoutException($"Could not acquire lock: {key}");
///         
///         return new RedisLockReleaser(db, lockKey);
///     }
/// }
/// </code>
///
/// USAGE IN RTR (Refresh Token Rotation):
/// The lock key is typically the token family ID, ensuring that only one
/// request can rotate tokens for a specific user's session at a time.
/// </remarks>
public sealed class InMemoryOperationLock : IOperationLock
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();
    private readonly TimeSpan _defaultTimeout;

    /// <summary>
    /// Creates a new InMemoryOperationLock with the specified default timeout.
    /// </summary>
    /// <param name="defaultTimeout">Default timeout for lock acquisition (default: 5 seconds).</param>
    public InMemoryOperationLock(TimeSpan? defaultTimeout = null)
    {
        _defaultTimeout = defaultTimeout ?? TimeSpan.FromSeconds(5);
    }

    /// <inheritdoc />
    public async Task<IDisposable> AcquireAsync(
        string key,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var semaphore = _locks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));

        var acquired = await semaphore.WaitAsync(timeout, cancellationToken);

        if (!acquired)
        {
            throw new TimeoutException(
                $"No se pudo adquirir el lock para '{key}' dentro de {timeout.TotalSeconds} segundos. " +
                $"Esto puede indicar una condición de carrera o un proceso bloqueado.");
        }

        return new LockReleaser(semaphore);
    }

    /// <summary>
    /// Releases the semaphore when disposed, allowing the next waiting thread to acquire the lock.
    /// </summary>
    private sealed class LockReleaser : IDisposable
    {
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed;

        public LockReleaser(SemaphoreSlim semaphore)
        {
            _semaphore = semaphore;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _semaphore.Release();
            }
        }
    }
}