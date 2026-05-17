namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Abstraction for acquiring locks during critical operations.
/// </summary>
/// <remarks>
/// DIDÁCTICA: This interface provides a way to serialize access to shared resources
/// across concurrent requests. It is primarily used in Refresh Token Rotation (RTR)
/// to prevent race conditions where two simultaneous requests could create multiple
/// valid tokens for the same session.
///
/// WHY IS THIS NEEDED?
/// Without a lock, two concurrent requests using the same refresh token could:
///
/// Request A: Reads token from DB ✓
/// Request B: Reads token from DB ✓
/// Request A: Creates new token, marks old as replaced ✓
/// Request B: Creates ANOTHER new token, marks old as replaced ✓
/// Result: TWO valid refresh tokens for the same family!
///
/// HOW TO USE:
/// 1. SINGLE-INSTANCE (default): The library provides InMemoryOperationLock
///    which uses SemaphoreSlim to serialize access within one server instance.
/// 2. MULTI-INSTANCE: For distributed systems, implement this interface with
///    Redis or a database-backed lock (e.g., SETNX with expiration).
///
/// IMPLEMENTATION EXAMPLE FOR REDIS:
/// <code>
/// public class RedisOperationLock : IOperationLock
/// {
///     private readonly IConnectionMultiplexer _redis;
///     public async Task&lt;IDisposable&gt; AcquireAsync(string key, TimeSpan timeout, CancellationToken ct)
///     {
///         var db = _redis.GetDatabase();
///         var acquired = await db.StringSetAsync($"lock:{key}", 1, timeout);
///         if (!acquired) throw new TimeoutException($"Could not acquire lock: {key}");
///         return new RedisLockReleaser(db, key);
///     }
/// }
/// </code>
///
/// IMPORTANT: If no IOperationLock is registered, the library will use the
/// in-memory implementation. This works for single-instance deployments but
/// does NOT protect against race conditions in distributed scenarios.
/// </remarks>
public interface IOperationLock
{
    /// <summary>
    /// Acquires a lock for the specified resource key.
    /// </summary>
    /// <param name="key">Unique identifier for the resource to lock.</param>
    /// <param name="timeout">Maximum time to wait for the lock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An IDisposable that releases the lock when disposed.
    /// Throws TimeoutException if the lock cannot be acquired within the timeout.
    /// </returns>
    Task<IDisposable> AcquireAsync(string key, TimeSpan timeout, CancellationToken cancellationToken);
}