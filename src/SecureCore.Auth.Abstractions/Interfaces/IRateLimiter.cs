namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Abstraction for rate limiting to prevent brute force and DDoS attacks.
/// </summary>
/// <remarks>
/// DIDÁCTICA: This interface provides a mechanism to limit the number of requests
/// from a specific source (typically IP address or user ID) within a time window.
///
/// WHY IS THIS NEEDED?
/// Without rate limiting, attackers can attempt:
/// 1. Brute force attacks: Try many passwords for the same account
/// 2. Credential stuffing: Try leaked credentials across many accounts
/// 3. DDoS: Overwhelm the server with requests
///
/// RATE LIMITING PROTECTS BY:
/// - Limiting attempts per IP (prevents distributed attacks)
/// - Limiting attempts per account (prevents brute force)
/// - Providing consistent feedback (throttle, don't block immediately)
///
/// HOW IT WORKS:
/// 1. Each request calls IsAllowed(key) before processing
/// 2. If returns false, reject immediately with 429 Too Many Requests
/// 3. On successful authentication, call Reset(key) to clear the counter
/// 4. GetRemainingAttempts(key) is optional, for UI feedback
///
/// IMPLEMENTATION OPTIONS:
///
/// 1. SINGLE-INSTANCE: Use InMemoryRateLimiter (provided by library)
///    - Uses ConcurrentDictionary
///    - Fast, no network latency
///    - ⚠️ Does NOT work across multiple servers
///
/// 2. MULTI-INSTANCE: Implement your own with Redis, etc.
///    - Uses distributed storage
///    - Works across load-balanced servers
///    - Requires Redis or similar
///
/// REDIS IMPLEMENTATION EXAMPLE:
/// <code>
/// public class RedisRateLimiter : IRateLimiter
/// {
///     private readonly IConnectionMultiplexer _redis;
///     private readonly int _maxAttempts;
///     private readonly TimeSpan _window;
///
///     public RedisRateLimiter(IConnectionMultiplexer redis, int maxAttempts, TimeSpan window)
///     {
///         _redis = redis;
///         _maxAttempts = maxAttempts;
///         _window = window;
///     }
///
///     public bool IsAllowed(string key)
///     {
///         var db = _redis.GetDatabase();
///         var count = db.StringIncrementAsync($"ratelimit:{key}").Result;
///         if (count == 1)
///             db.KeyExpireAsync($"ratelimit:{key}", _window);
///         return count <= _maxAttempts;
///     }
///
///     public void Reset(string key)
///     {
///         _redis.GetDatabase().KeyDeleteAsync($"ratelimit:{key}");
///     }
/// }
/// </code>
///
/// IMPORTANT: In-memory implementation works for single-instance deployments
/// but NOT for distributed systems. For production with multiple servers,
/// you MUST implement this interface with a distributed store (Redis, etc.)
/// or use a middleware like AspNetCoreRateLimiter.
/// </remarks>
public interface IRateLimiter
{
    /// <summary>
    /// Checks if the request from the specified key is allowed.
    /// </summary>
    /// <param name="key">The identifier to rate limit (typically IP address or user ID).</param>
    /// <returns>True if the request is allowed, false if rate limit exceeded.</returns>
    bool IsAllowed(string key);

    /// <summary>
    /// Resets the rate limit counter for the specified key.
    /// Call this after successful authentication.
    /// </summary>
    /// <param name="key">The identifier to reset.</param>
    void Reset(string key);

    /// <summary>
    /// Gets the remaining attempts available for the specified key.
    /// </summary>
    /// <param name="key">The identifier to check.</param>
    /// <returns>Number of remaining attempts, or -1 if not tracked.</returns>
    int GetRemainingAttempts(string key);
}