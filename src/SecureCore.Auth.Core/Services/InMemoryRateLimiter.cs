using System.Collections.Concurrent;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// In-memory implementation of IRateLimiter using ConcurrentDictionary.
/// </summary>
/// <remarks>
/// DIDÁCTICA: This implementation is suitable for single-instance deployments.
/// It uses a ConcurrentDictionary to track attempts per key (typically IP address).
///
/// HOW IT WORKS:
/// 1. Each key (IP) has a sliding window of time
/// 2. First request in window creates an entry with Count = 1
/// 3. Subsequent requests increment the counter
/// 4. When counter exceeds maxAttempts, IsAllowed returns false
/// 5. On successful login, call Reset() to clear the counter
///
/// LIMITATIONS:
/// ⚠️ This implementation does NOT work across multiple server instances.
/// In a load-balanced environment, each server has its own in-memory counter,
/// so an attacker could distribute requests across servers to bypass limits.
///
/// Example attack without distributed rate limiting:
/// - 3 servers behind load balancer
/// - Each server allows 10 attempts/minute
/// - Attacker distributes requests: 10 to Server A, 10 to B, 10 to C
/// - Total: 30 attempts/minute from the same IP!
///
/// For distributed systems, you MUST implement IRateLimiter with a distributed
/// store (Redis, database) or use a middleware like AspNetCoreRateLimiter.
///
/// DISTRIBUTED REDIS IMPLEMENTATION:
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
///         var current = db.StringIncrementAsync($"ratelimit:{key}").Result;
///         
///         // Set expiry on first request
///         if (current == 1)
///             db.KeyExpireAsync($"ratelimit:{key}", _window);
///         
///         return current <= _maxAttempts;
///     }
///
///     public void Reset(string key)
///     {
///         _redis.GetDatabase().KeyDeleteAsync($"ratelimit:{key}");
///     }
///
///     public int GetRemainingAttempts(string key)
///     {
///         var db = _redis.GetDatabase();
///         var current = db.StringGetAsync($"ratelimit:{key}").Result;
///         
///         if (current.IsNullOrEmpty)
///             return _maxAttempts;
///             
///         return Math.Max(0, _maxAttempts - (int)current);
///     }
/// }
/// </code>
///
/// USAGE:
/// - In endpoints, call IsAllowed(ip) before processing
/// - On successful login, call Reset(ip) to clear counter
/// - On 429 response, include Retry-After header
/// </remarks>
public sealed class InMemoryRateLimiter : IRateLimiter
{
    private readonly ConcurrentDictionary<string, RateLimitEntry> _attempts = new();
    private readonly int _maxAttemptsPerWindow;
    private readonly TimeSpan _window;

    /// <summary>
    /// Creates a new InMemoryRateLimiter with the specified configuration.
    /// </summary>
    /// <param name="maxAttemptsPerWindow">Maximum attempts allowed within the time window.</param>
    /// <param name="window">Time window for rate limiting.</param>
    public InMemoryRateLimiter(int maxAttemptsPerWindow, TimeSpan window)
    {
        _maxAttemptsPerWindow = maxAttemptsPerWindow;
        _window = window;
    }

    /// <summary>
    /// Creates a new InMemoryRateLimiter with default configuration (10 attempts per minute).
    /// </summary>
    public InMemoryRateLimiter() : this(10, TimeSpan.FromMinutes(1))
    {
    }

    /// <inheritdoc />
    public bool IsAllowed(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;

        var entry = _attempts.AddOrUpdate(
            key,
            _ => new RateLimitEntry { Count = 1, WindowStart = now },
            (_, existing) =>
            {
                if (now - existing.WindowStart > _window)
                {
                    return new RateLimitEntry { Count = 1, WindowStart = now };
                }

                existing.Count++;
                return existing;
            });

        return entry.Count <= _maxAttemptsPerWindow;
    }

    /// <inheritdoc />
    public void Reset(string key)
    {
        if (!string.IsNullOrEmpty(key))
        {
            _attempts.TryRemove(key, out _);
        }
    }

    /// <inheritdoc />
    public int GetRemainingAttempts(string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            return _maxAttemptsPerWindow;
        }

        if (!_attempts.TryGetValue(key, out var entry))
        {
            return _maxAttemptsPerWindow;
        }

        var now = DateTimeOffset.UtcNow;
        if (now - entry.WindowStart > _window)
        {
            return _maxAttemptsPerWindow;
        }

        return Math.Max(0, _maxAttemptsPerWindow - entry.Count);
    }

    private sealed class RateLimitEntry
    {
        public int Count;
        public DateTimeOffset WindowStart;
    }
}