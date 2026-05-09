using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using SecureCore.Auth.OAuth.Abstractions;

namespace SecureCore.Auth.AspNetCore.Extensions;

/// <summary>
/// Implementación de IOAuthStateStore usando IDistributedCache de ASP.NET Core.
/// </summary>
public class DistributedCacheOAuthStateStore(IDistributedCache cache) : IOAuthStateStore
{
    private const string Prefix = "OAuthState_";

    public async Task SaveAsync(string state, OAuthStateEntry entry, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        var key = Prefix + state;
        var json = JsonSerializer.Serialize(entry);
        
        var options = new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ttl };
        
        await cache.SetStringAsync(key, json, options, cancellationToken);
    }

    public async ValueTask<OAuthStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default)
    {
        var key = Prefix + state;
        
        // Obtener el valor
        var json = await cache.GetStringAsync(key, cancellationToken);
        
        if (json is null)
            return null;
            
        // Borrarlo inmediatamente para asegurar un solo uso (anti-replay)
        await cache.RemoveAsync(key, cancellationToken);
        
        try
        {
            return JsonSerializer.Deserialize<OAuthStateEntry>(json);
        }
        catch
        {
            return null;
        }
    }
}
