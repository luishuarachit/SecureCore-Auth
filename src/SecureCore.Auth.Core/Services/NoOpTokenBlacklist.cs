using System;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto (no-op) de <see cref="ITokenBlacklist"/> (A-24).
/// </summary>
/// <remarks>
/// DIDÁCTICA: el framework NO blacklistea access tokens por defecto (la revocación real la
/// aportan el SecurityStamp y el RTR). Este default mantiene el comportamiento previo intacto;
/// el host que quiera revocar el access token en un logout de sesión individual registra su
/// propia implementación (in-memory, Redis, etc.) ANTES de <c>AddSecureAuth()</c> (TryAdd).
/// </remarks>
public sealed class NoOpTokenBlacklist : ITokenBlacklist
{
    public ValueTask AddAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;

    public ValueTask<bool> IsBlacklistedAsync(string jti, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(false);
}
