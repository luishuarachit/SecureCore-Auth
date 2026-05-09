using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Interfaces;

namespace SecureCore.Auth.OAuth.Services;

/// <summary>
/// Permite obtener de forma segura y automatizada los tokens de acceso de un proveedor,
/// encargándose de la renovación automática si han expirado.
/// </summary>
public class ExternalTokenAccessor(
    IExternalTokenStore store,
    IEnumerable<IOAuthProviderValidator> validators)
{
    public async Task<string?> GetValidAccessTokenAsync(
        string userId, string provider, CancellationToken ct = default)
    {
        var entry = await store.GetAsync(userId, provider, ct);
        if (entry is null) return null;

        // Si el token es válido con margen de 5 minutos, se retorna.
        if (entry.ExpiresAt > DateTimeOffset.UtcNow.AddMinutes(5))
            return entry.AccessToken;

        // Si expiró y no hay refresh_token, no se puede renovar.
        if (string.IsNullOrEmpty(entry.RefreshToken))
            return null;

        var validator = validators.FirstOrDefault(v => 
            v.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));
            
        if (validator is null)
            return null;

        var refreshed = await validator.RefreshProviderAccessTokenAsync(entry.RefreshToken, ct);
        if (!refreshed.Succeeded || refreshed.NewAccessToken is null)
            return null;

        // Actualizamos la base de datos
        await store.SaveAsync(entry with
        {
            AccessToken = refreshed.NewAccessToken,
            ExpiresAt = refreshed.ExpiresAt ?? DateTimeOffset.UtcNow.AddHours(1)
        }, ct);

        return refreshed.NewAccessToken;
    }
}
