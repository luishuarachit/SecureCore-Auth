using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.OAuth.Abstractions;
using SecureCore.Auth.OAuth.Extensions;
using SecureCore.Auth.OAuth.Services;

namespace SecureCore.Auth.AspNetCore;

public static class SecureAuthOAuthExtensions
{
    /// <summary>
    /// Habilita el ecosistema OAuth y permite configurar proveedores.
    /// </summary>
    public static SecureAuthBuilder AddOAuth(this SecureAuthBuilder builder, Action<OAuthBuilder> configure)
    {
        // Registrar orquestador y servicios base
        builder.Services.AddScoped<OAuthOrchestrator>();
        builder.Services.AddScoped<ExternalTokenAccessor>();

        // Registrar el StateStore default usando IDistributedCache
        builder.Services.TryAddScoped<IOAuthStateStore, SecureCore.Auth.AspNetCore.Extensions.DistributedCacheOAuthStateStore>();

        // DIDÁCTICA: Registrar NullExternalTokenStore si no hay uno personalizado.
        // El warning se emitirá desde NullExternalTokenStore cuando se resuelva.
        builder.Services.TryAddScoped<IExternalTokenStore, NullExternalTokenStore>();

        // Opciones por defecto (configurables por el consumidor)
        builder.Services.Configure<OAuthSignInOptions>(opts =>
        {
            opts.AllowImplicitRegistration = false;
            opts.PersistProviderTokens = false;
        });

        // Permitir a los paquetes de proveedores configurarse
        var oauthBuilder = new OAuthBuilder(builder.Services);
        configure(oauthBuilder);

        return builder;
    }
}

/// <summary>
/// Implementación no-op de IExternalTokenStore.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este store se usa por defecto cuando el implementador no proporciona
/// uno personalizado. No persiste tokens OAuth, lo que es correcto para apps que
/// solo necesitan validar identidad (no acceder a recursos del proveedor como
/// Facebook Graph API, Google Drive, etc.).
///
/// Si necesitas guardar tokens de acceso del proveedor para llamadas API al proveedor,
/// implementa tu propia versión de IExternalTokenStore.
/// </remarks>
internal class NullExternalTokenStore : IExternalTokenStore
{
    private static bool _warningLogged;
    private readonly ILogger<NullExternalTokenStore>? _logger;

    public NullExternalTokenStore(ILogger<NullExternalTokenStore>? logger = null)
    {
        _logger = logger;
        LogWarningOnce();
    }

    private void LogWarningOnce()
    {
        if (!_warningLogged && _logger is not null)
        {
            _warningLogged = true;
            _logger.LogWarning(
                "IExternalTokenStore no personalizado registrado. Los tokens OAuth no se persistiran. " +
                "Si necesita guardar tokens de proveedor (para acceder a APIs del proveedor como Graph API), " +
                "implemente IExternalTokenStore y registrelo en el contenedor DI antes de AddOAuth().");
        }
    }

    public Task SaveAsync(ExternalTokenEntry entry, CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("NullExternalTokenStore: ignorando save para provider {Provider}", entry.Provider);
        return Task.CompletedTask;
    }

    public ValueTask<ExternalTokenEntry?> GetAsync(string userId, string provider, CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("NullExternalTokenStore: retornando null para get de {Provider}", provider);
        return ValueTask.FromResult<ExternalTokenEntry?>(null);
    }

    public Task RevokeAsync(string userId, string provider, CancellationToken cancellationToken = default)
    {
        _logger?.LogDebug("NullExternalTokenStore: ignorando revoke para provider {Provider}", provider);
        return Task.CompletedTask;
    }
}
