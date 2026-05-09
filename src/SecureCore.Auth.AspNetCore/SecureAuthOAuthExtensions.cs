using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
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

        // Si el consumidor no registra un IExternalTokenStore, proveemos uno nulo (no-op)
        // para no romper retrocompatibilidad si solo usan Flujo B o no les interesan los tokens de proveedor.
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

internal class NullExternalTokenStore : IExternalTokenStore
{
    public Task SaveAsync(ExternalTokenEntry entry, System.Threading.CancellationToken cancellationToken = default) => Task.CompletedTask;
    public ValueTask<ExternalTokenEntry?> GetAsync(string userId, string provider, System.Threading.CancellationToken cancellationToken = default) => ValueTask.FromResult<ExternalTokenEntry?>(null);
    public Task RevokeAsync(string userId, string provider, System.Threading.CancellationToken cancellationToken = default) => Task.CompletedTask;
}
