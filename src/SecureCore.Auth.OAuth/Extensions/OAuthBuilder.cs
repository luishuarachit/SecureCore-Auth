using System;
using Microsoft.Extensions.DependencyInjection;

namespace SecureCore.Auth.OAuth.Extensions;

/// <summary>
/// Permite configurar los proveedores y opciones del ecosistema OAuth.
/// </summary>
public class OAuthBuilder(IServiceCollection services)
{
    public IServiceCollection Services { get; } = services;
}
