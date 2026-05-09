using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Provee abstracción para almacenar tokens emitidos por proveedores externos (ej. Google, GitHub).
/// Esto está separado de ISessionStore, el cual maneja la sesión interna de AuthCore.
/// </summary>
public interface IExternalTokenStore
{
    /// <summary>
    /// Persiste los tokens de un proveedor externo para un usuario.
    /// </summary>
    Task SaveAsync(ExternalTokenEntry entry, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recupera los tokens vigentes de un proveedor para un usuario.
    /// Útil para llamar a APIs de terceros (ej. Google Calendar).
    /// </summary>
    ValueTask<ExternalTokenEntry?> GetAsync(string userId, string provider, CancellationToken cancellationToken = default);

    /// <summary>
    /// Elimina los tokens de un proveedor (ej. al desconectar la cuenta de terceros).
    /// </summary>
    Task RevokeAsync(string userId, string provider, CancellationToken cancellationToken = default);
}
