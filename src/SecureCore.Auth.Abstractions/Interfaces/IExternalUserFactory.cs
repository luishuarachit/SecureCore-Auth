using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Permite delegar la creación de un nuevo usuario a la aplicación consumidora.
/// Esto evita que AuthCore tenga que interactuar con la base de datos subyacente para insertar usuarios.
/// </summary>
public interface IExternalUserFactory
{
    /// <summary>
    /// Crea un nuevo usuario en el sistema a partir de los datos obtenidos del proveedor OAuth.
    /// </summary>
    Task<UserIdentity> CreateFromOAuthAsync(OAuthIdentityResult providerIdentity, string provider, CancellationToken cancellationToken = default);
}
