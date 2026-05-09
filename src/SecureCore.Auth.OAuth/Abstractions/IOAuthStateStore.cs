using System;
using System.Threading;
using System.Threading.Tasks;

namespace SecureCore.Auth.OAuth.Abstractions;

/// <summary>
/// Representa una entrada de estado temporal almacenada durante el flujo OAuth.
/// </summary>
public record OAuthStateEntry(
    string Nonce, 
    string Provider, 
    string RedirectUri, 
    DateTimeOffset CreatedAt);

/// <summary>
/// Contrato para almacenar temporalmente el state y nonce durante el Flujo de Authorization Code.
/// </summary>
public interface IOAuthStateStore
{
    /// <summary>
    /// Guarda un nuevo state y su entrada asociada por un tiempo determinado (TTL).
    /// </summary>
    Task SaveAsync(string state, OAuthStateEntry entry, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene Y BORRA la entrada de estado correspondiente al state provisto.
    /// Este método garantiza un uso único (anti-replay) por contrato.
    /// </summary>
    ValueTask<OAuthStateEntry?> ConsumeAsync(string state, CancellationToken cancellationToken = default);
}
