using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para publicar eventos de dominio del sistema de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los eventos de dominio son un patrón de diseño que permite desacoplar
/// las acciones que ocurren en el sistema de sus efectos secundarios. Por ejemplo,
/// cuando un usuario inicia sesión, podemos disparar un evento OnLoginSuccess que
/// otros componentes pueden escuchar para registrar auditoría, enviar notificaciones, etc.
/// Esto sigue el principio de "Open/Closed" (abierto para extensión, cerrado para modificación).
/// </remarks>
public interface IAuthEventDispatcher
{
    /// <summary>
    /// Publica un evento de autenticación de forma asíncrona.
    /// </summary>
    /// <param name="authEvent">El evento a publicar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task DispatchAsync(AuthEvent authEvent, CancellationToken cancellationToken = default);
}
