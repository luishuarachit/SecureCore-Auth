using Microsoft.Extensions.Logging;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Implementación por defecto del despachador de eventos de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta implementación base registra los eventos en el logger.
/// El desarrollador puede agregar handlers adicionales registrándolos en DI
/// como IAuthEventHandler. Cada handler se ejecuta cuando ocurre un evento,
/// permitiendo agregar funcionalidad sin modificar la librería.
///
/// Ejemplos de uso:
/// - Enviar un email al usuario cuando se detecta actividad sospechosa.
/// - Registrar eventos en un sistema de auditoría.
/// - Enviar métricas a Application Insights o Datadog.
/// </remarks>
public sealed class AuthEventDispatcher(
    ILogger<AuthEventDispatcher> logger,
    IEnumerable<IAuthEventHandler> handlers) : IAuthEventDispatcher
{
    /// <inheritdoc />
    public async Task DispatchAsync(AuthEvent authEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authEvent);

        // Registrar siempre en el logger como línea base
        logger.LogInformation(
            "Evento de autenticación: {EventType} | Usuario: {UserId} | Timestamp: {Timestamp}",
            authEvent.EventType,
            authEvent.UserId,
            authEvent.TimestampUtc);

        // Ejecutar todos los handlers registrados
        foreach (var handler in handlers)
        {
            try
            {
                await handler.HandleAsync(authEvent, cancellationToken);
            }
            catch (Exception ex)
            {
                // No propagamos excepciones de handlers para no interrumpir el flujo principal
                logger.LogError(ex,
                    "Error en handler {HandlerType} procesando evento {EventType}",
                    handler.GetType().Name,
                    authEvent.EventType);
            }
        }
    }
}

/// <summary>
/// Interfaz para handlers personalizados de eventos de autenticación.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este es el punto de extensión para que los desarrolladores agreguen
/// lógica cuando ocurren eventos de autenticación. Se registran en DI como:
/// services.AddTransient&lt;IAuthEventHandler, MiHandlerPersonalizado&gt;();
/// </remarks>
public interface IAuthEventHandler
{
    /// <summary>
    /// Procesa un evento de autenticación.
    /// </summary>
    /// <param name="authEvent">El evento que ocurrió.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    Task HandleAsync(AuthEvent authEvent, CancellationToken cancellationToken = default);
}
