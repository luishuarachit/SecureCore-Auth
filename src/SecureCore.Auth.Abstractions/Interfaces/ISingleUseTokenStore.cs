using System;
using System.Threading;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para almacenar y consumir exactamente una vez un valor efímero (anti-replay).
/// </summary>
/// <remarks>
/// DIDÁCTICA: Es la primitiva transversal de "consumir exactamente una vez" (equivalente a GETDEL)
/// del framework. Se usa para OAuth state (A-06), challenges WebAuthn (Fase 4) y redención de
/// recovery codes (Fase 5): todos son tokens de un solo uso y la operación de consumo debe ser
/// ATÓMICA para evitar el patrón TOCTOU (Time-Of-Check-Time-Of-Use) de GET + REMOVE no atómico.
///
/// CONTRATO SPI distribuido: la implementación por defecto usa IDistributedCache con GET + REMOVE
/// (fallback NO atómico, ventana residual de ~1 ms). Para despliegues multi-instancia, implemente
/// este contrato sobre un backend que soporte operación atómica:
/// - Redis: GETDEL (o un script Lua: get + del en una única ejecución en el servidor).
/// - SQL Server: UPDATE ... OUTPUT con confirmación transaccional de la fila.
///
/// RESPONSABILIDAD DEL LLAMANTE: las claves DEBEN llevar un prefijo por contexto (p. ej.
/// "OAuthState_", "WebAuthn_", "RecoveryCode_") para evitar colisiones entre tokens de diferentes
/// flujos que comparten el mismo store. La interfaz es agnóstica al backend e ignora el formato
/// interno de la clave.
///
/// La atomicidad garantiza que DOS llamadas concurrentes con la misma key nunca obtengan ambas
/// el valor: exactamente una consume; la otra recibe null.
/// </remarks>
public interface ISingleUseTokenStore
{
    /// <summary>
    /// Almacena un valor efímero con tiempo de expiración.
    /// </summary>
    /// <param name="key">Clave única del token.</param>
    /// <param name="value">Valor opaco a almacenar (ej. JSON serializado).</param>
    /// <param name="ttl">Tiempo de vida del token.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken cancellationToken = default);

    /// <summary>
    /// Obtiene Y ELIMINA el valor de forma atómica (consumo único).
    /// </summary>
    /// <param name="key">Clave única del token.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El valor si existía y fue consumido; null si no existe, expiró o ya fue consumido.</returns>
    ValueTask<string?> GetAndRemoveAsync(string key, CancellationToken cancellationToken = default);
}
