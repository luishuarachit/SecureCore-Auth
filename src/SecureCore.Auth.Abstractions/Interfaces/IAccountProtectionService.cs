using System;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Subsistema de anti-abuso por cuenta (S1): lockout multi-scope, temporal y escalonado.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Este contrato abstrae el "dónde" se guarda el estado anti-abuso por cuenta.
/// La implementación por defecto (InMemoryAccountProtectionService) funciona en single-instance.
/// Para arquitecturas distribuidas (varios servidores tras un load balancer), implemente este
/// contrato sobre un store compartido (Redis con INCR+EXPIRE, SQL Server, etc.): el estado del
/// lockout debe ser global a todas las instancias para que un atacante no pueda dividir sus
/// intentos entre servidores.
///
/// Contrato de claves: <c>key</c> identifica la cuenta (p. ej. el UserId). No es un secret;
/// es el índice sobre el que se acumulan los intentos fallidos.
///
/// Semántica:
/// - <see cref="RecordFailureAsync"/> acumula un fallo; al alcanzar el máximo del scope activa
///   un lockout escalonado (nivel 1, 2, 3, …) con duraciones crecientes.
/// - Los fallos durante un lockout activo se ignoran (no extienden ni escalan).
/// - El lockout decae solo al expirar; el nivel se conserva hasta un éxito o reset.
/// - <see cref="RecordSuccessAsync"/> limpia el scope tras una autenticación correcta.
/// - <see cref="AnyActiveLockAsync"/> permite a un contexto (p. ej. login) saber si la cuenta
///   tiene algún lockout activo en cualquiera de sus scopes.
/// </remarks>
public interface IAccountProtectionService
{
    /// <summary>
    /// Comprueba si la operación está permitida para un scope y clave de cuenta.
    /// </summary>
    /// <param name="scope">Factor de autenticación que se intenta.</param>
    /// <param name="key">Identificador de la cuenta (p. ej. UserId).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Resultado con Allow flag, intentos restantes y lockout activo.</returns>
    ValueTask<AccountProtectionResult> CheckAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Registra un intento fallido. Puede activar un lockout escalonado si se
    /// alcanza el máximo de intentos del scope.
    /// </summary>
    ValueTask RecordFailureAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Registra un autenticación correcta y limpia el contador del scope.
    /// </summary>
    ValueTask RecordSuccessAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Limpia el estado anti-abuso de un scope concreto para una clave.
    /// </summary>
    ValueTask ResetAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Limpia el estado anti-abuso de TODOS los scopes para una clave de cuenta.
    /// </summary>
    ValueTask ResetAllForUserAsync(
        string key,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Indica si la cuenta tiene algún lockout activo en cualquier scope.
    /// </summary>
    ValueTask<bool> AnyActiveLockAsync(
        string key,
        CancellationToken cancellationToken = default);
}
