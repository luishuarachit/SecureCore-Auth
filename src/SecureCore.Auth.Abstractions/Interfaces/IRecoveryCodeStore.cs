using System;
using System.Threading;
using System.Threading.Tasks;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato del store de recovery codes (Fase 5, A-18/A-20): "último recurso"
/// para el login cuando el factor MFA habitual (TOTP/email) no está disponible.
/// </summary>
/// <remarks>
/// DIDÁCTICA (S5): AuthCore ya generaba códigos de recuperación en el enrollment MFA pero
/// <c>VerifyAsync</c> jamás los redimía (A-18). Este contrato hace el mecanismo de primera
/// clase: generar → mostrar una vez → verificar (sin consumir) → usar (consumo single-use).
///
/// CONTRATO DE SINGLE-USE (S2): el store recibe SIEMPRE el hash del código (SHA-256 hex
/// minúsculas, coherente con <c>IUserStore.SetRecoveryCodesAsync</c>), nunca su texto plano.
/// La redención (<see cref="RedeemAsync"/>) consume de forma ATÓMICA (primitiva S2 GETDEL):
/// dos llamadas concurrentes con el mismo hash solo pueden tener éxito una vez.
///
/// RESPONSABILIDAD DEL STORE: distinguir tres estados para <see cref="GetStatusAsync"/>:
/// <c>Valid</c> (pendiente y consumible), <c>AlreadyUsed</c> (fue emitido y ya consumido) e
/// <c>Invalid</c> (nunca emitido, expirado o invalidado). El orquestador los expone al host
/// sin revelarlos a clientes no autenticados (anti-enumeración: el cliente solo ve válido/no).
///
/// El TTL de cada código lo decide la implementación (el default sobre IDistributedCache lo
/// toma de <c>MfaOptions.RecoveryCodeLifetimeDays</c>).
/// </remarks>
public interface IRecoveryCodeStore
{
    /// <summary>
    /// Registra un nuevo hash de recovery code como pendiente (consumible).
    /// </summary>
    /// <param name="userId">Identificador de la cuenta propietaria.</param>
    /// <param name="codeHash">Hash SHA-256 (hex minúsculas) del código. Nunca texto plano.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask CreateAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Consulta el estado de un código SIN consumirlo (peek no destructivo).
    /// </summary>
    /// <param name="userId">Identificador de la cuenta propietaria.</param>
    /// <param name="codeHash">Hash SHA-256 (hex minúsculas) del código a consultar.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// <c>Valid</c> si el código está pendiente, <c>AlreadyUsed</c> si fue emitido y ya se
    /// consumió, <c>Invalid</c> si nunca se emitió, expiró o fue invalidado.
    /// </returns>
    /// <remarks>
    /// DIDÁCTICA: <see cref="GetStatusAsync"/> cubre la fase "verify" del flujo
    /// (generar → mostrar → verificar → usar): permite saber si un código es redimible
    /// sin gastar su single-use. <see cref="RedeemAsync"/> es la única operación que consume.
    /// </remarks>
    ValueTask<RecoveryCodeStatus> GetStatusAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Consume un recovery code de forma ATÓMICA (single-use).
    /// </summary>
    /// <param name="userId">Identificador de la cuenta propietaria.</param>
    /// <param name="codeHash">Hash SHA-256 (hex minúsculas) del código a redimir.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// true si el código existía pendiente y fue consumido (exactamente UNA llamada
    /// concurrente obtiene true); false si no existía, expiró o ya fue usado.
    /// </returns>
    ValueTask<bool> RedeemAsync(
        string userId,
        string codeHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalida los códigos pendientes de un usuario (por ejemplo, al regenerar la lista).
    /// </summary>
    /// <param name="userId">Identificador de la cuenta propietaria.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <remarks>
    /// DIDÁCTICA: regenerar los recovery codes (generar un lote nuevo) reemplaza por
    /// completo el lote anterior: los códigos viejos no consumidos dejan de ser válidos.
    /// </remarks>
    ValueTask InvalidatePendingAsync(
        string userId,
        CancellationToken cancellationToken = default);
}
