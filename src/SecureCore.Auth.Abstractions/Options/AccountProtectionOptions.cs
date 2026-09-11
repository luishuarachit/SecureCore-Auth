using System.Collections.Generic;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones del subsistema de anti-abuso por cuenta (S1).
/// </summary>
/// <remarks>
/// DIDÁCTICA: El subsistema consolida el lockout por cuenta en un único mecanismo
/// multi-scope y escalonado. El escalamiento es temporal y crece con los bloqueos
/// consecutivos: 10 → 30 → 60 min → 24 h (máximo <see cref="MaxLockDuration"/>).
///
/// OPT-IN (D-03): <see cref="Enabled"/> es false por defecto. Hasta que no se
/// habilite, los orquestadores conservan su comportamiento actual (LockoutManager
/// en DB / ventana MFA fija). Al habilitarlo, los orquestadores que lo soporten
/// enrutan sus fallos por este subsistema sin tocar la base de datos en cada intento.
///
/// Ventana deslizante: los fallos más antiguos que <see cref="Window"/> no cuentan.
/// El bloqueo decae solo al expirar su duración; el nivel se conserva entre ciclos
/// hasta que un éxito o un reset limpien la cuenta.
/// </remarks>
public class AccountProtectionOptions
{
    /// <summary>
    /// Sección del archivo de configuración: "SecureAuth:AccountProtection".
    /// </summary>
    public const string SectionName = "SecureAuth:AccountProtection";

    /// <summary>
    /// Ventana deslizante por defecto (5 minutos).
    /// </summary>
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Duración máxima de lockout por defecto (24 h).
    /// </summary>
    public static readonly TimeSpan DefaultMaxLockDuration = TimeSpan.FromHours(24);

    private static readonly IReadOnlyDictionary<AccountProtectionScope, int> DefaultMaxAttempts =
        new Dictionary<AccountProtectionScope, int>
        {
            [AccountProtectionScope.Password] = 5,
            [AccountProtectionScope.MfaLogin] = 5,
            [AccountProtectionScope.Passkey] = 5,
            [AccountProtectionScope.Recovery] = 3,
            [AccountProtectionScope.VerifyAction] = 5,
            [AccountProtectionScope.PasswordChange] = 5
        };

    /// <summary>
    /// Habilita el subsistema. Opt-in: false por defecto (no altera el comportamiento actual).
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Ventana deslizante para contabilizar intentos fallidos. Default: 5 minutos.
    /// </summary>
    public TimeSpan Window { get; set; } = DefaultWindow;

    /// <summary>
    /// Intentos máximos por scope antes de activar un lockout escalonado.
    /// Defaults: Password/MfaLogin/Passkey/VerifyAction/PasswordChange 5, Recovery 3.
    /// </summary>
    public IReadOnlyDictionary<AccountProtectionScope, int> MaxAttempts { get; set; } = DefaultMaxAttempts;

    /// <summary>
    /// Duraciones del lockout por nivel de escalamiento (orden ascendente).
    /// Default: 10 → 30 → 60 min → 24 h.
    /// </summary>
    public IReadOnlyList<TimeSpan> EscalationDurations { get; set; } = new[]
    {
        TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(30),
        TimeSpan.FromHours(1),
        TimeSpan.FromHours(24)
    };

    /// <summary>
    /// Duración máxima de un lockout (techo de <see cref="EscalationDurations"/>). Default: 24 h.
    /// </summary>
    public TimeSpan MaxLockDuration { get; set; } = DefaultMaxLockDuration;

    /// <summary>
    /// Obtiene el máximo de intentos para un scope.
    /// </summary>
    public int GetMaxAttempts(AccountProtectionScope scope) =>
        MaxAttempts.TryGetValue(scope, out var maxAttempts) && maxAttempts > 0
            ? maxAttempts
            : 5;

    /// <summary>
    /// Obtiene la ventana deslizante efectiva. Defensivo: un valor no positivo
    /// (misconfiguración) decae al default en lugar de disparar el fail-open.
    /// </summary>
    public TimeSpan GetWindow() => Window > TimeSpan.Zero ? Window : DefaultWindow;

    /// <summary>
    /// Obtiene la duración máxima de lockout efectiva. Defensivo: un valor no
    /// positivo decae al default (24 h) en lugar de producir lockouts nulos.
    /// </summary>
    public TimeSpan GetMaxLockDuration() =>
        MaxLockDuration > TimeSpan.Zero ? MaxLockDuration : DefaultMaxLockDuration;

    /// <summary>
    /// Obtiene la duración del lockout para un nivel de escalamiento (1-indexed).
    /// Se usa como techo <see cref="GetMaxLockDuration"/> si el nivel excede la lista
    /// o si una duración configurada la supera.
    /// </summary>
    public TimeSpan GetLockDuration(int escalationLevel)
    {
        var max = GetMaxLockDuration();

        if (escalationLevel <= 0 || EscalationDurations.Count == 0)
        {
            return max;
        }

        var index = escalationLevel - 1;
        if (index >= EscalationDurations.Count)
        {
            return max;
        }

        var duration = EscalationDurations[index];
        if (duration <= TimeSpan.Zero || duration > max)
        {
            return max;
        }

        return duration;
    }
}
