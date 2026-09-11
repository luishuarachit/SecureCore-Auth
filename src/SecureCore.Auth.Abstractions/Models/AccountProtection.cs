namespace SecureCore.Auth.Abstractions.Models;

/// <summary>
/// Scope de protección anti-abuso por cuenta (S1). Cada factor de autenticación
/// tiene su propio presupuesto de intentos y escalamiento de bloqueo.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Un atacante puede atacar distintos factores por separado (contraseña,
/// código MFA, passkey, recovery code, verify-action). Tener un scope por factor
/// impide que los intentos fallidos de un factor consuman el presupuesto de otro,
/// y permite un nivel de bloqueo independiente y escalonado para cada uno.
/// </remarks>
public enum AccountProtectionScope
{
    /// <summary>Login con contraseña (password grant).</summary>
    Password,

    /// <summary>Verificación de código MFA (TOTP/email) durante el login.</summary>
    MfaLogin,

    /// <summary>Ceremonias WebAuthn/Passkeys (assertion y registration).</summary>
    Passkey,

    /// <summary>Redención de recovery codes de "último recurso".</summary>
    Recovery,

    /// <summary>Verificación temporal para acciones sensibles (step-up).</summary>
    VerifyAction,

    /// <summary>Cambio/creación de contraseña validando la contraseña actual (M4, auditoría).</summary>
    PasswordChange
}

/// <summary>
/// Resultado de una comprobación de anti-abuso por cuenta (S1).
/// </summary>
/// <remarks>
/// DIDÁCTICA: <c>Allowed</c> indica si la operación puede continuar. Cuando el
/// acceso está bloqueado, <c>LockEnd</c> informa cuándo termina el lockout y
/// <c>EscalationLevel</c> el nivel de escalamiento activo, sin revelar detalles
/// que permitan enumerar o planificar ataques.
/// </remarks>
/// <param name="Allowed">true si la operación está permitida; false si hay lockout activo.</param>
/// <param name="RemainingAttempts">Intentos restantes antes de un nuevo lockout (0 si bloqueado).</param>
/// <param name="LockEnd">Momento en que expira el lockout activo (null si no hay lockout).</param>
/// <param name="EscalationLevel">Nivel de escalamiento actual (1 = primer lockout).</param>
public readonly record struct AccountProtectionResult(
    bool Allowed,
    int RemainingAttempts,
    DateTimeOffset? LockEnd,
    int EscalationLevel);
