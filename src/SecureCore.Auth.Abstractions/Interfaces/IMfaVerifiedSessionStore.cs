namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Almacén del estado "sesión MFA-verificada" (S3, A-21). Permite saber si un
/// usuario verificó su identidad recientemente (dentro del TTL configurado en
/// <c>SecureAuthOptions.MfaVerifiedTtl</c>), independientemente de los tokens JWT.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Los claims JWT (<c>amr</c>, <c>mfa_method</c>) describen cómo se
/// autenticó la sesión en el momento de emitir los tokens, pero no permiten
/// consultar "¿el usuario verificó un factor hace menos de N minutos?". Este
/// almacén cubre ese hueco: alimenta el step-up (verify-action, cambiar
/// contraseña) y permite al host decidir si una mutación sensible sigue dentro
/// de la ventana de verificación.
///
/// Es un SPI con fallback en IDistributedCache (una ventana de verificación que
/// sobrevive al proceso). En multi-instancia, se comporta como la caché
/// distribuida que use el consumidor (Redis, SQL…).
/// </remarks>
public interface IMfaVerifiedSessionStore
{
    /// <summary>
    /// Marca al usuario como verificado usando el factor indicado.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="method">Método con el que se verificó (ej: "totp", "email", "email_otp").</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask SetVerifiedAsync(string userId, string method, CancellationToken cancellationToken = default);

    /// <summary>
    /// Indica si el usuario está dentro de la ventana de verificación vigente.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>true si hay una verificación vigente (no expirada).</returns>
    ValueTask<bool> IsVerifiedAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Limpia la ventana de verificación del usuario.
    /// </summary>
    /// <param name="userId">ID del usuario.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    ValueTask ClearAsync(string userId, CancellationToken cancellationToken = default);
}
