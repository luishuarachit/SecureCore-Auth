namespace SecureCore.Auth.Abstractions.Interfaces;

/// <summary>
/// Define el contrato para el hashing y verificación de contraseñas.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Esta interfaz abstrae el algoritmo de hashing de contraseñas.
/// La implementación por defecto usa Argon2id, considerado el estándar actual
/// para hashing de contraseñas (ganador del Password Hashing Competition 2015).
/// Argon2id combina protección contra ataques GPU (Argon2d) y ataques de
/// canal lateral (Argon2i), ofreciendo lo mejor de ambos mundos.
/// </remarks>
public interface IPasswordHasher
{
    /// <summary>
    /// Genera un hash seguro de la contraseña proporcionada.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El hash incluye un salt aleatorio generado internamente.
    /// El resultado es un string autocontenido que incluye el salt, los parámetros
    /// del algoritmo y el hash resultante. Esto permite verificar la contraseña
    /// sin necesidad de almacenar el salt por separado.
    /// </remarks>
    /// <param name="password">La contraseña en texto plano a hashear.</param>
    /// <returns>El hash completo de la contraseña (incluye salt y parámetros).</returns>
    string HashPassword(string password);

    /// <summary>
    /// Verifica si una contraseña en texto plano coincide con un hash almacenado.
    /// </summary>
    /// <param name="hashedPassword">El hash almacenado previamente.</param>
    /// <param name="providedPassword">La contraseña en texto plano a verificar.</param>
    /// <returns>El resultado de la verificación.</returns>
    PasswordVerificationResult VerifyPassword(string hashedPassword, string providedPassword);

    /// <summary>
    /// Realiza una verificación ficticia para mitigar ataques de enumeración por tiempo.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Cuando un usuario no existe, el sistema suele responder más rápido
    /// porque no tiene que calcular el hash. Un atacante puede medir esto.
    /// Este método consume el mismo tiempo que una verificación real, haciendo que
    /// el tiempo de respuesta sea constante e indistinguible.
    /// </remarks>
    /// <param name="providedPassword">La contraseña proporcionada (se ignora el resultado).</param>
    void VerifyDummyPassword(string providedPassword);
}

/// <summary>
/// Resultado de la verificación de una contraseña.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Además de "éxito" y "fallo", existe un tercer estado: "necesita re-hash".
/// Esto ocurre cuando la contraseña es correcta pero fue hasheada con parámetros obsoletos
/// (por ejemplo, menos iteraciones). La aplicación debería re-hashear la contraseña
/// con los parámetros actuales y guardar el nuevo hash.
/// </remarks>
public enum PasswordVerificationResult
{
    /// <summary>La contraseña no coincide con el hash.</summary>
    Failed = 0,

    /// <summary>La contraseña coincide con el hash.</summary>
    Success = 1,

    /// <summary>
    /// La contraseña coincide, pero el hash debe regenerarse con parámetros actualizados.
    /// </summary>
    SuccessRehashNeeded = 2
}
