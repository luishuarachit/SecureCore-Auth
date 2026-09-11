using SecureCore.Auth.Abstractions;

namespace SecureCore.Auth.WebAuthn;

/// <summary>
/// Resultado de una aserción WebAuthn (login con passkey) que distingue los motivos de fallo.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El método original <c>CompleteAssertionAsync</c> retorna <c>null</c> tanto cuando
/// la credencial no existe como cuando la firma es inválida. Esa ambigüedad impide, por ejemplo,
/// contabilizar aserciones fallidas POR CUENTA (lockout), porque en el ramo de firma inválida se
/// conoce la credencial/usuario pero no se expone.
///
/// Este resultado expone tres datos:
/// - <see cref="User"/>: el sujeto resuelto (si pudo resolverse), útil para aplicar políticas por cuenta.
/// - <see cref="CredentialFound"/>: si la credencial referida por el cliente existe en el store.
/// - <see cref="SignatureValid"/>: si la firma del challenge se verificó correctamente.
///
/// AVISO DE SEGURIDAD (Nº7): <see cref="CredentialFound"/> es un oráculo de existencia de
/// credenciales: verifica la base de datos contra un Id arbitrario del cliente. Es necesario
/// por diseño (para poder contabilizar aserciones fallidas POR CUENTA), pero NUNCA debes
/// exponer esta distinción al cliente; los endpoints de login deben devolver siempre el mismo
/// error genérico de autenticación tanto si la credencial no existe como si la firma es inválida.
/// </remarks>
public sealed record PasskeyAssertionResult(
    UserIdentity? User,
    bool CredentialFound,
    bool SignatureValid)
{
    /// <summary>
    /// Resultado de éxito: credencial encontrada, firma válida y usuario resuelto.
    /// </summary>
    public static PasskeyAssertionResult Success(UserIdentity user) =>
        new(user, CredentialFound: true, SignatureValid: true);

    /// <summary>
    /// Resultado cuando la credencial referida por el cliente no existe en el store.
    /// </summary>
    public static PasskeyAssertionResult CredentialNotFound() =>
        new(null, CredentialFound: false, SignatureValid: false);

    /// <summary>
    /// Resultado cuando la firma del challenge es inválida (posible intento de fraude).
    /// Expone el sujeto si pudo resolverse para habilitar políticas por cuenta.
    /// </summary>
    public static PasskeyAssertionResult InvalidSignature(UserIdentity? subject = null) =>
        new(subject, CredentialFound: true, SignatureValid: false);
}
