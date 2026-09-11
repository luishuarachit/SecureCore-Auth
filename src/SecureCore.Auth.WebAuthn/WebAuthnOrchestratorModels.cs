using Fido2NetLib;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Models;

namespace SecureCore.Auth.WebAuthn;

/// <summary>
/// Resultado del paso "begin" de la ceremonia de registro de passkey (S4).
/// </summary>
/// <remarks>
/// DIDÁCTICA: contiene el identificador del challenge (que el cliente debe devolver
/// en el paso "complete") y las opciones de creación que el navegador usa para
/// invocar <c>navigator.credentials.create</c>. El propio challenge viaja dentro de
/// <see cref="Options"/>; el servidor conserva el payload serializado de forma
/// single-use en el challenge store.
/// </remarks>
/// <param name="ChallengeId">Identificador del challenge (se devuelve en complete).</param>
/// <param name="Options">Opciones de creación para el navegador.</param>
public sealed record WebAuthnBeginRegistrationResult(string ChallengeId, CredentialCreateOptions Options);

/// <summary>
/// Resultado del paso "complete" de la ceremonia de registro de passkey (S4).
/// </summary>
/// <remarks>
/// DIDÁCTICA: en caso de fallo el mensaje es genérico (no se distingue entre
/// "challenge reusado/expirado" y "respuesta inválida") para no orientar a un
/// atacante sobre el estado del challenge.
/// </remarks>
/// <param name="Success">true si la credencial fue verificada y almacenada.</param>
/// <param name="Credential">La credencial almacenada cuando <see cref="Success"/> es true.</param>
/// <param name="ErrorMessage">Mensaje genérico de error (solo cuando <see cref="Success"/> es false).</param>
public sealed record WebAuthnRegistrationResult(
    bool Success,
    StoredCredential? Credential = null,
    string? ErrorMessage = null)
{
    public static WebAuthnRegistrationResult Ok(StoredCredential credential) =>
        new(true, credential);

    public static WebAuthnRegistrationResult Fail(string errorMessage) =>
        new(false, null, errorMessage);
}

/// <summary>
/// Resultado del paso "begin" de la ceremonia de aserción (login con passkey, S4).
/// </summary>
/// <param name="ChallengeId">Identificador del challenge (se devuelve en complete).</param>
/// <param name="Options">Opciones de aserción para el navegador.</param>
public sealed record WebAuthnBeginLoginResult(string ChallengeId, AssertionOptions Options);

/// <summary>
/// Resultado de la ceremonia de aserción: login con passkey (S4).
/// </summary>
/// <remarks>
/// DIDÁCTICA: cuando <see cref="Success"/> es true se entregan los tokens de acceso
/// y de refresco (claims <c>amr=webauthn</c>). El mensaje de error es siempre genérico:
/// el cliente NUNCA debe distinguir entre credencial no encontrada, firma inválida,
/// challenge reusado o cuenta bloqueada (anti-enumeración).
/// </remarks>
/// <param name="Success">true si la firma se verificó y se emitieron tokens.</param>
/// <param name="Tokens">Par de tokens cuando <see cref="Success"/> es true.</param>
/// <param name="LockedOut">true si la cuenta quedó bloqueada por aserciones fallidas (S1).</param>
/// <param name="ErrorMessage">Mensaje genérico de error (solo cuando <see cref="Success"/> es false).</param>
public sealed record WebAuthnLoginResult(
    bool Success,
    TokenResponse? Tokens = null,
    bool LockedOut = false,
    string? ErrorMessage = null)
{
    public static WebAuthnLoginResult Ok(TokenResponse tokens) =>
        new(true, tokens);

    public static WebAuthnLoginResult Fail(string errorMessage, bool lockedOut = false) =>
        new(false, null, lockedOut, errorMessage);
}