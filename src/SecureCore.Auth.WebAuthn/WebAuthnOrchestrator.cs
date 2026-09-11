using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.WebAuthn;

/// <summary>
/// Orquestador de WebAuthn de primera clase (S4): une las ceremonias FIDO2 (<see cref="PasskeyService"/>)
/// con el challenge single-use (S2), el origin check, el anti-abuso por cuenta (S1) y la emisión de tokens.
/// </summary>
/// <remarks>
/// DIDÁCTICA: <see cref="PasskeyService"/> resuelve las ceremonias criptográficas (verificar
/// attestation/assertion contra Fido2NetLib), pero NO gestiona el ciclo de vida del challenge
/// ni entrega tokens. <see cref="WebAuthnOrchestrator"/> es la capa que convierte esas ceremonias
/// en un flujo de autenticación completo:
///
/// CICLO DE VIDA DEL CHALLENGE (S2): en cada ceremonia "begin" se genera un challengeId único
/// (CSPRNG) y se persiste el payload serializado de las opciones con TTL
/// (<c>WebAuthnOptions.ChallengeTimeoutSeconds</c>, default 60 s). En "complete", el challenge se
/// consume atómicamente (GETDEL) ANTES de validar la respuesta: si ya se usó, expiró o no existe,
/// la ceremonia se rechaza con error genérico. Esto impide el replay de una respuesta firmada.
///
/// ORIGIN CHECK: cada uno de los 4 pasos valida que el origin del navegador esté en
/// <c>WebAuthnOptions.Origins</c>. Defense-in-depth con la verificación interna de clientDataJSON
/// que hace Fido2NetLib. Fail-closed: si la lista de origins está vacía, se rechaza todo (sin
/// origins configurados, WebAuthn no puede ser seguro).
///
/// ANTI-ABUSO (S1): una assertion fallida cuyo sujeto se pueda resolver (fix A-17) consume el
/// presupuesto del scope <c>AccountProtectionScope.Passkey</c> POR CUENTA. Un éxito renueva el
/// presupuesto. El cliente nunca distingue "credencial no encontrada" vs "firma inválida".
///
/// EMISIÓN DE TOKENS: on éxito de assertion se emite un par de tokens con el claim
/// <c>amr=webauthn</c> y, si está habilitado (<c>OpenMfaVerifiedWindowOnPasskeyLogin</c>), se abre
/// la ventana mfa_verified compartida (S3). La verificación de usuario de la passkey (biometría,
/// PIN) es un factor autenticador AAL2 (NIST SP 800-63B), así que la ventana es coherente con el
/// flujo "password + mfa".
/// </remarks>
public sealed class WebAuthnOrchestrator(
    PasskeyService passkeyService,
    IWebAuthnChallengeStore challengeStore,
    IUserStore userStore,
    ITokenService tokenService,
    ISessionStore sessionStore,
    IAuthEventDispatcher eventDispatcher,
    IOptions<WebAuthnOptions> webAuthnOptions,
    IOptions<SecureAuthOptions> secureAuthOptions,
    ILogger<WebAuthnOrchestrator> logger,
    IAccountProtectionService? accountProtectionService = null,
    IOptions<AccountProtectionOptions>? accountProtectionOptions = null,
    IMfaVerifiedSessionStore? mfaVerifiedSessionStore = null)
{
    private readonly WebAuthnOptions _webAuthnOptions = webAuthnOptions.Value;
    private readonly SecureAuthOptions _secureAuthOptions = secureAuthOptions.Value;
    private readonly IAccountProtectionService? _accountProtection = accountProtectionService;
    private readonly AccountProtectionOptions? _accountProtectionOptions = accountProtectionOptions?.Value;

    // DIDÁCTICA (A-29): la clave del challenge en el store se TIPA con la ceremonia que la creó
    // (login vs registro). Un challenge obtenido en una ceremonia jamás es consumible por la otra:
    // complete busca la clave tipada esperada, por lo que un "login:…" no matchea un consume de
    // registro (fail-closed) y viceversa. El valor devuelto al cliente sigue siendo opaco (el
    // tag vive dentro del store), preservando el contrato de round-trip.
    private const string RegistrationChallengeTag = "register";
    private const string LoginChallengeTag = "login";

    /// <summary>
    /// true cuando el subsistema S1 está registrado Y habilitado (opt-in, D-03).
    /// </summary>
    private bool AccountProtectionEnabled =>
        _accountProtection is not null && _accountProtectionOptions is { Enabled: true };

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE REGISTRO
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Paso 1 de registro: genera las opciones de creación y persiste el challenge single-use.
    /// </summary>
    /// <param name="userId">ID del usuario autenticado que registra la passkey.</param>
    /// <param name="origin">Origin del navegador (debe estar en <c>WebAuthnOptions.Origins</c>).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El challengeId y las opciones para el navegador.</returns>
    public async Task<WebAuthnBeginRegistrationResult> BeginRegistrationAsync(
        string userId,
        string origin,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(origin);

        if (!IsOriginAllowed(origin))
        {
            // DIDÁCTICA: el origin se rechaza ANTES de generar cualquier challenge, para no
            // consumir recursos con orígenes no autorizados (farming de challenges).
            logger.LogWarning("Origin no autorizado en begin de registro: {Origin}", origin);
            throw new WebAuthnOriginNotAllowedException(origin);
        }

        var user = await userStore.FindByIdAsync(userId, cancellationToken);
        if (user is null)
        {
            // DIDÁCTICA: flujo autenticado — si el usuario no existe no revelamos el estado
            // (sin oráculo de enumeración), y rechazamos con el mismo error genérico.
            logger.LogDebug("Begin de registro sin usuario para {UserId} (sin oráculo)", userId);
            throw new WebAuthnOriginNotAllowedException(origin);
        }

        var options = await passkeyService.BeginRegistrationAsync(user, cancellationToken);
        var (challengeId, ttl) = await StoreChallengeAsync(
            options.ToJson(),
            RegistrationChallengeTag,
            cancellationToken);

        return new WebAuthnBeginRegistrationResult(challengeId, options);
    }

    /// <summary>
    /// Paso 2 de registro: consume el challenge single-use y valida la respuesta del autenticador.
    /// </summary>
    /// <param name="userId">ID del usuario autenticado.</param>
    /// <param name="origin">Origin del navegador (debe estar en <c>WebAuthnOptions.Origins</c>).</param>
    /// <param name="challengeId">Identificador del challenge devuelto en begin.</param>
    /// <param name="attestationResponse">Respuesta de attestation del navegador.</param>
    /// <param name="deviceNickname">Nombre amigable opcional para el dispositivo.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Resultado con la credencial almacenada o error genérico.</returns>
    public async Task<WebAuthnRegistrationResult> CompleteRegistrationAsync(
        string userId,
        string origin,
        string challengeId,
        AuthenticatorAttestationRawResponse attestationResponse,
        string? deviceNickname = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(challengeId);
        ArgumentNullException.ThrowIfNull(attestationResponse);

        if (!IsOriginAllowed(origin))
        {
            logger.LogWarning("Origin no autorizado en complete de registro: {Origin}", origin);
            return WebAuthnRegistrationResult.Fail("No se pudo completar el registro de la passkey.");
        }

        // DIDÁCTICA (S2): el consumo atómico garantiza single-use. Un challenge reusado,
        // expirado o inexistente produce la misma respuesta genérica que cualquier fallo,
        // sin filtrar al atacante cuál de los casos ocurrió.
        var payload = await challengeStore.GetAndDeleteAsync(
            ChallengeKey(RegistrationChallengeTag, challengeId), cancellationToken);
        if (payload is null)
        {
            logger.LogWarning("Challenge reusado o expirado durante registro para {UserId}", userId);
            return WebAuthnRegistrationResult.Fail("No se pudo completar el registro de la passkey.");
        }

        var originalOptions = TryDeserializeCreateOptions(payload);
        if (originalOptions is null)
        {
            logger.LogError("Payload corrupto de challenge de registro para {UserId}", userId);
            return WebAuthnRegistrationResult.Fail("No se pudo completar el registro de la passkey.");
        }

        var credential = await passkeyService.CompleteRegistrationAsync(
            attestationResponse,
            originalOptions,
            userId,
            deviceNickname,
            cancellationToken);

        if (credential is null)
        {
            logger.LogWarning("Attestation inválida durante registro para {UserId}", userId);
            return WebAuthnRegistrationResult.Fail("No se pudo completar el registro de la passkey.");
        }

        logger.LogInformation("Passkey registrada vía orquestador para {UserId}", userId);
        return WebAuthnRegistrationResult.Ok(credential);
    }

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE ASERCIÓN (Login con Passkey)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Paso 1 de login: genera las opciones de aserción y persiste el challenge single-use.
    /// </summary>
    /// <param name="userId">
    /// ID del usuario (null para Discoverable Credentials). Si se indica un usuario inexistente,
    /// se genera igualmente un challenge válido (anti-enumeración).
    /// </param>
    /// <param name="origin">Origin del navegador (debe estar en <c>WebAuthnOptions.Origins</c>).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El challengeId y las opciones para el navegador.</returns>
    public async Task<WebAuthnBeginLoginResult> BeginLoginAsync(
        string? userId,
        string origin,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(origin);

        if (!IsOriginAllowed(origin))
        {
            logger.LogWarning("Origin no autorizado en begin de login: {Origin}", origin);
            throw new WebAuthnOriginNotAllowedException(origin);
        }

        // DIDÁCTICA (A-29, anti-enumeración): si el userId no existe en el store, el autenticador no
        // tendrá credenciales permitidas y la aserción fallará en complete con error genérico.
        // El begin NO valida la existencia del usuario para no revelar qué emails están
        // registrados (el veredicto llega solo en complete, indistinguible).
        //
        // ADEMÁS (A-29): por defecto NO se devuelven los descriptores de credenciales en
        // allowCredentials. Devolverlos solo cuando el usuario está enrolado (y vacío cuando no)
        // convertiría el begin en un oráculo de cuentas por barrido de userIds: la FORMA de la
        // respuesta difiere. Con Discoverable Credentials (RequireResidentKey default true) el
        // login funciona igual sin la pista. Solo si el host lo habilita explícitamente
        // (DiscloseCredentialsInLoginBegin) se pasa el userId al ceremonia para restringirlas.
        var options = await passkeyService.BeginAssertionAsync(
            _webAuthnOptions.DiscloseCredentialsInLoginBegin ? userId : null,
            cancellationToken);
        var (challengeId, _) = await StoreChallengeAsync(options.ToJson(), LoginChallengeTag, cancellationToken);

        return new WebAuthnBeginLoginResult(challengeId, options);
    }

    /// <summary>
    /// Paso 2 de login: consume el challenge single-use, valida la firma y emite tokens.
    /// </summary>
    /// <param name="origin">Origin del navegador (debe estar en <c>WebAuthnOptions.Origins</c>).</param>
    /// <param name="challengeId">Identificador del challenge devuelto en begin.</param>
    /// <param name="assertionResponse">Respuesta de assertion del navegador.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>
    /// <see cref="WebAuthnLoginResult.Ok"/> con los tokens si la firma es válida, o un fallo
    /// genérico (credencial no encontrada / firma inválida / challenge reusado / lockout S1).
    /// </returns>
    public async Task<WebAuthnLoginResult> CompleteLoginAsync(
        string origin,
        string challengeId,
        AuthenticatorAssertionRawResponse assertionResponse,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(challengeId);
        ArgumentNullException.ThrowIfNull(assertionResponse);

        if (!IsOriginAllowed(origin))
        {
            logger.LogWarning("Origin no autorizado en complete de login: {Origin}", origin);
            return WebAuthnLoginResult.Fail("Autenticación fallida.");
        }

        // DIDÁCTICA (S2): el challenge se consume ANTES de validar la aserción. Esto acota el
        // replay: cada firma válida requiere un challenge fresco del begin.
        var payload = await challengeStore.GetAndDeleteAsync(
            ChallengeKey(LoginChallengeTag, challengeId), cancellationToken);
        if (payload is null)
        {
            logger.LogWarning("Challenge reusado o expirado durante login");
            return WebAuthnLoginResult.Fail("Autenticación fallida.");
        }

        var originalOptions = TryDeserializeAssertionOptions(payload);
        if (originalOptions is null)
        {
            logger.LogError("Payload corrupto de challenge de login");
            return WebAuthnLoginResult.Fail("Autenticación fallida.");
        }

        var assertion = await passkeyService.CompleteAssertionDetailedAsync(
            assertionResponse,
            originalOptions,
            cancellationToken);

        if (!assertion.SignatureValid)
        {
            // DIDÁCTICA (A-17 + S1): el resultado detallado nos da el sujeto (si se pudo
            // resolver la credencial) para contabilizar el fallo POR CUENTA. Si no hay sujeto
            // (credencial desconocida/anónima) no existe cuenta que bloquear. La respuesta al
            // cliente es la misma en todos los ramos (anti-enumeración).
            if (AccountProtectionEnabled && assertion.User is not null)
            {
                var lockedOut = await RecordAssertionFailureAsync(assertion.User.Id, cancellationToken);
                if (lockedOut)
                {
                    logger.LogWarning("Cuenta {UserId} bloqueada por aserciones fallidas", assertion.User.Id);
                    await eventDispatcher.DispatchAsync(new AuthEvent
                    {
                        EventType = AuthEventType.AccountLockedOut,
                        UserId = assertion.User.Id,
                        Metadata = new Dictionary<string, string>
                        {
                            ["reason"] = "lock_triggered",
                            ["scope"] = "passkey"
                        }
                    }, cancellationToken);

                    return WebAuthnLoginResult.Fail("Autenticación fallida. Cuenta temporalmente bloqueada.", lockedOut: true);
                }
            }

            logger.LogWarning("Assertion de passkey fallida (credencial o firma inválida)");
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.PasskeyVerificationFailed,
                UserId = assertion.User?.Id
            }, cancellationToken);

            return WebAuthnLoginResult.Fail("Autenticación fallida.");
        }

        // DIDÁCTICA: en el ramo de éxito criptográfico la credencial fue encontrada PERO el
        // usuario no pudo resolverse (caso raro: credencial huérfana o usuario borrado). No hay
        // tokens que emitir; se responde genérico y se audita.
        if (assertion.User is null)
        {
            logger.LogError("Assertion válida sin sujeto resoluble (usuario huérfano)");
            return WebAuthnLoginResult.Fail("Autenticación fallida.");
        }

        var user = assertion.User;

        // DIDÁCTICA (S1): el éxito renueva el presupuesto del scope Passkey.
        if (AccountProtectionEnabled)
        {
            await _accountProtection!.RecordSuccessAsync(AccountProtectionScope.Passkey, user.Id, cancellationToken);
        }

        await userStore.ResetFailedAccessCountAsync(user.Id, cancellationToken);

        // DIDÁCTICA (S3): si la política lo permite, el login con passkey abre/renueva la ventana
        // mfa_verified compartida. La passkey con user verification es un factor autenticador
        // AAL2: coherente reutilizar la misma ventana que "password + mfa".
        if (_webAuthnOptions.OpenMfaVerifiedWindowOnPasskeyLogin && mfaVerifiedSessionStore is not null)
        {
            await mfaVerifiedSessionStore.SetVerifiedAsync(user.Id, "webauthn", cancellationToken);
        }

        // DIDÁCTICA: claim amr=webauthn (patrón de CompleteMfaLoginAsync: amr=mfa). El claim es
        // inyectable vía UserIdentity.Claims (no está bloqueado por JwtTokenService) y describe
        // cómo se autenticó este par de tokens.
        // A-29: se CLONA el diccionario antes de mutar. user.Claims puede ser una instancia
        // compartida/cacheada del store; mutarla en sitio contaminaría tokens de otros flujos
        // con un amr que no les corresponde.
        // DIDÁCTICA (S6, A-25 / RFC 8176): con EmitAmr se añade mfa_method=webauthn (paridad con
        // los flujos MFA que emiten amr=mfa + mfa_method). Opt-in: sin la opción, el token no cambia.
        var customClaims = new Dictionary<string, string>(user.Claims ?? []);
        customClaims["amr"] = "webauthn";
        if (_secureAuthOptions.EmitAmr)
        {
            customClaims["mfa_method"] = "webauthn";
        }
        var userWithClaims = user with { Claims = customClaims };

        var tokens = await tokenService.GenerateTokenPairAsync(userWithClaims, cancellationToken);

        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_secureAuthOptions.RefreshTokenLifetime),
            AuthMethod = "webauthn",
            MfaMethod = _secureAuthOptions.EmitAmr ? "webauthn" : null
        };

        await sessionStore.CreateAsync(refreshEntry, cancellationToken);

        logger.LogInformation("Login con passkey exitoso para {UserId}", user.Id);
        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = user.Id,
            Metadata = new Dictionary<string, string> { ["method"] = "webauthn" }
        }, cancellationToken);

        // DIDÁCTICA: PasskeyService ya emitió PasskeyLoginSuccess (evento de dominio del
        // autenticador); aquí se emite LoginSuccess consistente con el resto de orquestadores.
        return WebAuthnLoginResult.Ok(tokens);
    }

    // ═══════════════════════════════════════════════════════════════
    //  HELPERS PRIVADOS
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Valida el origin contra <c>WebAuthnOptions.Origins</c> (fail-closed si la lista está vacía).
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: el origin es la prueba de que la petición viene del dominio legítimo del
    /// Relying Party (anti-phishing de la propia passkey). Fail-closed: sin origins
    /// configurados, WebAuthn no puede garantizar su propiedad central de seguridad.
    /// </remarks>
    private bool IsOriginAllowed(string origin)
    {
        if (_webAuthnOptions.Origins.Count == 0)
        {
            logger.LogError("WebAuthnOptions.Origins vacío: se rechazan todas las ceremonias. Configure SecureAuth:WebAuthn:Origins.");
            return false;
        }

        return _webAuthnOptions.Origins.Contains(origin, StringComparer.Ordinal);
    }

    /// <summary>
    /// Persiste el payload del challenge con un TTL derivado de <c>ChallengeTimeoutSeconds</c>.
    /// </summary>
    /// <param name="payload">JSON serializado de las opciones de la ceremonia.</param>
    /// <param name="tag">Ceremonia que origina el challenge (<see cref="RegistrationChallengeTag"/>
    /// o <see cref="LoginChallengeTag"/>); se incrusta en la clave del store.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El challengeId generado (CSPRNG) y el TTL efectivo. El challengeId devuelto es el
    /// valor opaco crudo; la clave física del store incluye el tag de ceremonia.</returns>
    private async Task<(string ChallengeId, TimeSpan Ttl)> StoreChallengeAsync(
        string payload,
        string tag,
        CancellationToken cancellationToken)
    {
        var ttl = TimeSpan.FromSeconds(_webAuthnOptions.ChallengeTimeoutSeconds);
        // DIDÁCTICA (auditoría): challengeId con CSPRNG (RandomNumberGenerator), no Guid.NewGuid()
        // (que no es una fuente criptográfica documentada). Actúa como capability token.
        var rawId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        await challengeStore.CreateAsync(ChallengeKey(tag, rawId), payload, ttl, cancellationToken);

        logger.LogDebug("Challenge de {Tag} creado. Id: {ChallengeId}, TTL: {Ttl}s",
            tag, rawId, _webAuthnOptions.ChallengeTimeoutSeconds);

        return (rawId, ttl);
    }

    /// <summary>
    /// Compone la clave física del challenge tipada por ceremonia (A-29).
    /// </summary>
    private static string ChallengeKey(string tag, string challengeId) => $"{tag}:{challengeId}";

    /// <summary>
    /// Registra el fallo de assertion contra S1 (scope Passkey) y devuelve si la cuenta quedó bloqueada.
    /// </summary>
    private async Task<bool> RecordAssertionFailureAsync(string userId, CancellationToken cancellationToken)
    {
        await _accountProtection!.RecordFailureAsync(AccountProtectionScope.Passkey, userId, cancellationToken);
        var check = await _accountProtection.CheckAsync(AccountProtectionScope.Passkey, userId, cancellationToken);
        return !check.Allowed;
    }

    /// <summary>
    /// Deserializa el payload del challenge de registro de forma tolerante a errores.
    /// </summary>
    private static CredentialCreateOptions? TryDeserializeCreateOptions(string payload)
    {
        try
        {
            return CredentialCreateOptions.FromJson(payload);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Deserializa el payload del challenge de login de forma tolerante a errores.
    /// </summary>
    private static AssertionOptions? TryDeserializeAssertionOptions(string payload)
    {
        try
        {
            return AssertionOptions.FromJson(payload);
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// Excepción lanzada cuando el origin de una ceremonia WebAuthn no está autorizado (S4).
/// </summary>
/// <remarks>
/// DIDÁCTICA: se usa en las fases "begin" (no hay resultado de error normal en el contrato
/// cuando no se puede siquiera generar el challenge). El endpoint la traduce a 400 con mensaje
/// genérico. Jamás se expone el origin rechazado ni el motivo (anti-enumeración).
/// </remarks>
public sealed class WebAuthnOriginNotAllowedException(string origin) : InvalidOperationException(
    "El origin no está autorizado para la ceremonia WebAuthn.")
{
    /// <summary>Origin que fue rechazado (solo para log; nunca se expone en responses).</summary>
    public string RejectedOrigin { get; } = origin;
}
