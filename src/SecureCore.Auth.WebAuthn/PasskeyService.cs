using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.WebAuthn;

/// <summary>
/// Servicio principal para la gestión de Passkeys (FIDO2/WebAuthn).
/// </summary>
/// <remarks>
/// DIDÁCTICA: WebAuthn es un protocolo de autenticación que usa criptografía de clave pública
/// en lugar de contraseñas. Funciona en dos fases llamadas "ceremonias":
///
/// 1. CEREMONIA DE REGISTRO (Attestation):
///    - El servidor genera un "challenge" (desafío aleatorio).
///    - El dispositivo del usuario crea un par de claves (pública/privada).
///    - La clave privada NUNCA sale del dispositivo.
///    - El servidor almacena la clave pública.
///
/// 2. CEREMONIA DE ASERCIÓN (Assertion):
///    - El servidor genera un nuevo challenge.
///    - El dispositivo firma el challenge con la clave privada.
///    - El servidor verifica la firma con la clave pública almacenada.
///
/// Ventajas sobre contraseñas:
/// - Inmune a phishing (la credencial está vinculada al dominio).
/// - Inmune a robo de base de datos (no hay secretos compartidos).
/// - Resistente a replay attacks (cada challenge es único y expira).
/// </remarks>
public sealed class PasskeyService(
    IFido2 fido2,
    ICredentialStore credentialStore,
    IUserStore userStore,
    IAuthEventDispatcher eventDispatcher,
    IOptions<WebAuthnOptions> webAuthnOptions,
    ILogger<PasskeyService> logger)
{
    private readonly WebAuthnOptions _options = webAuthnOptions.Value;

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE REGISTRO (Attestation)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Paso 1 de registro: Genera las opciones que el navegador necesita para crear una credencial.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método prepara el "desafío" (challenge) que el navegador enviará
    /// al autenticador del usuario (ej: sensor de huella, Face ID, YubiKey).
    /// El challenge es un array de bytes aleatorios que el autenticador debe firmar.
    /// Incluimos las credenciales existentes del usuario para evitar registros duplicados.
    /// </remarks>
    /// <param name="user">El usuario que quiere registrar una passkey.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Las opciones de creación para enviar al navegador.</returns>
    public async Task<CredentialCreateOptions> BeginRegistrationAsync(
        UserIdentity user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        // Creamos el descriptor del usuario para FIDO2
        var fido2User = new Fido2User
        {
            Id = System.Text.Encoding.UTF8.GetBytes(user.Id),
            Name = user.Email,
            DisplayName = user.DisplayName ?? user.Email
        };

        // Obtenemos las credenciales existentes para evitar registros duplicados
        var existingCredentials = await credentialStore.FindByUserIdAsync(user.Id, cancellationToken);
        var excludeCredentials = existingCredentials
            .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
            .ToList();

        // Configuramos las preferencias del autenticador
        var authenticatorSelection = new AuthenticatorSelection
        {
            UserVerification = ParseUserVerification(_options.UserVerification),
            ResidentKey = _options.RequireResidentKey
                ? ResidentKeyRequirement.Required
                : ResidentKeyRequirement.Preferred
        };

        // Si se especifica un tipo de autenticador, lo configuramos
        if (!string.IsNullOrEmpty(_options.AuthenticatorAttachment))
        {
            authenticatorSelection.AuthenticatorAttachment = _options.AuthenticatorAttachment switch
            {
                "platform" => Fido2NetLib.Objects.AuthenticatorAttachment.Platform,
                "cross-platform" => Fido2NetLib.Objects.AuthenticatorAttachment.CrossPlatform,
                _ => null
            };
        }

        // Generamos las opciones de creación con el challenge
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = fido2User,
            ExcludeCredentials = excludeCredentials,
            AuthenticatorSelection = authenticatorSelection,
            AttestationPreference = AttestationConveyancePreference.None
        });

        logger.LogDebug(
            "Ceremonia de registro iniciada para usuario {UserId}. Challenge generado.",
            user.Id);

        return options;
    }

    /// <summary>
    /// Paso 2 de registro: Valida la respuesta del autenticador y almacena la credencial.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Cuando el autenticador responde al challenge, el navegador envía
    /// un AuthenticatorAttestationRawResponse que contiene:
    /// - La clave pública generada
    /// - El ID de la credencial
    /// - La firma del challenge (prueba de posesión de la clave privada)
    /// - Metadatos del autenticador (tipo, modelo, etc.)
    ///
    /// El servidor verifica la firma y almacena la clave pública para futuras autenticaciones.
    /// </remarks>
    /// <param name="attestationResponse">Respuesta del autenticador del navegador.</param>
    /// <param name="originalOptions">Las opciones originales generadas en BeginRegistration.</param>
    /// <param name="userId">ID del usuario que está registrando la passkey.</param>
    /// <param name="deviceNickname">Nombre amigable para el dispositivo (opcional).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La credencial almacenada o null si la verificación falla.</returns>
    public async Task<StoredCredential?> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse attestationResponse,
        CredentialCreateOptions originalOptions,
        string userId,
        string? deviceNickname = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attestationResponse);
        ArgumentNullException.ThrowIfNull(originalOptions);
        ArgumentNullException.ThrowIfNull(userId);

        try
        {
            // Verificamos la respuesta del autenticador contra el challenge original
            var credentialResult = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = originalOptions,
                IsCredentialIdUniqueToUserCallback = async (args, ct) =>
                {
                    var existing = await credentialStore.FindByCredentialIdAsync(
                        args.CredentialId, ct);
                    return existing is null;
                }
            }, cancellationToken: cancellationToken);

            // Creamos y almacenamos la credencial
            var storedCredential = new StoredCredential
            {
                CredentialId = credentialResult.Id,
                PublicKey = credentialResult.PublicKey,
                UserId = userId,
                SignatureCount = credentialResult.SignCount,
                CredentialType = credentialResult.Type.ToString(),
                AaGuid = credentialResult.AaGuid,
                DeviceNickname = deviceNickname
            };

            await credentialStore.CreateAsync(storedCredential, cancellationToken);

            logger.LogInformation(
                "Passkey registrada exitosamente para usuario {UserId}. Dispositivo: {Nickname}",
                userId, deviceNickname ?? "(sin nombre)");

            // Disparar evento de registro de passkey
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.PasskeyRegistered,
                UserId = userId,
                Metadata = new Dictionary<string, string>
                {
                    ["aaGuid"] = credentialResult.AaGuid.ToString(),
                    ["deviceNickname"] = deviceNickname ?? ""
                }
            }, cancellationToken);

            return storedCredential;
        }
        catch (Fido2VerificationException ex)
        {
            logger.LogError(ex, "Error de verificación FIDO2 durante registro para usuario {UserId}", userId);
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE ASERCIÓN (Login con Passkey)
    // ═══════════════════════════════════════════════════════════════

    /// <summary>
    /// Paso 1 de login: Genera las opciones de aserción para el navegador.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: En la aserción, el servidor pide al autenticador que demuestre
    /// que posee la clave privada correspondiente a una credencial registrada.
    ///
    /// Hay dos modos:
    /// 1. Con userId (el usuario ya ingresó su email): enviamos las credenciales
    ///    permitidas para que el autenticador elija una.
    /// 2. Sin userId (Discoverable Credential): el autenticador propondrá las
    ///    credenciales que tiene guardadas para este dominio. El usuario elige una.
    /// </remarks>
    /// <param name="userId">ID del usuario (null para Discoverable Credentials).</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>Las opciones de aserción para enviar al navegador.</returns>
    public async Task<AssertionOptions> BeginAssertionAsync(
        string? userId = null,
        CancellationToken cancellationToken = default)
    {
        var allowedCredentials = new List<PublicKeyCredentialDescriptor>();

        // Si tenemos el userId, restringimos a sus credenciales registradas
        if (userId is not null)
        {
            var userCredentials = await credentialStore.FindByUserIdAsync(userId, cancellationToken);
            allowedCredentials.AddRange(
                userCredentials.Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)));
        }

        // Generamos las opciones de aserción
        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
            UserVerification = ParseUserVerification(_options.UserVerification)
        });

        logger.LogDebug(
            "Ceremonia de aserción iniciada. UserId: {UserId}, Credenciales permitidas: {Count}",
            userId ?? "(discoverable)", allowedCredentials.Count);

        return options;
    }

    /// <summary>
    /// Paso 2 de login: Valida la firma del autenticador y retorna el usuario autenticado.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Este método es un wrapper de compatibilidad sobre
    /// <see cref="CompleteAssertionDetailedAsync"/>. No distingue entre "credencial no
    /// encontrada" y "firma inválida" (ambas retornan <c>null</c>). Prefiere el método detallado
    /// cuando necesites conocer el sujeto en el ramo de fallo (p.ej. lockout por cuenta).
    /// </remarks>
    /// <param name="assertionResponse">Respuesta del autenticador del navegador.</param>
    /// <param name="originalOptions">Las opciones originales generadas en BeginAssertion.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>La identidad del usuario autenticado o null si falla la verificación.</returns>
    [Obsolete("Use CompleteAssertionDetailedAsync which exposes the subject (User) even when the signature fails.")]
    public async Task<UserIdentity?> CompleteAssertionAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        CancellationToken cancellationToken = default)
    {
        var result = await CompleteAssertionDetailedAsync(assertionResponse, originalOptions, cancellationToken);
        return result.SignatureValid ? result.User : null;
    }

    /// <summary>
    /// Paso 2 de login: valida la firma del autenticador y retorna el resultado con el sujeto resuelto.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: El autenticador firmó el challenge con su clave privada.
    /// El servidor verifica la firma usando la clave pública almacenada durante el registro.
    /// Si la firma es válida, el usuario queda autenticado sin haber ingresado contraseña.
    ///
    /// También se verifica el contador de firmas (SignatureCount) como medida
    /// anti-clonación: si el contador recibido es menor o igual al almacenado, podría
    /// indicar que alguien clonó el autenticador físico.
    ///
    /// En el ramo de fallo de firma se intenta resolver el <see cref="PasskeyAssertionResult.User"/>
    /// para habilitar políticas de seguridad por cuenta (p.ej. lockout de aserciones fallidas).
    /// </remarks>
    /// <param name="assertionResponse">Respuesta del autenticador del navegador.</param>
    /// <param name="originalOptions">Las opciones originales generadas en BeginAssertion.</param>
    /// <param name="cancellationToken">Token de cancelación.</param>
    /// <returns>El resultado de la aserción con la credencial y el sujeto resueltos.</returns>
    public async Task<PasskeyAssertionResult> CompleteAssertionDetailedAsync(
        AuthenticatorAssertionRawResponse assertionResponse,
        AssertionOptions originalOptions,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assertionResponse);
        ArgumentNullException.ThrowIfNull(originalOptions);

        try
        {
            // Buscamos la credencial almacenada por su ID
            //
            // DIDÁCTICA (A-29): el navegador envía el Id de la credencial en dos formatos:
            // - "id":     string Base64URL sin padding (RFC 4648 §5), p.ej. "-___".
            // - "rawId":  byte[] que Fido2NetLib YA decodifica correctamente (Base64UrlConverter).
            // El Id llega SIN padding y puede contener los caracteres '-'/'_', por lo que
            // Convert.FromBase64String (Base64 estándar) lanzaba FormatException en casi todos
            // los logins reales (los tests pasaban porque usaban Base64 estándar con padding).
            // Se prefiere "rawId" (bytes autoritativos decodificados por la librería) y solo si
            // no viene, se decodifica "id" con un decoder Base64URL tolerante.
            // Un Id malformado no puede referirse a una credencial existente, así que tratarlo
            // como "no encontrada" preserva el contrato del método (nunca lanza).
            var credentialIdBytes = TryResolveCredentialId(assertionResponse);
            if (credentialIdBytes is null)
            {
                logger.LogWarning(
                    "Id de credencial no es Base64 válido durante aserción; se rechaza como no encontrada");
                return PasskeyAssertionResult.CredentialNotFound();
            }

            var storedCredential = await credentialStore.FindByCredentialIdAsync(
                credentialIdBytes, cancellationToken);

            if (storedCredential is null)
            {
                logger.LogWarning("Credencial no encontrada para ID proporcionado durante aserción");
                return PasskeyAssertionResult.CredentialNotFound();
            }

            // Verificamos la firma del autenticador
            var assertionResult = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = originalOptions,
                StoredPublicKey = storedCredential.PublicKey,
                StoredSignatureCounter = storedCredential.SignatureCount,
                IsUserHandleOwnerOfCredentialIdCallback = async (args, ct) =>
                {
                    // DIDÁCTICA (Nº8): Este callback solo confirma que la credencial EXISTE.
                    // No vincula el userHandle remoto contra el usuario almacenado; esa
                    // vinculación criptográfica viene resuelta porque el sujeto se recupera
                    // desde storedCredential.UserId (la misma credencial verificada), no desde
                    // argumentos controlados por el cliente. Mientras se devuelva "existe",
                    // Fido2 garantiza que el par de claves es el correcto para la credencial.
                    var credential = await credentialStore.FindByCredentialIdAsync(
                        args.CredentialId, ct);
                    return credential is not null;
                }
            }, cancellationToken: cancellationToken);

            // DIDÁCTICA (Nº6): El contador de firmas se actualiza SIN try/catch a propósito:
            // un fallo transitorio del store aquí (timeout, caída) NO debe silenciarse, sino
            // propagarse al llamador para que la capa superior lo registre y decida.
            // Trae un coste aceptable: un login con firma válida podría resolverse como
            // excepción 5xx si la escritura falla. No se recomienda reintentar ni ocultar
            // porque eso impediría detectar operaciones de store degradadas.
            //
            // (Nº7) Aviso anti-enumeración: los resultados CredentialNotFound vs.
            // InvalidSignature son distinguibles POR DISEÑO (necesario para lockout por
            // cuenta). No expongas esa distinción al cliente: devuelve siempre el mismo
            // formato de error genérico de autenticación.
            await credentialStore.UpdateSignatureCountAsync(
                credentialIdBytes,
                assertionResult.SignCount,
                cancellationToken);

            // Obtener el usuario completo
            var user = await userStore.FindByIdAsync(storedCredential.UserId, cancellationToken);

            if (user is null)
            {
                logger.LogError(
                    "Usuario {UserId} no encontrado tras aserción exitosa de passkey",
                    storedCredential.UserId);
                return new PasskeyAssertionResult(null, CredentialFound: true, SignatureValid: true);
            }

            logger.LogInformation(
                "Login con Passkey exitoso para usuario {UserId}", user.Id);

            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.PasskeyLoginSuccess,
                UserId = user.Id,
                Metadata = new Dictionary<string, string>
                {
                    ["credentialId"] = assertionResponse.Id
                }
            }, cancellationToken);

            return PasskeyAssertionResult.Success(user);
        }
        catch (Fido2VerificationException ex)
        {
            logger.LogError(ex, "Error de verificación FIDO2 durante aserción");

            // DIDÁCTICA: Intentamos resolver el sujeto para contabilizar el fallo por cuenta.
            // El fallo solo puede ser de firma (la credencial ya fue encontrada), así que
            // exponemos la credencial como encontrada y la firma como inválida.
            UserIdentity? subject = null;
            try
            {
                var credentialIdBytes = TryResolveCredentialId(assertionResponse);
                if (credentialIdBytes is null)
                {
                    return PasskeyAssertionResult.InvalidSignature(subject);
                }

                var credential = await credentialStore.FindByCredentialIdAsync(
                    credentialIdBytes, cancellationToken);
                if (credential is not null)
                {
                    subject = await userStore.FindByIdAsync(credential.UserId, cancellationToken);
                }
            }
            catch (Exception lookupEx)
            {
                logger.LogDebug(lookupEx, "No se pudo resolver el sujeto en fallo de aserción");
            }

            return PasskeyAssertionResult.InvalidSignature(subject);
        }
    }

    /// <summary>
    /// Convierte el string de configuración a la enumeración de Fido2NetLib.
    /// </summary>
    private static UserVerificationRequirement ParseUserVerification(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "required" => UserVerificationRequirement.Required,
            "discouraged" => UserVerificationRequirement.Discouraged,
            _ => UserVerificationRequirement.Preferred
        };
    }

    /// <summary>
    /// Resuelve los bytes de la credencial desde la respuesta de assertion.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (A-29): se prefiere <c>RawId</c> (byte[] decodificado por el
    /// <c>Base64UrlConverter</c> de Fido2NetLib — Base64URL RFC 4648 §5 con/sin padding) porque
    /// es la representación autoritativa. Si el cliente no envió <c>rawId</c> (algunos clients
    /// mínimos solo envían <c>id</c>), se decodifica el string con un decoder Base64URL propio.
    /// </remarks>
    private static byte[]? TryResolveCredentialId(AuthenticatorAssertionRawResponse response)
    {
        if (response.RawId is { Length: > 0 })
        {
            return response.RawId;
        }

        return TryDecodeBase64UrlCredentialId(response.Id);
    }

    /// <summary>
    /// Decodifica el Id de credencial (Base64URL) de forma tolerante a payloads malformados.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA: Devuelve <c>null</c> si el valor está vacío o no es Base64URL válido,
    /// permitiendo tratar el caso como "credencial no encontrada" sin lanzar excepciones
    /// (un Id malformado no puede corresponder a una credencial del store).
    /// </remarks>
    private static byte[]? TryDecodeBase64UrlCredentialId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            // DIDÁCTICA (A-29): el navegador emite id/rawId en Base64URL (RFC 4648 §5):
            // usa '-'/'_' en lugar de '+'/'/' y NO lleva padding. Convert.FromBase64String
            // (Base64 estándar) rechazaría ambos casos. Normalizamos y añadimos el padding
            // que falte para decodificar con el mismo Convert.
            var normalized = value.Replace('-', '+').Replace('_', '/');
            switch (normalized.Length % 4)
            {
                case 2:
                    normalized += "==";
                    break;
                case 3:
                    normalized += "=";
                    break;
                case 1:
                    return null;
            }

            return Convert.FromBase64String(normalized);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
