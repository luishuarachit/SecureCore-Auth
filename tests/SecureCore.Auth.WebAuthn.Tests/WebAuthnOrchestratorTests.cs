using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.WebAuthn;

namespace SecureCore.Auth.WebAuthn.Tests;

/// <summary>
/// Tests de WebAuthnOrchestrator — ceremonias de primera clase (S4): challenge single-use (S2),
/// origin check fail-closed, anti-abuso por cuenta (S1) y emisión de tokens con amr=webauthn + mfa window (S3).
/// </summary>
public class WebAuthnOrchestratorTests
{
    private const string AllowedOrigin = "https://test.example.com";
    private const string EvilOrigin = "https://evil.example.com";

    private static readonly byte[] CredentialId = [1, 2, 3];
    private static readonly string CredentialIdBase64 = Convert.ToBase64String(CredentialId);

    private const string CreateOptionsJson = """
        {"challenge":"AQIDBAUGBwgJ","rp":{"id":"test.example.com","name":"Test RP"},"user":{"id":"AQID","name":"test@example.com","displayName":"Test User"},"pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":60000,"attestation":"none","authenticatorSelection":{"residentKey":"preferred","userVerification":"preferred"},"excludeCredentials":[],"extensions":{}}
        """;

    private const string AssertionOptionsJson = """
        {"challenge":"AQIDBAUGBwgJ","rpId":"test.example.com","timeout":60000,"userVerification":"preferred","allowCredentials":[]}
        """;

    private readonly IFido2 _fido2 = Substitute.For<IFido2>();
    private readonly ICredentialStore _credentialStore = Substitute.For<ICredentialStore>();
    private readonly IUserStore _userStore = Substitute.For<IUserStore>();
    private readonly IWebAuthnChallengeStore _challengeStore = Substitute.For<IWebAuthnChallengeStore>();
    private readonly ITokenService _tokenService = Substitute.For<ITokenService>();
    private readonly ISessionStore _sessionStore = Substitute.For<ISessionStore>();
    private readonly IAuthEventDispatcher _eventDispatcher = Substitute.For<IAuthEventDispatcher>();
    private readonly IAccountProtectionService _protection = Substitute.For<IAccountProtectionService>();
    private readonly IMfaVerifiedSessionStore _mfaVerified = Substitute.For<IMfaVerifiedSessionStore>();

    private readonly WebAuthnOptions _webAuthnOptions = new()
    {
        RelyingPartyName = "Test RP",
        RelyingPartyId = "test.example.com",
        Origins = [AllowedOrigin],
        ChallengeTimeoutSeconds = 60
    };

    private WebAuthnOrchestrator CreateOrchestrator(
        bool enableProtection = false,
        bool openMfaWindow = true,
        string[]? origins = null,
        bool discloseCredentials = false)
    {
        _webAuthnOptions.Origins = origins is null ? [AllowedOrigin] : [.. origins];
        _webAuthnOptions.OpenMfaVerifiedWindowOnPasskeyLogin = openMfaWindow;
        _webAuthnOptions.DiscloseCredentialsInLoginBegin = discloseCredentials;

        var passkeyService = new PasskeyService(
            _fido2,
            _credentialStore,
            _userStore,
            _eventDispatcher,
            Options.Create(_webAuthnOptions),
            NullLogger<PasskeyService>.Instance);

        return new WebAuthnOrchestrator(
            passkeyService,
            _challengeStore,
            _userStore,
            _tokenService,
            _sessionStore,
            _eventDispatcher,
            Options.Create(_webAuthnOptions),
            Options.Create(new SecureAuthOptions()),
            NullLogger<WebAuthnOrchestrator>.Instance,
            enableProtection ? _protection : null,
            enableProtection ? Options.Create(new AccountProtectionOptions { Enabled = true }) : null,
            openMfaWindow ? _mfaVerified : null);
    }

    private static UserIdentity NewUser(string id = "u1")
    {
        return new UserIdentity
        {
            Id = id,
            Email = $"{id}@example.com",
            SecurityStamp = "stamp"
        };
    }

    private static StoredCredential NewStoredCredential(string userId = "u1", uint signatureCount = 5)
    {
        return new StoredCredential
        {
            CredentialId = CredentialId,
            PublicKey = [9, 9, 9],
            UserId = userId,
            SignatureCount = signatureCount,
            CredentialType = PublicKeyCredentialType.PublicKey.ToString(),
            AaGuid = Guid.NewGuid()
        };
    }

    private static AuthenticatorAssertionRawResponse NewAssertionResponse()
    {
        return new AuthenticatorAssertionRawResponse
        {
            Id = CredentialIdBase64,
            RawId = CredentialId,
            Type = PublicKeyCredentialType.PublicKey,
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                ClientDataJson = [1, 2],
                AuthenticatorData = new byte[37],
                Signature = new byte[10],
                UserHandle = [1, 2, 3]
            }
        };
    }

    private void StubSuccessfulAssertion(UserIdentity? resolvedUser = null, bool resolveUser = true)
    {
        _challengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(AssertionOptionsJson));

        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(NewStoredCredential()));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult
            {
                CredentialId = CredentialId,
                SignCount = 6
            });

        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(resolveUser ? resolvedUser ?? NewUser() : null));
    }

    private void StubFailingAssertion()
    {
        _challengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(AssertionOptionsJson));

        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(NewStoredCredential()));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<VerifyAssertionResult>(
                new Fido2VerificationException("firma inválida (mock)")));

        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(NewUser()));
    }

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE REGISTRO
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public async Task BeginRegistration_CreatesStoredChallenge_ReturnsOptions()
    {
        var sut = CreateOrchestrator();
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(NewUser()));
        _credentialStore.FindByUserIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(Array.Empty<StoredCredential>()));
        _fido2.RequestNewCredential(Arg.Any<RequestNewCredentialParams>())
            .Returns(CredentialCreateOptions.FromJson(CreateOptionsJson));

        string? capturedId = null;
        string? capturedPayload = null;
        TimeSpan? capturedTtl = null;
        _challengeStore.CreateAsync(
                Arg.Do<string>(id => capturedId = id),
                Arg.Do<string>(p => capturedPayload = p),
                Arg.Do<TimeSpan>(t => capturedTtl = t),
                Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var result = await sut.BeginRegistrationAsync("u1", AllowedOrigin);

        Assert.False(string.IsNullOrEmpty(result.ChallengeId));
        Assert.NotNull(result.Options);
        // DIDÁCTICA (A-29): la clave del store se TIPA con la ceremonia ("register:"), mientras
        // que el value opaco devuelto al cliente es el rawId (sin tag).
        Assert.Equal("register:" + result.ChallengeId, capturedId);
        Assert.Equal(TimeSpan.FromSeconds(60), capturedTtl);
        Assert.Contains("\"challenge\"", capturedPayload);
    }

    [Fact]
    public async Task BeginRegistration_MissingUser_ThrowsGeneric_NoOrphanOracle()
    {
        // DIDÁCTICA: en un flujo autenticado, un userId inexistente NO debe responder distinto
        // (sin oráculo de enumeración): se rechaza con la misma excepción genérica de origin.
        var sut = CreateOrchestrator();
        _userStore.FindByIdAsync("ghost", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(null));

        await Assert.ThrowsAsync<WebAuthnOriginNotAllowedException>(
            () => sut.BeginRegistrationAsync("ghost", AllowedOrigin));

        await _challengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BeginRegistration_BadOrigin_Throws_WithoutGeneratingChallenge()
    {
        var sut = CreateOrchestrator();

        await Assert.ThrowsAsync<WebAuthnOriginNotAllowedException>(
            () => sut.BeginRegistrationAsync("u1", EvilOrigin));

        await _challengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteRegistration_Success_StoresCredential()
    {
        var sut = CreateOrchestrator();
        _challengeStore.GetAndDeleteAsync("register:ch1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(CreateOptionsJson));
        _fido2.MakeNewCredentialAsync(Arg.Any<MakeNewCredentialParams>(), Arg.Any<CancellationToken>())
            .Returns(new RegisteredPublicKeyCredential
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = CredentialId,
                PublicKey = [7, 8, 9],
                SignCount = 0,
                AaGuid = Guid.NewGuid()
            });

        var result = await sut.CompleteRegistrationAsync(
            "u1", AllowedOrigin, "ch1", new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.True(result.Success);
        Assert.NotNull(result.Credential);
        Assert.Equal(CredentialId, result.Credential!.CredentialId);
        Assert.Equal("u1", result.Credential.UserId);
        await _credentialStore.Received(1).CreateAsync(Arg.Any<StoredCredential>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.PasskeyRegistered && e.UserId == "u1"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteRegistration_Success_ConsumesTypedChallengeKey()
    {
        // DIDÁCTICA (A-29): el consume usa la clave TIPADA ("register:"+id). Un challenge de login
        // almacenado bajo "login:…" jamás matchea este consume (fail-closed cross-ceremonia).
        var sut = CreateOrchestrator();
        string? consumedKey = null;
        _challengeStore.GetAndDeleteAsync(
                Arg.Do<string>(k => consumedKey = k), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(CreateOptionsJson));
        _fido2.MakeNewCredentialAsync(Arg.Any<MakeNewCredentialParams>(), Arg.Any<CancellationToken>())
            .Returns(new RegisteredPublicKeyCredential
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = CredentialId,
                PublicKey = [7, 8, 9],
                SignCount = 0,
                AaGuid = Guid.NewGuid()
            });

        await sut.CompleteRegistrationAsync(
            "u1", AllowedOrigin, "ch1", new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.Equal("register:ch1", consumedKey);
    }

    [Fact]
    public async Task CompleteRegistration_AttestationInvalid_ReturnsGenericFail()
    {
        var sut = CreateOrchestrator();
        _challengeStore.GetAndDeleteAsync("register:ch1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(CreateOptionsJson));
        _fido2.MakeNewCredentialAsync(Arg.Any<MakeNewCredentialParams>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException<RegisteredPublicKeyCredential>(
                new Fido2VerificationException("attestation inválida (mock)")));

        var result = await sut.CompleteRegistrationAsync(
            "u1", AllowedOrigin, "ch1", new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.False(result.Success);
        Assert.Contains("No se pudo completar", result.ErrorMessage);
        await _credentialStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<StoredCredential>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteRegistration_ReusedChallenge_ReturnsGenericFail_NoCredentialStored()
    {
        // DIDÁCTICA (S2): challenge consumido/expirado/inexistente → misma respuesta genérica.
        var sut = CreateOrchestrator();
        _challengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        var result = await sut.CompleteRegistrationAsync(
            "u1", AllowedOrigin, "stale", new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.False(result.Success);
        await _credentialStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<StoredCredential>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteRegistration_BadOrigin_ReturnsFail_WithoutConsumingChallenge()
    {
        var sut = CreateOrchestrator();

        var result = await sut.CompleteRegistrationAsync(
            "u1", EvilOrigin, "ch1", new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.False(result.Success);
        await _challengeStore.DidNotReceiveWithAnyArgs().GetAndDeleteAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RegistrationRoundTrip_BeginThenComplete_Succeeds()
    {
        // DIDÁCTICA: integración del ciclo completo — el payload real persistido en begin
        // (options.ToJson()) se consume en complete y la verificación usa las opciones originales.
        var sut = CreateOrchestrator();
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(NewUser()));
        _credentialStore.FindByUserIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(Array.Empty<StoredCredential>()));
        _fido2.RequestNewCredential(Arg.Any<RequestNewCredentialParams>())
            .Returns(CredentialCreateOptions.FromJson(CreateOptionsJson));

        string? capturedPayload = null;
        _challengeStore.CreateAsync(
                Arg.Any<string>(),
                Arg.Do<string>(p => capturedPayload = p),
                Arg.Any<TimeSpan>(),
                Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        _fido2.MakeNewCredentialAsync(Arg.Any<MakeNewCredentialParams>(), Arg.Any<CancellationToken>())
            .Returns(new RegisteredPublicKeyCredential
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = CredentialId,
                PublicKey = [7, 8, 9],
                SignCount = 0,
                AaGuid = Guid.NewGuid()
            });
        var begin = await sut.BeginRegistrationAsync("u1", AllowedOrigin);
        Assert.False(string.IsNullOrEmpty(begin.ChallengeId));
        _challengeStore.GetAndDeleteAsync("register:" + begin.ChallengeId, Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(capturedPayload));
        var complete = await sut.CompleteRegistrationAsync(
            "u1", AllowedOrigin, begin.ChallengeId, new AuthenticatorAttestationRawResponse { Id = CredentialIdBase64 });

        Assert.True(complete.Success);
    }

    // ═══════════════════════════════════════════════════════════════
    //  CEREMONIA DE ASERCIÓN (LOGIN)
    // ═══════════════════════════════════════════════════════════════

    [Fact]
    public async Task BeginLogin_WithUserId_DisclosureEnabled_QueriesCredentials()
    {
        var sut = CreateOrchestrator(discloseCredentials: true);
        _credentialStore.FindByUserIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(Array.Empty<StoredCredential>()));
        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));

        string? capturedId = null;
        _challengeStore.CreateAsync(
                Arg.Do<string>(id => capturedId = id),
                Arg.Any<string>(),
                Arg.Any<TimeSpan>(),
                Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var result = await sut.BeginLoginAsync("u1", AllowedOrigin);

        Assert.False(string.IsNullOrEmpty(result.ChallengeId));
        Assert.NotNull(result.Options);
        // DIDÁCTICA (A-29): clave tipada "login:".
        Assert.Equal("login:" + result.ChallengeId, capturedId);
        await _credentialStore.Received(1).FindByUserIdAsync("u1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BeginLogin_Default_NoCredentialDisclosure_ClosesEnumerationOracle()
    {
        // DIDÁCTICA (A-29): por defecto (DiscloseCredentialsInLoginBegin=false) el begin NO
        // consulta el store de credenciales aunque el payload traiga userId. La respuesta es
        // idéntica para usuarios existentes (enrolados o no) que para inexistentes: allowCredentials
        // vacío siempre → se cierra el oráculo de cuentas por barrido de userIds.
        var sut = CreateOrchestrator();
        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));
        _challengeStore.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var result = await sut.BeginLoginAsync("u1", AllowedOrigin);

        Assert.False(string.IsNullOrEmpty(result.ChallengeId));
        await _credentialStore.DidNotReceiveWithAnyArgs().FindByUserIdAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BeginLogin_Discoverable_DoesNotQueryCredentials()
    {
        var sut = CreateOrchestrator();
        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(AssertionOptions.FromJson(AssertionOptionsJson));
        _challengeStore.CreateAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);

        var result = await sut.BeginLoginAsync(null, AllowedOrigin);

        Assert.False(string.IsNullOrEmpty(result.ChallengeId));
        await _credentialStore.DidNotReceiveWithAnyArgs().FindByUserIdAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BeginLogin_BadOrigin_Throws_WithoutGeneratingChallenge()
    {
        var sut = CreateOrchestrator();

        await Assert.ThrowsAsync<WebAuthnOriginNotAllowedException>(
            () => sut.BeginLoginAsync(null, EvilOrigin));

        await _challengeStore.DidNotReceiveWithAnyArgs().CreateAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_Success_EmitsTokensWithAmrWebAuthn_AndOpensMfaWindow()
    {
        var sut = CreateOrchestrator(openMfaWindow: true);
        StubSuccessfulAssertion();

        UserIdentity? capturedIdentity = null;
        _tokenService.GenerateTokenPairAsync(Arg.Do<UserIdentity>(u => capturedIdentity = u), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddHours(1)));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.True(result.Success);
        Assert.Equal("at", result.Tokens!.AccessToken);
        Assert.Equal("rt", result.Tokens.RefreshToken);
        Assert.Equal("webauthn", capturedIdentity!.Claims!["amr"]);
        await _sessionStore.Received(1).CreateAsync(Arg.Any<RefreshTokenEntry>(), Arg.Any<CancellationToken>());
        await _userStore.Received(1).ResetFailedAccessCountAsync("u1", Arg.Any<CancellationToken>());
        await _mfaVerified.Received(1).SetVerifiedAsync("u1", "webauthn", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginSuccess
                                   && e.Metadata != null
                                   && e.Metadata["method"] == "webauthn"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_Success_DoesNotMutateSourceUserClaims()
    {
        // DIDÁCTICA (A-29): user.Claims puede ser una instancia compartida/cacheada del store.
        // El orquestador debe clonar el diccionario antes de inyectar amr=webauthn: si mutara en
        // sitio, el claim contaminaría tokens de otros flujos para el mismo usuario.
        var sut = CreateOrchestrator();
        var sourceClaims = new Dictionary<string, string> { ["region"] = "eu" };
        var user = NewUser();
        user = user with { Claims = sourceClaims };
        StubSuccessfulAssertion(user);
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddHours(1)));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.True(result.Success);
        Assert.False(sourceClaims.ContainsKey("amr"), "El diccionario de claims del store no debe mutar");
    }

    [Fact]
    public async Task CompleteLogin_Success_RenewsProtectionBudget()
    {
        var sut = CreateOrchestrator(enableProtection: true);
        StubSuccessfulAssertion();
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddHours(1)));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.True(result.Success);
        await _protection.Received(1).RecordSuccessAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_Success_MfaWindowDisabled_DoesNotOpenWindow()
    {
        var sut = CreateOrchestrator(openMfaWindow: false);
        StubSuccessfulAssertion();
        _tokenService.GenerateTokenPairAsync(Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>())
            .Returns(new TokenResponse("at", "rt", DateTimeOffset.UtcNow.AddHours(1)));
        _tokenService.HashRefreshToken(Arg.Any<string>()).Returns("token-hash");

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.True(result.Success);
        await _mfaVerified.DidNotReceiveWithAnyArgs().SetVerifiedAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_FailedAssertion_WithoutProtection_NoTokens_EmitsFailureEvent()
    {
        var sut = CreateOrchestrator(enableProtection: false);
        StubFailingAssertion();

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.False(result.Success);
        Assert.False(result.LockedOut);
        Assert.Equal("Autenticación fallida.", result.ErrorMessage);
        await _tokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.PasskeyVerificationFailed && e.UserId == "u1"),
            Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceive().DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginSuccess),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_FailedAssertion_WithLockout_ReturnsLocked_EmitsAccountLockedOut()
    {
        // DIDÁCTICA (S1): el sujeto se resuelve vía la credencial (fix A-17), el fallo consume el
        // presupuesto del scope Passkey y el lockout se traduce en la respuesta estándar de bloqueo.
        var sut = CreateOrchestrator(enableProtection: true);
        StubFailingAssertion();
        _protection.RecordFailureAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.CompletedTask);
        _protection.CheckAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(
                Allowed: false,
                RemainingAttempts: 0,
                LockEnd: DateTimeOffset.UtcNow.AddMinutes(10),
                EscalationLevel: 1)));

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.False(result.Success);
        Assert.True(result.LockedOut);
        await _protection.Received(1).RecordFailureAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.AccountLockedOut
                                   && e.UserId == "u1"
                                   && e.Metadata != null
                                   && e.Metadata["scope"] == "passkey"),
            Arg.Any<CancellationToken>());
        await _tokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_FailedAssertion_WithSubject_NoLockYet_EmitsFailureEvent()
    {
        // DIDÁCTICA: el lockout solo se activa cuando CheckAsync dice que ya no se permite;
        // mientras haya presupuesto se responde el error genérico de autenticación.
        var sut = CreateOrchestrator(enableProtection: true);
        StubFailingAssertion();
        _protection.CheckAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult(new AccountProtectionResult(
                Allowed: true,
                RemainingAttempts: 3,
                LockEnd: null,
                EscalationLevel: 0)));

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.False(result.Success);
        Assert.False(result.LockedOut);
        await _protection.Received(1).RecordFailureAsync(AccountProtectionScope.Passkey, "u1", Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.PasskeyVerificationFailed && e.UserId == "u1"),
            Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceive().DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginSuccess),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_ReusedChallenge_ReturnsGenericFail_NoTokens()
    {
        // DIDÁCTICA (S2): el challenge se consume antes de la verificación — un replay obtiene
        // la misma respuesta genérica y jamás llega a Fido2 ni a la emisión de tokens.
        var sut = CreateOrchestrator();
        _challengeStore.GetAndDeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<string?>(null));

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "stale", NewAssertionResponse());

        Assert.False(result.Success);
        await _fido2.DidNotReceiveWithAnyArgs().MakeAssertionAsync(
            Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
        await _tokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_BadOrigin_ReturnsFail_WithoutConsumingChallenge()
    {
        var sut = CreateOrchestrator();

        var result = await sut.CompleteLoginAsync(EvilOrigin, "ch1", NewAssertionResponse());

        Assert.False(result.Success);
        await _challengeStore.DidNotReceiveWithAnyArgs().GetAndDeleteAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _fido2.DidNotReceiveWithAnyArgs().MakeAssertionAsync(
            Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteLogin_OrphanCredential_SignatureValidButNoUser_ReturnsGenericFail()
    {
        // DIDÁCTICA: la firma es válida pero el sujeto no se puede resolver (usuario huérfano).
        // No hay tokens que emitir: se responde genérico y se audita sin filtrar el motivo.
        var sut = CreateOrchestrator();
        StubSuccessfulAssertion(resolveUser: false);

        var result = await sut.CompleteLoginAsync(AllowedOrigin, "ch1", NewAssertionResponse());

        Assert.False(result.Success);
        Assert.False(result.LockedOut);
        await _tokenService.DidNotReceiveWithAnyArgs().GenerateTokenPairAsync(
            Arg.Any<UserIdentity>(), Arg.Any<CancellationToken>());
        await _eventDispatcher.DidNotReceive().DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.LoginSuccess),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EmptyOrigins_FailClosed_AllCeremoniesRejected()
    {
        // DIDÁCTICA: sin origins configurados el orquestador no puede garantizar la propiedad
        // central de WebAuthn (anti-phishing) → rechaza TODO (fail-closed).
        var sut = CreateOrchestrator(origins: []);

        await Assert.ThrowsAsync<WebAuthnOriginNotAllowedException>(
            () => sut.BeginRegistrationAsync("u1", "https://any.example.com"));
        await Assert.ThrowsAsync<WebAuthnOriginNotAllowedException>(
            () => sut.BeginLoginAsync(null, "https://any.example.com"));

        var reg = await sut.CompleteRegistrationAsync(
            "u1", "https://any.example.com", "ch1", new AuthenticatorAttestationRawResponse { Id = "" });
        var login = await sut.CompleteLoginAsync("https://any.example.com", "ch1", NewAssertionResponse());

        Assert.False(reg.Success);
        Assert.False(login.Success);
    }
}
