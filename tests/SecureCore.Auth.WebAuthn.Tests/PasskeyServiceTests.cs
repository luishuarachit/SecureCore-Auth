using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.Core;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.WebAuthn;

namespace SecureCore.Auth.WebAuthn.Tests;

/// <summary>
/// Tests para PasskeyService — ceremonias WebAuthn con mocks de IFido2.
/// </summary>
public class PasskeyServiceTests
{
    private readonly PasskeyService _passkeyService;
    private readonly IFido2 _fido2;
    private readonly ICredentialStore _credentialStore;
    private readonly IUserStore _userStore;
    private readonly IAuthEventDispatcher _eventDispatcher;

    public PasskeyServiceTests()
    {
        _fido2 = Substitute.For<IFido2>();
        _credentialStore = Substitute.For<ICredentialStore>();
        _userStore = Substitute.For<IUserStore>();
        _eventDispatcher = Substitute.For<IAuthEventDispatcher>();

        var options = Options.Create(new WebAuthnOptions
        {
            RelyingPartyName = "Test RP",
            RelyingPartyId = "test.example.com",
            UserVerification = "preferred",
            RequireResidentKey = false,
            Origins = ["https://test.example.com"]
        });

        _passkeyService = new PasskeyService(
            _fido2, _credentialStore, _userStore, _eventDispatcher,
            options, NullLogger<PasskeyService>.Instance);
    }

    [Fact]
    public async Task BeginRegistrationAsync_CallsFido2RequestNewCredential()
    {
        // Arrange
        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            SecurityStamp = "s",
            PasswordHash = "h"
        };

        _credentialStore.FindByUserIdAsync("u1")
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(
                new List<StoredCredential>().AsReadOnly()));

        // CredentialCreateOptions es sealed con required members;
        // Verificamos que se llamó a IFido2.RequestNewCredential correctamente
        RequestNewCredentialParams? capturedParams = null;
        _fido2.RequestNewCredential(Arg.Do<RequestNewCredentialParams>(p => capturedParams = p))
            .Returns(x => throw new InvalidOperationException("Test: verifying call was made"));

        // Act — esperamos la excepción controlada
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _passkeyService.BeginRegistrationAsync(user));

        // Assert — se llamó a IFido2 con los parámetros correctos
        Assert.NotNull(capturedParams);
        Assert.Equal("test@example.com", capturedParams.User.Name);
        Assert.Equal(AttestationConveyancePreference.None, capturedParams.AttestationPreference);
    }

    [Fact]
    public async Task BeginRegistrationAsync_IncludesExistingCredentials()
    {
        // Arrange
        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            SecurityStamp = "s",
            PasswordHash = "h"
        };

        var existingCreds = new List<StoredCredential>
        {
            new() { CredentialId = new byte[] { 1, 2, 3 }, UserId = "u1", PublicKey = new byte[] { 4 }, SignatureCount = 0 }
        };

        _credentialStore.FindByUserIdAsync("u1")
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(existingCreds.AsReadOnly()));

        RequestNewCredentialParams? capturedParams = null;
        _fido2.RequestNewCredential(Arg.Do<RequestNewCredentialParams>(p => capturedParams = p))
            .Returns(x => throw new InvalidOperationException("Test: verifying call was made"));

        // Act
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _passkeyService.BeginRegistrationAsync(user));

        // Assert — verifica que se pasaron las credenciales existentes como exclusión
        Assert.NotNull(capturedParams);
        Assert.NotNull(capturedParams.ExcludeCredentials);
        Assert.Single(capturedParams.ExcludeCredentials);
    }

    [Fact]
    public async Task BeginRegistrationAsync_ThrowsOnNullUser()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _passkeyService.BeginRegistrationAsync(null!));
    }

    [Fact]
    public async Task BeginAssertionAsync_WithUserId_RestrictsCredentials()
    {
        // Arrange
        var userCreds = new List<StoredCredential>
        {
            new() { CredentialId = new byte[] { 1, 2 }, UserId = "u1", PublicKey = new byte[] { 3 }, SignatureCount = 0 }
        };

        _credentialStore.FindByUserIdAsync("u1")
            .Returns(ValueTask.FromResult<IReadOnlyList<StoredCredential>>(userCreds.AsReadOnly()));

        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(Substitute.For<AssertionOptions>());

        // Act
        var result = await _passkeyService.BeginAssertionAsync("u1");

        // Assert
        Assert.NotNull(result);
        _fido2.Received(1).GetAssertionOptions(
            Arg.Is<GetAssertionOptionsParams>(p =>
                p.AllowedCredentials != null && p.AllowedCredentials.Count > 0));
    }

    [Fact]
    public async Task BeginAssertionAsync_WithoutUserId_AllowsDiscoverable()
    {
        // Arrange — no userId = Discoverable Credentials
        _fido2.GetAssertionOptions(Arg.Any<GetAssertionOptionsParams>())
            .Returns(Substitute.For<AssertionOptions>());

        // Act
        var result = await _passkeyService.BeginAssertionAsync(null);

        // Assert
        Assert.NotNull(result);
        _fido2.Received(1).GetAssertionOptions(
            Arg.Is<GetAssertionOptionsParams>(p =>
                p.AllowedCredentials == null || p.AllowedCredentials.Count == 0));
    }

    // ─────────────────────────────────────────────────────
    //  CompleteAssertionDetailedAsync (A-17)
    // ─────────────────────────────────────────────────────

    private static AuthenticatorAssertionRawResponse CreateAssertionResponse(string id = "c2lkZQ==") =>
        new() { Id = id };

    private static StoredCredential CreateStoredCredential(string userId = "u1") =>
        new()
        {
            CredentialId = new byte[] { 1, 2, 3 },
            UserId = userId,
            PublicKey = new byte[] { 4 },
            SignatureCount = 0
        };

    [Fact]
    public async Task CompleteAssertionDetailedAsync_CredentialNotFound_ReturnsNotFound()
    {
        // Arrange
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(null));

        // Act
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());

        // Assert — expone distinción credencial no encontrada vs firma inválida
        Assert.False(result.CredentialFound);
        Assert.False(result.SignatureValid);
        Assert.Null(result.User);
        _fido2.DidNotReceive().MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteAssertionDetailedAsync_MalformedCredentialId_ReturnsNotFound_NotThrows()
    {
        // Arrange — Id no Base64 válido (regresión Nº4: antes propagaba FormatException → 500)

        // Act — no debe lanzar, sino reportar credencial no encontrada con el contrato del método
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse("!!!not-base64!!!"),
            Substitute.For<AssertionOptions>());

        // Assert
        Assert.False(result.CredentialFound);
        Assert.False(result.SignatureValid);
        Assert.Null(result.User);
        _credentialStore.DidNotReceive().FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>());
        _fido2.DidNotReceive().MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteAssertionDetailedAsync_NullCredentialId_ReturnsNotFound_NotThrows()
    {
        // Arrange — Id null (ArgumentNullException en Convert.FromBase64String);
        // el guard de decodificación debe tratarlo como credencial no encontrada

        // Act
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse(null!),
            Substitute.For<AssertionOptions>());

        // Assert
        Assert.False(result.CredentialFound);
        _fido2.DidNotReceive().MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteAssertionDetailedAsync_InvalidSignature_ExposesSubject()
    {
        // Arrange
        var credential = CreateStoredCredential();
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(credential));

        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            SecurityStamp = "s",
            PasswordHash = "h"
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns((Func<CallInfo, Task<VerifyAssertionResult>>)(_ => throw new Fido2VerificationException("firma inválida")));

        // Act
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());

        // Assert — sujeto resuelto incluso en el ramo de fallo (lockout por cuenta)
        Assert.True(result.CredentialFound);
        Assert.False(result.SignatureValid);
        Assert.Same(user, result.User);
    }

    [Fact]
    public async Task CompleteAssertionDetailedAsync_Success_ReturnsUserAndUpdatesCounter()
    {
        // Arrange
        var credential = CreateStoredCredential();
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(credential));

        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            SecurityStamp = "s",
            PasswordHash = "h"
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult { SignCount = 7 });

        // Act
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());

        // Assert
        Assert.True(result.SignatureValid);
        Assert.Same(user, result.User);

        // Anti-clonación: el contador de la credencial almacenada se actualiza con el nuevo valor
        await _credentialStore.Received(1).UpdateSignatureCountAsync(
            Arg.Any<byte[]>(), 7u, Arg.Any<CancellationToken>());
        await _eventDispatcher.Received(1).DispatchAsync(
            Arg.Is<AuthEvent>(e => e.EventType == AuthEventType.PasskeyLoginSuccess),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompleteAssertionDetailedAsync_SuccessButUserMissing_ReportsSignatureValidWithNullUser()
    {
        // Arrange
        var credential = CreateStoredCredential();
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(credential));
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(null));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult { SignCount = 1 });

        // Act
        var result = await _passkeyService.CompleteAssertionDetailedAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());

        // Assert — la firma era válida pero la cuenta ya no existe
        Assert.True(result.CredentialFound);
        Assert.True(result.SignatureValid);
        Assert.Null(result.User);
    }

#pragma warning disable CS0618 // Testeo deliberado del wrapper obsoleto
    [Fact]
    public async Task CompleteAssertionAsync_ObsoleteWrapper_ReturnsUserOnSuccess()
    {
        // Arrange
        var credential = CreateStoredCredential();
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(credential));

        var user = new UserIdentity
        {
            Id = "u1",
            Email = "test@example.com",
            SecurityStamp = "s",
            PasswordHash = "h"
        };
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(user));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns(new VerifyAssertionResult { SignCount = 1 });

        // Act
        var result = await _passkeyService.CompleteAssertionAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());

        // Assert — el wrapper conserva el contrato anterior (usuario autenticado o null)
        Assert.Same(user, result);
    }
#pragma warning restore CS0618

    [Fact]
    public async Task CompleteAssertionAsync_ObsoleteWrapper_ReturnsNullOnInvalidSignature()
    {
        // Arrange
        var credential = CreateStoredCredential();
        _credentialStore.FindByCredentialIdAsync(Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<StoredCredential?>(credential));
        _userStore.FindByIdAsync("u1", Arg.Any<CancellationToken>())
            .Returns(ValueTask.FromResult<UserIdentity?>(new UserIdentity
            {
                Id = "u1",
                Email = "test@example.com",
                SecurityStamp = "s",
                PasswordHash = "h"
            }));

        _fido2.MakeAssertionAsync(Arg.Any<MakeAssertionParams>(), Arg.Any<CancellationToken>())
            .Returns((Func<CallInfo, Task<VerifyAssertionResult>>)(_ => throw new Fido2VerificationException("firma inválida")));

        // Act
#pragma warning disable CS0618 // Testeo deliberado del wrapper obsoleto
        var result = await _passkeyService.CompleteAssertionAsync(
            CreateAssertionResponse(),
            Substitute.For<AssertionOptions>());
#pragma warning restore CS0618

        // Assert — el contrato anterior no distingue credencial no encontrada de firma inválida
        Assert.Null(result);
    }
}
