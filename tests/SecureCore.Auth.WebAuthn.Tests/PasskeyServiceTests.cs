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
            Id = "u1", Email = "test@example.com",
            SecurityStamp = "s", PasswordHash = "h"
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
            Id = "u1", Email = "test@example.com",
            SecurityStamp = "s", PasswordHash = "h"
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
}
