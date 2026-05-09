using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.OAuth.Services;

/// <summary>
/// El Orquestador de OAuth es el "director de orquesta" para las autenticaciones externas.
/// Su misión es recibir la identidad validada de un proveedor (Google, GitHub, etc.) 
/// y transformarla en una sesión segura dentro de nuestro sistema.
/// </summary>
public class OAuthOrchestrator(
    IUserStore userStore,
    IExternalTokenStore? externalTokenStore,
    ISessionStore sessionStore,
    ITokenService tokenService,
    LockoutManager lockoutManager,
    IAuthEventDispatcher eventDispatcher,
    IOptions<SecureAuthOptions> options,
    IEnumerable<IOAuthProviderValidator> validators)
{
    private readonly SecureAuthOptions _options = options.Value;

    /// <summary>
    /// Procesa el inicio de sesión o registro de un usuario mediante OAuth.
    /// Soporta dos flujos principales:
    /// 1. Flujo A (Servidor): Se recibe un 'code' que se intercambia por tokens en el backend.
    /// 2. Flujo B (Frontend): El frontend ya tiene un 'id_token' y nosotros solo lo validamos.
    /// </summary>
    public async Task<OAuthSignInResult> SignInOrRegisterAsync(
        string provider,
        OAuthValidationRequest request,
        OAuthSignInOptions signInOptions,
        CancellationToken ct = default)
    {
        var validator = validators.FirstOrDefault(v => 
            v.ProviderName.Equals(provider, StringComparison.OrdinalIgnoreCase));

        if (validator is null)
            return OAuthSignInResult.ProviderNotConfigured(provider);

        OAuthIdentityResult identity;

        // Flujo B (Frontend Token)
        if (!string.IsNullOrEmpty(request.IdToken))
        {
            identity = await validator.ValidateIdTokenAsync(request.IdToken, null, ct);
        }
        // Flujo A (Authorization Code)
        else if (!string.IsNullOrEmpty(request.Code) && !string.IsNullOrEmpty(request.RedirectUri))
        {
            // Para el flujo A, el orquestador llamará a ValidateIdToken internamente si hay id_token.
            // La lógica de verificar el nonce se delega al validador durante ExchangeCodeAsync.
            identity = await validator.ExchangeCodeAsync(request.Code, request.RedirectUri, request.Nonce, ct);
        }
        else
        {
            return OAuthSignInResult.Failure("Invalid OAuth validation request. Code or IdToken must be provided.");
        }

        if (!identity.Succeeded || identity.ProviderKey is null)
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.LoginFailed,
                UserId = "Unknown",
                TimestampUtc = DateTimeOffset.UtcNow.UtcDateTime,
                Metadata = new Dictionary<string, string> { { "Provider", provider }, { "Reason", identity.ErrorMessage ?? "Unknown" } }
            }, ct);
            return OAuthSignInResult.Failure(identity.ErrorMessage ?? "OAuth validation failed");
        }

        var user = await userStore.FindByExternalProviderAsync(provider, identity.ProviderKey, ct);
        var isNewUser = false;

        if (user is null)
        {
            if (!signInOptions.AllowImplicitRegistration || signInOptions.UserFactoryType is null)
                return OAuthSignInResult.UserNotFoundResult();

            return OAuthSignInResult.Failure("Implicit registration is enabled but IExternalUserFactory is not registered. Register a factory via AddExternalUserFactory<T>().");
        }

        if (lockoutManager.IsLockedOut(user))
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.AccountLockedOut,
                UserId = user.Id,
                TimestampUtc = DateTimeOffset.UtcNow.UtcDateTime,
                Metadata = new Dictionary<string, string> { { "Provider", provider } }
            }, ct);
            return OAuthSignInResult.LockedOutResult();
        }

        if (signInOptions.PersistProviderTokens && externalTokenStore is not null && identity.AccessToken is not null)
        {
            await externalTokenStore.SaveAsync(new ExternalTokenEntry
            {
                UserId = user.Id,
                Provider = provider,
                ProviderKey = identity.ProviderKey,
                AccessToken = identity.AccessToken,
                RefreshToken = identity.RefreshToken,
                IdToken = identity.IdToken,
                Scopes = identity.Scopes ?? [],
                ExpiresAt = identity.TokenExpiresAt ?? DateTimeOffset.UtcNow.AddHours(1)
            }, ct);
        }

        // Emit tokens
        var tokens = await tokenService.GenerateTokenPairAsync(user, ct);
        
        var tokenHash = tokenService.HashRefreshToken(tokens.RefreshToken);
        var refreshEntry = new RefreshTokenEntry
        {
            TokenHash = tokenHash,
            FamilyId = Guid.NewGuid().ToString(),
            UserId = user.Id,
            ExpiresAtUtc = DateTime.UtcNow.Add(_options.RefreshTokenLifetime)
        };

        await sessionStore.CreateAsync(refreshEntry, ct);

        await eventDispatcher.DispatchAsync(new AuthEvent
        {
            EventType = AuthEventType.LoginSuccess,
            UserId = user.Id,
            TimestampUtc = DateTimeOffset.UtcNow.UtcDateTime,
            Metadata = new Dictionary<string, string> { { "Provider", provider } }
        }, ct);

        return OAuthSignInResult.Success(tokens, user.Id, isNewUser);
    }
}
