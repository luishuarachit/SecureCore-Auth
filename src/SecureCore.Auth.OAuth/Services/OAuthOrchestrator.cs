using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
    IServiceProvider serviceProvider,
    IOptions<SecureAuthOptions> options,
    IEnumerable<IOAuthProviderValidator> validators,
    ILogger<OAuthOrchestrator> logger)
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
            return OAuthSignInResult.Failure(
                "Invalid OAuth validation request. Code or IdToken must be provided.",
                "oauth_invalid_request");
        }

        if (!identity.Succeeded || identity.ProviderKey is null)
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.LoginFailed,
                UserId = "Unknown",
                TimestampUtc = DateTime.UtcNow,
                Metadata = new Dictionary<string, string> { { "Provider", provider }, { "Reason", identity.ErrorMessage ?? "Unknown" } }
            }, ct);
            return OAuthSignInResult.Failure(identity.ErrorMessage ?? "OAuth validation failed", "oauth_validation_failed");
        }

        var user = await userStore.FindByExternalProviderAsync(provider, identity.ProviderKey, ct);
        var isNewUser = false;

        if (user is null)
        {
            // DIDÁCTICA: El usuario no existe en nuestro sistema pero el proveedor externo
            // nos devolvió una identidad válida. Si AllowImplicitRegistration está activo,
            // podemos crear el usuario automáticamente delegando en IExternalUserFactory.
            //
            // IExternalUserFactory es el punto de extensión donde la aplicación consumidora
            // decide cómo crear un usuario (qué tabla, qué datos extra guardar, etc.)
            // a partir de la identidad validada por el proveedor OAuth.
            //
            // La aplicación debe registrar su factory en DI:
            //   services.AddScoped<IExternalUserFactory, MiUserFactory>();
            if (signInOptions.AllowImplicitRegistration)
            {
                // DIDÁCTICA: Resolvemos IExternalUserFactory desde el ServiceProvider en lugar
                // de inyectarlo directamente, porque es un servicio OPCIONAL que la aplicación
                // consumidora puede o no haber registrado. Al usar GetService (no GetRequiredService),
                // obtenemos null si no está registrado, sin lanzar excepción de DI.
                var userFactory = serviceProvider.GetService<IExternalUserFactory>();
                if (userFactory is null)
                {
                    return OAuthSignInResult.Failure(
                        "AllowImplicitRegistration está habilitado pero IExternalUserFactory " +
                        "no está registrado. Registre una implementación vía: " +
                        "services.AddScoped<IExternalUserFactory, TuFactory>().",
                        "oauth_factory_not_registered");
                }

                user = await userFactory.CreateFromOAuthAsync(identity, provider, ct);
                isNewUser = true;

                logger.LogInformation(
                    "Nuevo usuario creado automáticamente desde {Provider}: {Email}",
                    provider, identity.Email);
            }
            else
            {
                // DIDÁCTICA: AllowImplicitRegistration=false (valor por defecto por seguridad).
                // El usuario debe existir previamente en el sistema (registro tradicional).
                // Esto evita que cualquiera que se autentique con Google/GitHub cree
                // una cuenta automáticamente sin pasar por el flujo de registro.
                return OAuthSignInResult.UserNotFoundResult();
            }
        }

        if (lockoutManager.IsLockedOut(user))
        {
            await eventDispatcher.DispatchAsync(new AuthEvent
            {
                EventType = AuthEventType.AccountLockedOut,
                UserId = user.Id,
                TimestampUtc = DateTime.UtcNow,
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
            TimestampUtc = DateTime.UtcNow,
            Metadata = new Dictionary<string, string> { { "Provider", provider } }
        }, ct);

        return OAuthSignInResult.Success(tokens, user.Id, isNewUser);
    }
}
