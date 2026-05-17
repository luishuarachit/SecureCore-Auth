# Technical Reference: SecureCore Auth Framework

This documentation provides a detailed technical specification of the members, interfaces, and internal mechanisms of the SecureCore Auth framework, aimed at software engineers and architects.

---

## 1. Architecture and Design Principles

SecureCore Auth is designed under a storage-agnostic architecture and decoupled from the UI framework.

- **Dependency Inversion**: Core logic depends on interfaces (`IUserStore`, `ISessionStore`) that must be implemented by the infrastructure layer.
- **Orchestration**: Identity flow is managed through a central orchestrator that coordinates cryptographic validations, state management, and event dispatching.
- **Security by Design**: Native implementation of mitigations against enumeration attacks (constant-time verification) and token rotation (RTR).

---

## 2. Configuration and Options

The framework uses the .NET `IOptions<T>` pattern and allows for startup validation (`ValidateOnStart`).

### 2.1. JwtOptions
Manages parameters for the Bearer authentication scheme using JWT.

| Property | Type | Description | Requirement/Validation |
| :--- | :--- | :--- | :--- |
| `Issuer` | `string` | Token issuer identifier. | Required |
| `Audience` | `string` | Token audience identifier. | Required |
| `SigningKey` | `string?` | Symmetric key for HS256 signing. | Minimum 32 chars. Only if Algorithm=HS256. |
| `PrivateKey` | `string?` | RSA/ECDSA private key in PEM format. | Required for RS256 or ES256. |
| `PublicKey` | `string?` | RSA/ECDSA public key in PEM format. | Required for RS256 or ES256. |
| `Algorithm` | `string` | Signing algorithm (Default: `RS256`). | Values: HS256, RS256, ES256, ES384, ES512 |

> **SECURITY NOTE**: **RS256 or ES256** is recommended for production. These algorithms use asymmetric cryptography:
> - **HS256 (symmetric)**: Same key signs and validates. If leaked, anyone can forge tokens.
> - **RS256/ES256 (asymmetric)**: Uses private key to sign, public key to validate. Public key can be distributed; private key stays secure on the server.

### 2.2. SecureAuthOptions
Defines session lifecycle parameters and lockout policies.

| Property | Type | Default Value | Validation |
| :--- | :--- | :--- | :--- |
| `AccessTokenLifetime` | `TimeSpan` | 15 min | Required |
| `RefreshTokenLifetime` | `TimeSpan` | 7 days | Required |
| `GracePeriodSeconds` | `int` | 30 sec | [0, 300] |
| `MaxFailedAttempts` | `int` | 5 | [1, 100] |
| `LockoutDurations` | `TimeSpan[]` | [1m, 5m, 15m, 1h] | Required |
| `ClockSkew` | `TimeSpan` | 30 sec | Required |
| `SecurityStampCacheDuration` | `TimeSpan` | 1 min | Required |
| `LoginRateLimitMaxAttempts` | `int` | 10 | [1, 1000] |
| `LoginRateLimitWindow` | `TimeSpan` | 1 min | Required |

#### AccessTokenLifetime Configuration Guide

The Access Token lifetime is a balance between security and user experience:

| Scenario | AccessTokenLifetime | RefreshTokenLifetime | Justification |
| :--- | :--- | :--- | :--- |
| **Sensitive apps** (finance, admin) | 5-15 min | 24h | Minimal attack window if token is stolen. Frequent refresh. |
| **Normal apps** (default) | 15-30 min | 7 days | Balance between UX and security. |
| **Internal APIs** | 1+ hour | 7 days | Only with robust firewall. **Not recommended** for direct internet exposure. |

**Recommendation for sensitive operations**: For critical tasks (payments, data deletion), implement additional verification such as explicit re-authentication or very short-lived tokens specific to those operations.

### 2.3. Argon2Options
Configuration for password hashing using Argon2id.

| Property | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `MemorySize` | `int` | 65536 | Memory in KB (64MB). |
| `Iterations` | `int` | 3 | Passes over the memory block. |
| `Parallelism` | `int` | 4 | Number of simultaneous threads. |
| `HashSize` | `int` | 32 | Resulting hash length in bytes. |

> **PERFORMANCE NOTE - Async Methods**: IPasswordHasher includes async versions of the main methods:
> - `HashPasswordAsync()` - Async version of HashPassword
> - `VerifyPasswordAsync()` - Async version of VerifyPassword
> - `VerifyDummyPasswordAsync()` - Async version of VerifyDummyPassword
>
> These methods use `Task.Run` to execute Argon2's CPU-intensive operations on the thread pool, avoiding blocking the HTTP request thread.
>
> **WHEN TO USE ASYNC METHODS**:
> - **Low load** (few simultaneous authentications): Use sync methods
> - **High load** (many simultaneous authentications): Use async methods to avoid exhausting the thread pool
> - **Single-instance** with moderate load: Sync methods are sufficient
> - **High volume** of simultaneous logins: Async methods + rate limiting

### 2.4. PasswordResetOptions
Defines the account recovery policy.

| Property | Type | Default Value | Validation |
| :--- | :--- | :--- | :--- |
| `TokenLifetimeMinutes` | `int` | 15 | [1, 1440] |
| `TokenSizeBytes` | `int` | 32 | [16, 64] |
| `MaxRequestsPerHour` | `int` | 3 | [0, 100] |

### 2.5. MfaOptions
Defines the Multi-Factor Authentication policy.

| Property | Type | Default Value | Validation |
| :--- | :--- | :--- | :--- |
| `Enabled` | `bool` | false | Enable/disable MFA globally |
| `RequiredByDefault` | `bool` | false | MFA required for all users |
| `AllowedMethods` | `List<string>` | ["totp", "email"] | Allowed MFA methods |
| `AllowUserEnrollment` | `bool` | true | Allow voluntary MFA enrollment |
| `AllowUserDisable` | `bool` | true | Allow users to disable MFA |
| `EnableRecoveryCodes` | `bool` | false | **NOT RECOMMENDED** - reduces security |
| `RecoveryCodeCount` | `int` | 10 | [1, 20] - number of recovery codes |
| `TotpIssuer` | `string` | "AuthCore" | Issuer shown in QR code |
| `EmailCodeLifetimeMinutes` | `int` | 5 | [1, 30] - email code expiry |
| `EmailCodeLength` | `int` | 6 | [6, 8] - email code digits |
| `MaxVerificationAttempts` | `int` | 5 | [3, 10] - max failed MFA attempts |
| `CodeRetryWindowMinutes` | `int` | 3 | [1, 15] - retry window |
| `MfaSessionTokenMinutes` | `int` | 5 | [1, 15] - MFA session token expiry |
| `EncryptionKey` | `string` | - | **REQUIRED** - 64-char hex key for TOTP encryption |

> **SECURITY NOTE**: Recovery codes reduce MFA security. If enabled, they must have HIGH ENTROPY (minimum 32 random characters) to resist brute-force attacks if the database is compromised.

---

## 3. Infrastructure Interfaces (SPI)

To integrate the framework, persistence interfaces must be implemented.

### 3.1. IUserStore
Defines access to identity entities.

- `ValueTask<UserIdentity?> FindByIdAsync(string userId, CancellationToken ct)`
- `ValueTask<UserIdentity?> FindByEmailAsync(string email, CancellationToken ct)`
- `Task UpdateSecurityStampAsync(string userId, string newStamp, CancellationToken ct)`
- `Task<int> IncrementFailedAccessCountAsync(string userId, CancellationToken ct)`

**MFA Methods**:
- `Task UpdateMfaEnrollmentAsync(string userId, MfaEnrollmentStatus status, string? preferredMethod, CancellationToken ct)`
- `Task SetTotpSecretAsync(string userId, string encryptedSecret, CancellationToken ct)`
- `Task SetRecoveryCodesAsync(string userId, List<string> codeHashes, CancellationToken ct)`
- `Task<int> IncrementMfaFailedAttemptsAsync(string userId, CancellationToken ct)`
- `Task ResetMfaFailedAttemptsAsync(string userId, CancellationToken ct)`

### 3.2. ISessionStore
Manages persistence of Refresh Tokens for RTR (Refresh Token Rotation).

- `Task CreateAsync(RefreshTokenEntry entry, CancellationToken ct)`
- `ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task RevokeAsync(string tokenHash, string? replacedByHash, CancellationToken ct)`
- `Task RevokeByFamilyAsync(string familyId, CancellationToken ct)`

### 3.3. IPasswordResetStore
Persistence for single-use tokens.
- `Task StoreAsync(PasswordResetEntry entry, CancellationToken ct)`
- `ValueTask<PasswordResetEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task MarkAsUsedAsync(string tokenHash, CancellationToken ct)`
- `ValueTask<int> CountRecentRequestsAsync(string userId, DateTime since, CancellationToken ct)`

### 3.4. IResetTokenMailer
Interface for recovery notification dispatch.
- `Task SendResetEmailAsync(string email, string rawToken, CancellationToken ct)`

---

## 4. Core Services (API)

### 4.1. IdentityOrchestrator
Coordinates the authentication flow. It contains no cryptographic logic but orchestrates each step.

- **`SignInWithPasswordAsync(email, password)`**: Executes lookup, lockout validation, constant-time hashing, and token generation.
  - Implements `VerifyDummyPassword` to mitigate timing attacks if the user is not found.
- **`SignInExternalAsync(provider, providerKey)`**: Processes login for users authenticated via OAuth (Google, GitHub, etc.). Links external identity with a local session.

### 4.2. ITokenService (JwtTokenService)
Responsible for token generation and validation.

- **`GenerateTokenPairAsync(UserIdentity user)`**: Generates Access Token (JWT) and Refresh Token (Base64Url).
- **`HashRefreshToken(string token)`**: Generates SHA256 hash for secure storage of session tokens.

### 4.3. PasswordResetOrchestrator
Manages the reset lifecycle.
- **`RequestPasswordResetAsync(email)`**: Validates existence (constant-time), applies rate limiting, generates opaque token, and dispatches email.
- **`ConfirmPasswordResetAsync(token, newPassword)`**: Validates token hash, updates credentials, and triggers `RevokeAllSessionsAsync`.

### 4.4. LoginRateLimiter
Protects the login endpoint against distributed brute force attacks by IP.

- **Default config**: 10 attempts per minute per IP address.
- **Purpose**: Complements per-account lockout (`LockoutManager`) by protecting against attackers trying many different accounts from the same IP.
- **Behavior**: Returns HTTP 429 Too Many Requests when the limit is exceeded.

#### Configurable Options

The implementer can adjust the behavior via `SecureAuthOptions`:

| Property | Default | Description |
| :--- | :--- | :--- |
| `LoginRateLimitMaxAttempts` | 10 | Maximum attempts allowed in the window |
| `LoginRateLimitWindow` | 1 min | Time window for counting attempts |

**Configuration examples:**

```csharp
// Strict security (5 attempts/min)
options.LoginRateLimitMaxAttempts = 5;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);

// Balance (default: 10 attempts/min)
options.LoginRateLimitMaxAttempts = 10;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);

// Permissive (20 attempts/min) - only for internal APIs
options.LoginRateLimitMaxAttempts = 20;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);
```

---

> **NOTE**: AuthCore's security system operates in two layers:
> 1. **Per-account protection**: `LockoutManager` locks individual accounts after multiple failed attempts (exponential lockout).
> 2. **Global IP protection**: `LoginRateLimiter` limits aggregate attempts from any IP, preventing distributed attacks.

### 4.5. MFA Services (Multi-Factor Authentication)

SecureCore Auth implements native MFA support without external dependencies.

**Core Interfaces:**

| Interface | Purpose |
| :--- | :--- |
| `ITotpService` | RFC 6238 TOTP implementation (6/8 digit codes, 30s window) |
| `IEmailMfaService` | Email verification code delivery |
| `IMfaService` | Main MFA orchestration (enrollment, verification) |
| `IMfaSessionStore` | MFA session token management (JWT-based, 5-min expiry) |
| `IEmailService` | Generic email sending (replaces IResetTokenMailer) |

**Security Implementation:**
- **TOTP**: Native RFC 6238 implementation using HMAC-SHA1
- **Encryption**: AES-256-GCM for TOTP secrets (requires 64-char hex key)
- **Session Tokens**: JWT-based (5-min expiry, Auth0/Stytch industry standard)
- **Rate Limiting**: Configurable max attempts (default: 5) with 3-min lockout window

**Configuration:**
```csharp
builder.Services.AddSecureAuth(options =>
{
    options.Auth.Mfa.Enabled = true;
    options.Auth.Mfa.EncryptionKey = "..."; // 64-char hex required
})
.AddPasswordAuthentication()
.AddMfa();
```

**Registration:**
```csharp
// After successful password login with MFA enabled:
// 1. Returns RequiresTwoFactor + mfaSessionToken
// 2. User provides TOTP code or email code
// 3. Verify via CompleteMfaLoginAsync(mfaSessionToken, code)
// 4. Returns access tokens with "amr": "mfa" claim
```

### 4.6. ExternalTokenStore and OAuth Token Persistence

**A-07: NullExternalTokenStore Warning**

When `PersistProviderTokens = true` but no custom `IExternalTokenStore` is registered, AuthCore will emit a warning in the logs indicating that OAuth tokens will not be persisted.

```csharp
// If you need to store provider access tokens (e.g., for Microsoft Graph API calls):
public class MyExternalTokenStore : IExternalTokenStore
{
    public async Task SaveAsync(ExternalTokenEntry entry, CancellationToken ct) { ... }
    public async ValueTask<ExternalTokenEntry?> GetAsync(string userId, string provider, CancellationToken ct) { ... }
    public async Task RevokeAsync(string userId, string provider, CancellationToken ct) { ... }
}

// Register it before AddOAuth()
services.AddScoped<IExternalTokenStore, MyExternalTokenStore>();
builder.AddOAuth(...);
```

### 4.6. Request Size Limit (A-10)

Authentication endpoints can be targets of DoS attacks with large payloads. It is recommended to configure request size limits at the Kestrel level:

```csharp
// Program.cs - Limit request size to 4KB for the entire API
builder.WebHost.ConfigureKestrel(opt =>
{
    opt.Limits.MaxRequestBodySize = 4096;
});

// Or specifically for auth endpoints (more restrictive: 2KB)
builder.WebHost.ConfigureKestrel(opt =>
{
    opt.Limits.MaxRequestBodySize = 4096; // global: 4KB
});
```

> **NOTE**: AuthCore endpoints (/auth/login, /auth/refresh, /auth/forgot-password, /auth/reset-password) typically receive payloads under 1KB (email + password). A 4KB limit is reasonable and secure.

---

## 5. Middleware and Integration Endpoints

The `SecureCore.Auth.AspNetCore` package exposes extension methods for the ASP.NET Core pipeline.

### 5.1. Service Registration
```csharp
services.AddSecureAuth(options => { ... })
        .AddPasswordAuthentication();
```

### 5.2. Request Pipeline
1. `app.UseAuthentication()`: Establishes `ClaimsPrincipal` from the JWT.
2. `app.UseSecureAuthValidation()`: Active SecurityStamp validation middleware (against cache/storage) and session revocation.
3. `app.UseAuthorization()`: Access policy evaluation.

### 5.3. Automatic Endpoints
`app.MapSecureAuthEndpoints("/base-path")` registers:
- `POST /login`: Credentials reception.
- `POST /refresh`: Refresh Token rotation.
- `POST /logout`: Revocation of the current token.
- `POST /revoke-all`: Global session reset (SecurityStamp change).
- `POST /forgot-password`: Recovery flow initiation.
- `POST /reset-password`: Confirmation and credential change.

---

## 6. Security and Observability

### 6.1. Event System
The system dispatches asynchronous domain events via `IAuthEventDispatcher`.

**Key Events:**
- `LoginSuccess`: Successful login processed.
- `LoginFailed`: Invalid credential (with attempt metadata).
- `SuspiciousActivityDetected`: Detected attempt to reuse a previously rotated Refresh Token.
- `PasswordResetRequested`: Reset request initiated by email.
- `PasswordResetCompleted`: Successful password change via token.

**MFA Events:**
- `MfaEnrolled`: MFA successfully enrolled by user.
- `MfaVerificationSuccess`: MFA verification passed.
- `MfaVerificationFailed`: MFA verification failed (with attempt metadata).
- `MfaDisabled`: MFA disabled by user.

### 6.2. Enumeration Mitigation
The framework guarantees constant response time on authentication failures by injecting dummy hashing operations when the user is not found in the data store.

---

## 7. OAuth 2.0 / OIDC Ecosystem (v2.0.0)

As of v2.0.0, the framework includes a decoupled external identity validation architecture.

### 7.1. IOAuthProviderValidator
Interface implemented by all provider validators.

- `Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce, CancellationToken ct)`
- `Task<OAuthIdentityResult> ExchangeCodeAsync(string code, string redirectUri, string? expectedNonce, CancellationToken ct)`

### 7.2. Security Mechanisms

| Feature | Purpose | Implementation |
| :--- | :--- | :--- |
| **Nonce Enforcement** | Prevents Replay attacks. | Strict validation in OIDC providers (Google, MS, LinkedIn, Apple). |
| **JWKS Caching + Auto-Retry** | Performance and resilience. | In-memory cache with `Lazy<Task>` (24h expiry) + auto-retry on `SecurityTokenSignatureKeyNotFoundException` or `SecurityTokenInvalidSignatureException`. The `Lazy<Task>` pattern avoids the bottleneck caused by `SemaphoreSlim(1,1)` under high concurrency. |
| **AppSecret Proof** | Server-to-Server security. | HMAC-SHA256(AccessToken, ClientSecret) for Facebook. |
| **Dynamic Issuer** | Multi-tenancy. | Prefix/regex validation in Microsoft Entra ID. |
| **State Anti-Replay** | Prevents OAuth state reuse. | `ConsumeAsync` uses non-atomic GET + REMOVE. For high-risk apps, implement a version with Redis GETDEL. |

> **SECURITY NOTE - OAuth State TOCTOU**: The `ConsumeAsync` method in `DistributedCacheOAuthStateStore` uses a non-atomic GET + REMOVE operation. The race condition window is ~1ms and would require exact coordination between two requests.
>
> For high-risk applications requiring atomic operation, implement your own `IOAuthVersion` using Redis with the GETDEL command. The risk in practice is minimal for most applications.

### 7.3. Supported Providers

1. **Google**: OpenID Connect (v2.0).
2. **Microsoft**: Entra ID (v2.0) with multi-tenant support.
3. **Facebook**: OAuth 2.0 + Graph API + AppSecret Proof.
4. **GitHub**: OAuth 2.0 + User Email API.
5. **LinkedIn**: OpenID Connect.
6. **TikTok**: OAuth 2.0 (Login Kit V2) with adapted error handling.
7. **Apple**: Sign In with Apple (OIDC) with dynamic Client Secret generation via **ES256**.

### 7.4. SignIn Result Standardization (v2.4.0)

`OAuthSignInResult` includes a standardized `ErrorCode` property for programmatic error handling:

| ErrorCode | Meaning |
| :--- | :--- |
| `oauth_provider_not_configured` | The requested provider is not registered. |
| `oauth_user_not_found` | User not found and implicit registration is disabled. |
| `oauth_account_locked` | The account is temporarily locked due to failed attempts. |
| `oauth_validation_failed` | The ID Token or authorization code validation failed. |
| `oauth_invalid_request` | The request lacks required fields (IdToken or Code). |
| `oauth_factory_not_registered` | `AllowImplicitRegistration=true` but `IExternalUserFactory` is missing. |

### 7.5. JWT Claims Protection (v2.4.0)

`JwtTokenService` includes a static `SystemClaims` blocklist that prevents injection of 17 security-sensitive claims from `UserIdentity.Claims`:

- **Identity**: `sub`, `email`, `name`
- **Token control**: `jti`, `iss`, `aud`, `exp`, `iat`, `nbf`
- **Security**: `ssv` (SecurityStamp), `nonce`
- **Authorization**: `role`, `roles`, `auth_time`, `amr`, `acr`, `azp`

Any attempt to override these via `UserIdentity.Claims` is silently ignored.

### 7.6. CI/CD (v2.4.0)

The repository includes a GitHub Actions workflow (`.github/workflows/ci.yml`) that runs on push/PR to `main`:
- Build (`dotnet build --configuration Release`)
- Test (`dotnet test --configuration Release`)
- Format verification (`dotnet format --verify-no-changes`)

Additionally, an `.editorconfig` enforces C# 12 coding conventions: file-scoped namespaces, primary constructors, pattern matching (`is not null`), `sealed` class preference, and `nameof` usage.

---

## 8. IOperationLock - Locks for Critical Operations

### Purpose

The `IOperationLock` interface provides a mechanism to serialize access to shared resources during critical operations, primarily **Refresh Token Rotation (RTR)**.

### Interface

```csharp
public interface IOperationLock
{
    Task<IDisposable> AcquireAsync(
        string key, 
        TimeSpan timeout, 
        CancellationToken cancellationToken);
}
```

### Default Implementation: InMemoryOperationLock

The library includes `InMemoryOperationLock` which uses `SemaphoreSlim` internally:

```csharp
public sealed class InMemoryOperationLock : IOperationLock
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();

    public async Task<IDisposable> AcquireAsync(string key, TimeSpan timeout, CancellationToken ct)
    {
        var semaphore = _locks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        if (!await semaphore.WaitAsync(timeout, ct))
            throw new TimeoutException($"Could not acquire lock: {key}");
        return new LockReleaser(semaphore);
    }
}
```

### Usage in SessionOrchestrator

```csharp
// In RotateRefreshTokenAsync:
using var @lock = await operationLock.AcquireAsync($"rtr:{familyId}", timeout, ct);
// ... atomic RTR operations ...
```

### Limitations and Recommendations

| Scenario | Implementation Required | Notes |
| :--- | :--- | :--- |
| **Single-instance** | None (default) | Works out-of-the-box |
| **Multi-instance (Redis)** | Custom | Use `SETNX` with TTL |
| **Multi-instance (SQL)** | Custom | Use `sp_getapplock` |

> **IMPORTANT**: If using the default implementation in distributed architectures, you will NOT have race condition protection. Document this limitation clearly for your production operations.

### Configuration

```json
{
  "SecureAuth": {
    "OperationLock": {
      "TimeoutSeconds": 5
    }
  }
}
```

The default timeout (5 seconds) is sufficient for typical database operations (&lt;100ms). Only increase if your operations are particularly slow.

---

## 9. IRateLimiter - Rate Limiting for Attack Prevention

### Purpose

The `IRateLimiter` interface provides a mechanism to limit the number of requests from a specific source (IP, user) within a time period. It protects against:

- **Brute force**: Multiple password attempts
- **Credential stuffing**: Testing leaked passwords across multiple accounts
- **DDoS**: Overwhelming the server with requests

### Interface

```csharp
public interface IRateLimiter
{
    bool IsAllowed(string key);
    void Reset(string key);
    int GetRemainingAttempts(string key);
}
```

### Default Implementation: InMemoryRateLimiter

The library includes `InMemoryRateLimiter` which uses `ConcurrentDictionary` internally:

```csharp
public sealed class InMemoryRateLimiter : IRateLimiter
{
    private readonly ConcurrentDictionary<string, RateLimitEntry> _attempts = new();
    private readonly int _maxAttemptsPerWindow;
    private readonly TimeSpan _window;

    public InMemoryRateLimiter(int maxAttemptsPerWindow, TimeSpan window)
    {
        _maxAttemptsPerWindow = maxAttemptsPerWindow;
        _window = window;
    }

    public bool IsAllowed(string key)
    {
        // Implementation with sliding window
    }

    public void Reset(string key) { /* ... */ }
    public int GetRemainingAttempts(string key) { /* ... */ }
}
```

### Usage in Endpoints

```csharp
// In login endpoint:
if (!rateLimiter.IsAllowed(ipAddress))
    return Results.StatusCode(429);

// On successful login:
rateLimiter.Reset(ipAddress);
```

### Limitations and Recommendations

| Scenario | Implementation Required | Notes |
| :--- | :--- | :--- |
| **Single-instance** | None (default) | Works out-of-the-box |
| **Multi-instance (Redis)** | Custom | Use `StringIncrement` with TTL |
| **Multi-instance (Middleware)** | AspNetCoreRateLimiter | Alternative built-in |

> **IMPORTANT**: The default implementation does NOT work in distributed architectures. Attackers can bypass limits by distributing requests across servers. For production with multiple instances, use Redis or a rate limiting middleware.

### Configuration

```json
{
  "SecureAuth": {
    "RateLimiter": {
      "MaxAttempts": 10,
      "Window": "00:01:00"
    }
  }
}
```
