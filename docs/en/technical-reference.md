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
| `AllowedSystemClaims` | `HashSet<string>` | System claims allowed for injection from `UserIdentity.Claims`. | Default: empty (all blocked). Add `"role"`/`"roles"` for RBAC. |

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
| `ForgotPasswordRateLimiter` (v3.2.0) | `RateLimiterOptions?` | 5/hour per IP | Optional (see §9) |
| `MaxAuthRequestBodySize` (v3.2.0) | `int` | 2048 bytes | [256, 8192] (see §4.6) |
| `AccessTokenLifetimeProvider` (v3.1.5) | `Func<UserIdentity, TimeSpan?>` | null | Optional |
| `MfaVerifiedTtl` (v3.2.0, S3) | `TimeSpan` | 8 h | "mfa_verified" window; ≤ 0 → 8 h fallback (see §4.9) |
| `EmitAcr` (v3.2.0, S3) | `bool` | false | Emits the `acr` claim on every token (opt-in) |
| `AcrLevel` (v3.2.0, S3) | `string` | "1" | Value of the `acr` claim when `EmitAcr` is on |

#### Per-Role Access Token Lifetime (v3.1.5)

`AccessTokenLifetimeProvider` resolves the Access Token TTL per user (defense in depth: superadmin 15m, admin 30m, support 1h). If `null` or returns `null`, the global `AccessTokenLifetime` is used.

```csharp
options.AccessTokenLifetimeProvider = user =>
    user.Claims?.GetValueOrDefault("role") switch
    {
        "superadmin" => TimeSpan.FromMinutes(15),
        "admin"      => TimeSpan.FromMinutes(30),
        "support"    => TimeSpan.FromHours(1),
        _            => null // use global TTL
    };
```

**REQUIREMENTS**: the `role` claim must flow to the JWT via `JwtOptions.AllowedSystemClaims` (see section 7.5). If not configured, the provider receives empty `Claims` → returns null → global TTL (fail-secure). If the provider throws, a warning is logged and the global TTL is used (availability is preserved).

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

### 2.6. AccountProtectionOptions (v3.2.0, S1)
Defines the **per-account abuse prevention** policy (attempt limits per factor). It is **opt-in**
(default `Enabled = false`, principle D-03): without registering `AddSecureAuthAccountProtection()`
the previous behavior remains intact.

| Property | Type | Default Value | Validation / Note |
| :--- | :--- | :--- | :--- |
| `Enabled` | `bool` | false | Activates the S1 subsystem. |
| `Window` | `TimeSpan` | 5 min | Sliding window: failures older than `Window` no longer count. |
| `MaxAttempts` | `IReadOnlyDictionary<AccountProtectionScope, int>` | Password 5, MfaLogin 5, Passkey 5, Recovery 3, VerifyAction 5, PasswordChange 5 | Per-factor/action limit. `GetMaxAttempts(scope)` falls back to 5 for unconfigured scopes. |
| `EscalationDurations` | `IReadOnlyList<TimeSpan>` | [10 min, 30 min, 1 h, 24 h] | Lockout duration per escalation level. `GetLockDuration(level)` clamps within the list. |
| `MaxLockDuration` | `TimeSpan` | 24 h | Hard cap: no lockout exceeds this duration. |

Configuration section: `SecureAuth:AccountProtection`.

```csharp
services.AddSecureAuth(options => { options.AccountProtection.Enabled = true; /* or via appsettings */ });
services.AddSecureAuthAccountProtection(o =>
{
    o.Enabled = true;
    o.Window = TimeSpan.FromMinutes(10);
});
```

> **DIDACTIC — Level escalation**: the level is kept between episodes while the process lives. If an
> account gets locked (`Level 1` = 10 min), fails again, unlocks, and fails again, the second lockout
> is `Level 2` (30 min). This progressively raises the cost of brute force without penalizing a single
> accidental mistake.
> **DIDACTIC — Per-factor scoping**: budgets are independent per `AccountProtectionScope`. An MFA
> attack (5 attempts) does not consume the password budget, and vice versa.

> **Security (audit)**: `AddSecureAuthAccountProtection()` validates the configuration at startup (`.Validate().ValidateOnStart()`): `Window > 0`, `MaxLockDuration > 0`, `EscalationDurations` non-empty with durations > 0 and `MaxAttempts ≥ 1`. Defensively, even **without validation** (direct service construction): `GetWindow()`/`GetMaxLockDuration()` fall back to the defaults (5 min / 24 h) on values ≤ 0, and `GetLockDuration(level)` clamps every duration to the `MaxLockDuration` cap while out-of-range levels / durations ≤ 0 resolve to `MaxLockDuration` — invalid configuration never downgrades the lockout to harmless/fail-open.
>
> **DIDACTIC — Configuration precedence**: the `configure` action of `AddSecureAuthAccountProtection(Action<AccountProtectionOptions>)` overrides the `SecureAuth:AccountProtection` section **as a whole** (all properties of the received object, not only the ones you set). To combine sources, set **all** active properties in `configure` or use appsettings only.

### 2.7. VerifyActionOptions (v3.2.0, S3)
Defines the lifecycle of the **verify-action** OTP code (step-up for sensitive actions). Registered
via `AddVerifyAction()`, section `SecureAuth:VerifyAction`, validated at startup
(`.ValidateDataAnnotations().ValidateOnStart()`).

| Property | Type | Default | Validation |
| :--- | :--- | :--- | :--- |
| `TtlMinutes` | `int` | 5 | [1, 15] — the code expires even when the attempt only fails |
| `CodeLength` | `int` | 6 | [6, 8] — number of OTP digits |
| `MaxSendsPerWindow` (audit, S3) | `int` | 3 | [1, 10] — max sends per user and window (`TtlMinutes`) |

> **DIDACTIC** (H1, audit): `MaxSendsPerWindow` is a **hard throttle that ALWAYS applies**, even
> without S1. Without it, an attacker with a valid session could issue codes without limit and
> brute-force the OTP (~10^6 combinations). A successfully validated code renews the throttle
> (parity with S1). It is in-memory per instance: keep both when using a distributed S1.
>
> Step-up does NOT issue tokens by itself: its success opens the shared
> `mfa_verified` window (`SecureAuthOptions.MfaVerifiedTtl`). The host checks
> `IMfaVerifiedSessionStore.IsVerifiedAsync(userId)` to decide whether a sensitive mutation may
> proceed without repeating the code (optional-2FA pattern over an already-authenticated session).

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
Persistence for single-use tokens. Only the SHA-256 hash of the token is stored.
- `Task StoreAsync(PasswordResetEntry entry, CancellationToken ct)`
- `ValueTask<PasswordResetEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task MarkAsUsedAsync(string tokenHash, CancellationToken ct)`
- `ValueTask<int> CountRecentRequestsAsync(string userId, DateTime since, CancellationToken ct)`
- `Task DeleteExpiredAsync(CancellationToken ct)`: periodic cleanup of expired tokens (invoke with a daily BackgroundService).
- `Task UpdateDeliveryStateAsync(string tokenHash, PasswordResetDeliveryState state, CancellationToken ct)` (v3.2.0): **default interface member**. Override it to record whether the email was `Dispatched` or `Failed` (`PasswordResetEntry.DeliveryState`) for audit and cleanup of orphaned Pending/Failed tokens (A-09). Not overriding it breaks nothing: the state stays `Pending`.

### 3.4. IResetTokenMailer
Interface for dispatching recovery notifications.
- `Task SendResetEmailAsync(string email, string rawToken, CancellationToken ct)`

### 3.5. ISingleUseTokenStore (v3.2.0, S2)
Cross-cutting "consume exactly once" primitive (GETDEL equivalent). The foundation for
**anti-replay** of OAuth state (A-06), WebAuthn challenges (Phase 4) and recovery codes (Phase 5).

- `ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct)`
- `ValueTask<string?> GetAndRemoveAsync(string key, CancellationToken ct)`

**Distributed SPI contract**: `DistributedCacheOAuthStateStore` routes the **full lifecycle** of
the state (write and consume) through this SPI when registered. The default implementation
`DistributedCacheSingleUseTokenStore` uses IDistributedCache with GET + REMOVE (**non-atomic**,
residual ~1 ms window). For atomic operation in multi-instance deployments, implement this contract
over a backend that supports GETDEL/Lua (Redis) or another transactional mechanism — the store must
be **symmetric** (same backend and key format) and registered **before `AddSecureAuth()`** (where
the default is registered with `TryAddScoped`). Keys carry the caller's per-context prefix
(e.g. `OAuthState_`).

### 3.6. IAccountProtectionService (v3.2.0, S1)
**Per-account, per-factor abuse prevention** service (A-02/A-15/A-19). Designed to be extensible
(distributable) via a custom implementation over a shared backend; the default implementation is
`InMemoryAccountProtectionService`.

- `ValueTask<AccountProtectionResult> CheckAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — current budget state for the factor.
- `Task RecordFailureAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — records a failure; reaching `MaxAttempts` triggers the escalating lockout.
- `Task RecordSuccessAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — successful verification: clears the scope budget.
- `Task ResetAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — releases only the given scope.
- `Task ResetAllForUserAsync(string key, CancellationToken ct)` — releases every scope of the account (same `key`).
- `ValueTask<bool> AnyActiveLockAsync(string key, CancellationToken ct)` — decide homogeneous responses without disclosing which factor is locked.

`AccountProtectionResult` exposes `Allowed`, `RemainingAttempts`, `LockEnd` and `EscalationLevel`
(see § 4.8 for the wiring).

### 3.7. Verified-session and step-up OTP SPI (v3.2.0, S3)

- `IMfaVerifiedSessionStore` — "mfa_verified" window (A-21): `SetVerifiedAsync(userId, method)`,
  `IsVerifiedAsync(userId)`, `ClearAsync(userId)`. Default `DistributedCacheMfaVerifiedSessionStore`
  (TTL `SecureAuthOptions.MfaVerifiedTtl`, defensive 8 h fallback; the key stores the verified
  method and its presence means verified). Registered `TryAddScoped` in `AddMfa`,
  `AddPasswordAuthentication` and `AddVerifyAction`.
  - **Lifecycle (H2, audit)**: `SessionOrchestrator` (when an `IMfaVerifiedSessionStore` is
    registered) calls `ClearAsync(userId)` in both `RevokeAllSessionsAsync` and `LogoutAsync`: a
    fresh session (without MFA) must not inherit the step-up of a session revoked/closed by an
    attacker.
- `IEmailOtpStore` (A-22) — step-up OTP code with **atomic single-use** consumption: only the
  SHA-256 hash (lowercase hex) is persisted; `ValidateAndRemoveCodeAsync` compares in constant time
  (`CryptographicOperations.FixedTimeEquals` with a length guard) and consumes the entry by
  delegating to `ISingleUseTokenStore` (S2). Default `DistributedCacheEmailOtpStore`.
- `IEmailOtpSender` (A-22) — transports the code to its destination. Default
  `EmailServiceEmailOtpSender` (adapter over `IEmailService`). Register your own implementation
  BEFORE `AddVerifyAction()` to override it (TryAdd).

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

**Email MFA requirement:** The default `IEmailMfaService` (`EmailMfaService`) sends codes through `IEmailService`. SecureCore registers a `NullEmailService` default (via `TryAddScoped`) that **throws** `InvalidOperationException` when used. Register your own `IEmailService` **before** `AddMfa()`/`AddPasswordAuthentication()`:
```csharp
services.AddScoped<IEmailService, MyEmailService>();
builder.Services.AddSecureAuth(...).AddMfa();
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

Authentication endpoints can be targets of DoS attacks with large payloads. The library limits the body of the anonymous endpoints `/auth/login`, `/auth/refresh`, `/auth/forgot-password` and `/auth/reset-password` with two complementary mechanisms:

- **`SecureAuthOptions.MaxAuthRequestBodySize`** (default: `2048` bytes, range `[256, 8192]`): defines the limit.
- **Endpoint filter** (`EnforceAnonymousRequestSizeLimit`): fast rejection by `Content-Length` for any valid body that exceeds the limit, returning `413 Payload Too Large` (JSON). It is added automatically to the 4 anonymous endpoints and is verifiable in TestServer.
- **Middleware** `UseSecureAuthRequestSizeLimit(prefix)`: sets `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize` **before** binding, so Kestrel rejects with 413 even **chunked** bodies (without `Content-Length`).

> **IMPORTANT**: In Minimal APIs endpoint filters run **after** binding, so a filter alone cannot limit chunked bodies. Register the middleware with the same prefix as `MapSecureAuthEndpoints`:

```csharp
app.MapSecureAuthEndpoints("/auth");
app.UseSecureAuthRequestSizeLimit("/auth");
```

For global limits for the whole API (outside the auth endpoints), keep using Kestrel configuration (`Kestrel.MaxRequestBodySize`); the middleware does not replace it.

### 4.7. PasskeyService (WebAuthn)

Registration and assertion service for Passkeys (FIDO2/WebAuthn), enabling passwordless login.

- **`CompleteRegistrationAsync(response, options, userId, displayName)`**: registers a new passkey.
- **`BeginAssertionAsync(credentialIds)`**: generates the login challenge (`null` = Discoverable Credentials).
- **`CompleteAssertionAsync(response, options)`**: verifies the signature and returns the user, or `null` on failure (ambiguous by design).
- **`CompleteAssertionDetailedAsync(response, options)`** (v3.2.0, A-17): verifies the signature and returns a `PasskeyAssertionResult` that distinguishes the outcome:

| Property | Meaning |
| :--- | :--- |
| `User` | The resolved subject (if resolvable), useful for per-account policies (lockout). |
| `CredentialFound` | Whether the credential referenced by the client exists in the store. |
| `SignatureValid` | Whether the challenge signature verified correctly. |

> **SECURITY** (v3.2.0): A malformed credential `Id` (not Base64) is treated as "credential not found" and never throws. `CredentialFound` is a credential-existence oracle — needed by design for per-account lockout — but **do not expose this distinction to the client**: always return the same generic authentication error.

#### 4.7.1. Credential ID resolution (S4)

- **`TryResolveCredentialId(response)`** prefers `response.RawId` — the `byte[]` already decoded by Fido2NetLib's `Base64UrlConverter` — and falls back to `response.Id` (string) only through **`TryDecodeBase64UrlCredentialId`**:
  - Normalizes unpadded Base64URL into standard Base64 (`-`→`+`, `_`→`/`) and adds synthetic padding (`=`, `==`).
  - A `length % 4 == 1` (invalid padding), an empty string, or a `FormatException` all resolve to `null` (credential not found), never to an exception.
  - Standard `Convert.FromBase64String` is NOT Base64URL: the `Id` sent by the browser (`-`/`_`, unpadded) would fail ~100% of the time. Do not use it on `response.Id`.

#### 4.7.2. Automatic FIDO2 configuration (S4)

`AddWebAuthn()` registers with `TryAddSingleton`:

| Service | Derivation |
| :--- | :--- |
| `Fido2Configuration` | `ServerDomain = WebAuthnOptions.RelyingPartyId`, `ServerName = RelyingPartyName`, `Origins = WebAuthnOptions.Origins` |
| `Fido2` | Ctor `Fido2(Fido2Configuration, IMetadataService?)` (metadata service resolved from DI if present; optional) |
| `IFido2` | Same instance as `Fido2` |

**Security consequence**: Fido2NetLib internally validates the origin signed in the `clientDataJSON` against the `Fido2Configuration` of its `Fido2` instance. Since that configuration is now derived from `WebAuthnOptions`, the verified origin matches the one you configured for the ceremony — there is no longer a consumer-side decoupled config. `RelyingPartyId`/`RelyingPartyName` are no longer dead options.

#### 4.7.3. Anti-enumeration in `BeginLoginAsync` (S4)

- By default (`DiscloseCredentialsInLoginBegin = false`) the enumeration oracle is **closed**: `userId` is not propagated to `BeginAssertionAsync`, so `allowCredentials` are not filtered per user and the response is identical whether the userId exists or not.
- When enabled (`= true`), `BeginLoginAsync` passes `userId` into the challenge, propagating the user's credential IDs to the authenticator (allows "this account has no passkeys" on the client). **Risk**: enrollment oracle by userId sweeping.

#### 4.7.4. Rate limiting and payload (S4)

- **`/webauthn/login/begin`**: keyed limiter `"webauthn-begin"` (default 30 attempts/min per IP, `SecureAuthOptions.WebAuthnBeginRateLimiter`).
- **`/webauthn/login/complete`**: keyed limiter `"webauthn-complete"` (default 10 attempts/min per IP, `SecureAuthOptions.WebAuthnCompleteRateLimiter`); reset after a successful login. The key is `Connection.RemoteIpAddress` (the real TCP connection IP; see the XFF section — do not use the header as a key).
- If the host does not register the limiters (an app without `AddSecureAuth`), the endpoints degrade gracefully and do not fail.
- **`/webauthn/*`**: `RequestSizeLimitMiddleware` assigns `MaxWebAuthnRequestBodySize` (default 65536 bytes, range [4096, 1048576]) to `IHttpMaxRequestBodySizeFeature`. FIDO2 payloads (KB-scale) neither depend on the 2 KB limit of `/auth` nor fall back to Kestrel's default (~30 MB).

#### 4.7.5. Ceremony-typed challenges (S4)

- `StoreChallengeAsync` stores under key `"{tag}:{rawId}"` (`"register:…"` for registration, `"login:…"` for login); the `challengeId` returned to the client is the opaque `rawId`.
- On consume, the orchestrator recomposes the typed key according to the ceremony: cross-ceremony reuse (a registration challenge presented on login or vice versa) is **fail-closed** — the entry is not found under the expected ceremony key and the request is rejected before parsing the authenticator response. Combined with the atomic single-use of `ISingleUseTokenStore` (reusing the same `challengeId` within the same ceremony also fails).

### 4.8. Per-account abuse prevention (S1, v3.2.0)
Integration of `IAccountProtectionService` into the orchestrators. It is activated **only** via
`AddSecureAuthAccountProtection()` (registers the service and binds `AccountProtectionOptions`
from `SecureAuth:AccountProtection`). Without that registration, `IdentityOrchestrator` and
`MfaOrchestrator` keep their legacy (DB-based lockout) policy unchanged.

| Flow | Scope | Integration |
| :--- | :--- | :--- |
| `IdentityOrchestrator.SignInWithPasswordAsync` | `Password` | **Pre-check**: if `CheckAsync` denies, returns `SignInResult.LockedOut` with `AccountLockedOut (reason: account_protection_lock)`. **Wrong password**: `RecordFailureAsync`; when the lockout triggers, `LockedOut` + `AccountLockedOut (reason: lock_triggered, scope, level)`. **Success/RequiresMfa**: `RecordSuccessAsync` (scope reset). The legacy `LockoutManager` flow (admin/DB policy) is kept in parallel. |
| `MfaOrchestrator.VerifyAsync` | `MfaLogin` | **Pre-check**: if the scope is locked → `"Demasiados intentos. Intente más tarde."`. **Failure**: `RecordFailureAsync`; the failure that triggers the lockout responds `"Código inválido"` (generic, no oracle about when it locks). **Success**: `RecordSuccessAsync`. Without S1, the legacy flow is kept (`IncrementMfaFailedAttemptsAsync` + `ApplyMfaLockoutIfNeededAsync` with `MaxVerificationAttempts`/`CodeRetryWindowMinutes`). |

> **Legacy → S1 transition (fail-closed)**: when S1 is enabled, `VerifyAsync` honors a pending `LockoutEnd` left by the legacy DB flow: a user with `MfaFailedAttemptsCount >= MaxVerificationAttempts` and an active lockout is blocked even if the S1 window recorded no failures. Expiry self-resets (T9: `IsMfaLockedOutAsync` clears counter and lockout) and the flow continues — a historical lockout cannot veto the account forever.

> **DIDACTIC — Per-attempt events**: with S1 enabled, `MfaVerificationFailed` is published on **every** failure: the `attempts` metadata reports the remaining attempts (budget still available) or `MaxAttempts` for the failure that triggers the lockout. Without S1 (legacy), the event was emitted only on the lockout-triggering failure.

> **DIDACTIC — Escalating lockout**: `InMemoryAccountProtectionService` keeps `EscalationLevel`
> between episodes; the 2nd lockout of the same account lasts 30 min (level 2), the 3rd 1 h, etc.
> `LockEnd` is computed as `now + GetLockDuration(level)`, capped at `MaxLockDuration`.
> Failures during an active lockout are **ignored** (they spend no budget and do not extend the lock).

### 4.9. Verified-session state, verify-action and password (S3, v3.2.0)

**`mfa_verified` window**: `IdentityOrchestrator.CompleteMfaLoginAsync` marks the window with the
verified method (`SetVerifiedAsync(userId, method.ToLowerInvariant())`) **only** on a successful
MFA login — a failed MFA attempt never opens it. The window is **additive**: without an
`IMfaVerifiedSessionStore` registered, the flow behaves exactly as before.

**Step-up `VerifyActionOrchestrator`** (`AddVerifyAction()`):

| Method | Behavior |
| :--- | :--- |
| `SendVerifyCodeAsync(userId, channel, cancellationToken)` | Validates the channel (`VerifyActionChannel.Email`), applies the per-user **hard throttle** (H1, audit: `MaxSendsPerWindow` = 3 per window, always active even without S1), fires the send via `IEmailOtpSender`, and ONLY after a successful delivery stores the OTP hash (`IEmailOtpStore`, `VerifyActionOptions.TtlMinutes`/`CodeLength`). Each send spends one unit of the S1 `VerifyAction` scope (anti email-flood); when exhausted it returns a generic failure. Sender errors → generic failure without storing the hash or spending budget (M2, audit; no enumeration). |
| `VerifyActionAsync(userId, code, cancellationToken)` | Rejects codes whose length differs from `CodeLength` (H3, audit) before touching the store. S1-checked: failure → spends budget (the lockout-triggering failure returns a generic failure). Correct code → **atomic** single-use consume, `RecordSuccessAsync` + throttle renew (budget renewed), opens the `mfa_verified` window with the verified method, and fires `VerifyActionCompleted` (success) or `VerifyActionFailed` (failure). |

**Password with step-up — `ChangePasswordOrchestrator`** (`AddChangePassword()`):

- `CreateAsync(userId, newPassword, cancellationToken)`: for accounts with **no password yet**
  (passwordless → password flow). Requires the verify-action window to be **open** (M1, audit): the
  OTP was already consumed in `VerifyActionAsync` (single-use), so this only checks
  `IMfaVerifiedSessionStore.IsVerifiedAsync(userId)`; closed window → fail-closed
  `verify_action_required`. Code 409 `password_already_exists` when the account already has a
  password (idempotency invariant, not a security failure).
- `ChangeAsync(userId, currentPassword, newPassword, cancellationToken)`: validates the current
  password against the hasher; returns `invalid_current_password` otherwise (and spends the S1
  `PasswordChange` budget — M4, audit — when enabled; the current password is capped at 1024
  characters before Argon2 to prevent memory/CPU amplification — H3, audit). Account without a
  registered password → `no_password_created`. `SuccessRehashNeeded` spots an outdated hash and
  updates it.
- Both rotate the **SecurityStamp** (call to `IUserStore.UpdateSecurityStampAsync`), invalidate the
  stamp cache (`SecurityStampValidator.InvalidateAsync`), revoke **all** previous sessions
  (`RevokeAllAsync`) — re-issuing **a new token pair** whose refresh family is **new** (including the
  in-use family) — and fire `SecurityStampUpdated` (stamp: new).
- Password policy (NIST SP 800-63B): 8–1024 characters; **no** composition rules; rejection →
  generic failure (`invalid_password`).

> **NOTE**: `ChangePasswordOrchestrator` accepts optional `IPasswordHasher` and `ITokenService`
> (null → resolved from DI); `IUserStore` and `ISecurityStampValidator` are **required** (without
> registered implementations, `AddChangePassword()` fails in ValidateOnBuild). The
> `/create-password` and `/change-password` endpoints return the **new token pair** in the body
> (`success.tokens`) so the client adopts the new family.

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

> **DIDÁCTICA — Scoped resolution**: `SecurityStampValidator` is **scoped** and is resolved by the middleware **per request** (via `InvokeAsync`), not in its constructor. Middleware instances are constructed once for the whole application; injecting a scoped service into the constructor would create a **captive dependency** (a scoped instance held by the root provider) and fail under `ValidateOnBuild`/`ValidateScopes`. Resolving it per request guarantees the validator always runs with a valid request scope.

### 5.3. Automatic Endpoints
`app.MapSecureAuthEndpoints("/base-path")` registers:
- `POST /login`: Credentials reception.
- `POST /refresh`: Refresh Token rotation.
- `POST /logout`: Revocation of the current token.
- `POST /revoke-all`: Global session reset (SecurityStamp change).
- `POST /forgot-password`: Recovery flow initiation.
- `POST /reset-password`: Confirmation and credential change.

**S3 (v3.2.0) — opt-in endpoints** (require Bearer authentication; the `userId` comes from the `sub`
claim; responses use generic messages; 503 when the orchestrator is not registered):

- `POST /verify-action/send`: no body — sends a step-up OTP (user from the `sub` claim; fixed email channel in this version).
- `POST /verify-action/verify`: `{ code }` — consumes the OTP and opens the window.
- `POST /create-password`: `{ newPassword }` — creates a password (requires an open step-up window; no `otp` in the body).
- `POST /change-password`: `{ currentPassword, newPassword }` — changes the password (no step-up).

---

## 6. Security and Observability

### 6.1. Event System
The system dispatches asynchronous domain events via `IAuthEventDispatcher`. The implementer can subscribe by registering an `IAuthEventHandler` handler in DI.

**Key Events:**
- `LoginSuccess`: Successful login processed.
- `LoginFailed`: Invalid credential (with attempt metadata).
- `AccountLockedOut`: Account locked after too many failed attempts.
- `TokenRotated`: Refresh Token rotated successfully.
- `Logout` / `GlobalLogout`: Single-session / all-sessions logout.
- `SuspiciousActivityDetected`: Detected attempt to reuse a previously rotated Refresh Token.
- `PasskeyRegistered` / `PasskeyLoginSuccess`: WebAuthn/Passkey registration and login.
- `PasswordResetRequested`: Reset request initiated by email.
- `PasswordResetCompleted`: Successful password change via token.
- `MfaEnrolled` / `MfaDisabled` / `MfaVerificationSuccess` / `MfaVerificationFailed`: MFA flow events.
- `AnonymousLoginFailed` (v3.1.5): Login attempt with non-existent email/user. `UserId = null`, no sensitive data in Metadata (anti-enumeration).
- `RateLimitExceeded` (v3.1.5): IP rate limit exceeded on `/auth/login`. `UserId = null`.
- `PasskeyVerificationFailed`, `SecurityStampChanged`, `PasswordChangeFailed` (v3.1.5): Reserved for future use.

**Automatic HTTP context enrichment (v3.1.5):**
`AuthEventContextEnricher` is a decorator of `IAuthEventDispatcher` registered automatically in DI. It adds to `Metadata` without implementer intervention:
- `ip`: `RemoteIpAddress` (real TCP connection IP).
- `path`: request path.
- `ua`: `User-Agent` header.
- `xff`: `X-Forwarded-For` header (spoofable; stored separately from `ip`).
- `roles`: role claims of the authenticated user (from the `ClaimsPrincipal` already validated by the JWT middleware).

**`AuthEvent.UserId` nullable (v3.1.5):** enables anonymous events (`AnonymousLoginFailed`, `RateLimitExceeded`) without an identified user. Handlers must validate `UserId` before acting on it.

### 6.2. Enumeration Mitigation
The framework guarantees constant response time on authentication failures by injecting dummy hashing operations when the user is not found in the data store.

### 6.3. Proper use of X-Forwarded-For

The `X-Forwarded-For` (XFF) header is informational and is **not** used as a rate-limiting key or as the basis for security decisions in the library:

- **IP rate limit** (`/auth/login`): uses `Connection.RemoteIpAddress` (the real TCP connection IP), it does **not** read `X-Forwarded-For`. Sending XFF does not bypass it.
- **TOTP verification and enrollment**: the rate limit is **per-user** (`MfaFailedAttemptsCount`), independent of the IP or XFF.
- **Auditing**: `AuthEventContextEnricher` stores `xff` as informational metadata, separate from `ip` (the real connection IP).

**When to use XFF**: only when the API is behind a reverse proxy (nginx, HAProxy, load balancer, Cloudflare), where `RemoteIpAddress` is the proxy's IP. In that case, configure ASP.NET Core `ForwardedHeaders` (`UseForwardedHeaders`) so `RemoteIpAddress` reflects the real client IP in a **controlled** way (only trusting the configured proxies). Without this, behind a proxy all users share the same rate-limit key.

**Risk**: if an implementer builds a custom `IRateLimiter` that uses the `X-Forwarded-For` header as its key, **an attacker can bypass the rate limit by forging the header**. Do not do this without validating the header's origin (trusted proxies).

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
| **State Anti-Replay** | Prevents OAuth state reuse. | `ConsumeAsync` delegates to `ISingleUseTokenStore` (§3.5) — overridable with an atomic implementation (Redis GETDEL/Lua). |

> **SECURITY NOTE - OAuth State TOCTOU**: As of v3.2.0, `ConsumeAsync` in `DistributedCacheOAuthStateStore` delegates to the `ISingleUseTokenStore` SPI. The default implementation (`DistributedCacheSingleUseTokenStore`) uses non-atomic GET + REMOVE (~1 ms race window).
>
> For high-risk applications requiring atomic operation, implement your own `ISingleUseTokenStore` using Redis with the GETDEL command (or an equivalent transactional operation); `DistributedCacheOAuthStateStore` will consume it automatically. The risk in practice is minimal for most applications.

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

`JwtTokenService` includes a `SystemClaims` blocklist that prevents injection of security-sensitive claims from `UserIdentity.Claims`. Starting from v3.1.0, this blocklist is configurable via `JwtOptions.AllowedSystemClaims`:

- **Default**: All system claims are blocked, including `role` and `roles`.
- **To enable RBAC**: Add `"role"` and `"roles"` to `AllowedSystemClaims`. This allows injecting roles from `UserIdentity.Claims` to use `[Authorize(Roles = "...")]`.

```csharp
// Enable RBAC in JWT
options.Jwt.AllowedSystemClaims = new HashSet<string> { "role", "roles" };
```

> **v3.1.4 (fix)**: The Fluent API now propagates `AllowedSystemClaims` to the effective `JwtOptions`. Previously, configuring it only via the Fluent API left the set empty (RBAC broken). `appsettings.json` binding (`SecureAuth:Jwt:AllowedSystemClaims`) remains supported.

> **v3.1.5**: `ITokenService.GenerateAccessToken(UserIdentity, TimeSpan? lifetime = null)` accepts an optional TTL. If null, the global TTL or the one resolved by `AccessTokenLifetimeProvider` is used.

**Claims blocked by default:**
- **Identity**: `sub`, `email`, `name`
- **Token control**: `jti`, `iss`, `aud`, `exp`, `iat`, `nbf`
- **Security**: `ssv` (SecurityStamp), `nonce`
- **Authorization**: `role`, `roles`, `auth_time`, `amr`, `acr`, `azp`

Any attempt to override these via `UserIdentity.Claims` is silently ignored, unless explicitly allowed in `AllowedSystemClaims`.

### 7.6. OAuth SignIn Options (v3.1.0)

`OAuthSignInOptions` includes new properties for HttpOnly cookie-based authentication and OAuth `redirect_uri` configuration:

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `SetCookiesDirectly` | `bool` | false | If true, sets HttpOnly cookies and redirects to SPA instead of returning JSON. |
| `CookieDomain` | `string?` | null | Cookie domain (e.g., ".example.com" for subdomains). |
| `PostLoginRedirectUrl` | `string?` | null | Post-login redirect URL for the SPA. Default: "/". |
| `PublicBaseUrl` | `string?` | null | Public API base used as the provider `redirect_uri`. When null, it is derived from the request (scheme + host). Set it explicitly when the API sits behind a load balancer / TLS termination. |
| `CallbackPrefix` | `string` | `/auth/oauth` | Route prefix where OAuth endpoints are mapped. The provider `redirect_uri` is built as `{base}{CallbackPrefix}/{provider}/callback`. |
| `AllowedPostLoginHosts` | `string[]` | `[]` | Extra hosts allowed as SPA post-login targets. The `redirectUri` query param of `/authorize` is accepted only if HTTPS and its host is in this list or matches `PostLoginRedirectUrl`. Prevents open redirect. |

```csharp
// Enable HttpOnly cookies for OAuth
services.Configure<OAuthSignInOptions>(opts =>
{
    opts.SetCookiesDirectly = true;
    opts.CookieDomain = ".example.com";
    opts.PostLoginRedirectUrl = "https://app.example.com/dashboard";
});
```

### 7.7. IMfaCodeStore — MFA Code Storage (v3.1.0)

New interface for storing and validating temporary MFA codes (email):

```csharp
public interface IMfaCodeStore
{
    Task StoreCodeHashAsync(string key, string codeHash, TimeSpan ttl, CancellationToken ct);
    Task<bool> ValidateAndRemoveCodeAsync(string key, string code, CancellationToken ct);
}
```

**Default implementation**: `DistributedCacheMfaCodeStore` uses `IDistributedCache` (compatible with MemoryCache, Redis, SQL Server).

**Security**:
- Codes are stored as SHA-256 hashes, never in plaintext.
- Validation uses `CryptographicOperations.FixedTimeEquals` to prevent timing attacks.
- Codes are single-use: removed after the first validation attempt.

### 7.11. MFA/TOTP Flow Security (v3.1.6)

Hardening of MFA enrollment and verification:

1. **Enrollment bound to the session token**: `CompleteEnrollmentAsync(userId, code, mfaSessionToken)` validates that the `mfaSessionToken` belongs to the `userId` and **consumes** it (single-use). Only whoever started the enrollment can complete it.

> **v3.1.8 (fix)**: token single-use is now real. The consumed `jti` is registered in `IMemoryCache` (expiration = token `ValidTo`); reuse returns `null`. The `sub` claim is also read as `ClaimTypes.NameIdentifier` (due to `JwtSecurityTokenHandler` claim mapping). Note: the blacklist is in-memory (single-instance); for multi-instance, replace `IMfaSessionStore` with a distributed implementation.
2. **TOTP secret anti-overwrite**: `StartEnrollmentAsync` rejects if the user is `Enrolled` or if there is a `Pending` enrollment with a secret. `DisableAsync` can cancel a pending enrollment (prevents getting stuck if the token expired).
3. **Anti-TOCTOU (fingerprint)**: a SHA-256 hash of the secret is embedded in the `mfaSessionToken`. If the secret changes between Start and Complete, completion is rejected.
4. **TOTP code single-use**: the same code cannot complete the enrollment or verify the login twice within the tolerance window (±1 step). It is marked as used in `IMfaCodeStore` (key `mfa_totp_used_code:{userId}`).
5. **Enrollment rate limit**: `CompleteEnrollmentAsync` applies `MaxVerificationAttempts` (increments on failure, resets on success).
6. **Temporary lockout (not permanent)**: when `MaxVerificationAttempts` is exceeded, `LockoutEnd = UtcNow + CodeRetryWindowMinutes` is set. When the window expires, the counter resets automatically. An active, longer password lockout is not overwritten.
7. **Base32 RFC 4648**: `TotpService` generates 20-byte secrets → 32 characters, without entropy loss (fixes the previous encoder that produced 40 characters and ~140 effective bits).

#### 7.11.1. Post-enrollment flow — authentication suggestion

`CompleteEnrollmentAsync` returns `true` when the user verifies a valid enrollment code. That moment constitutes **real proof of possession of the MFA factor**. The library does **not** automatically issue tokens on enrollment completion; the continuation policy is the implementer's decision.

**Available building blocks** (all public): `CompleteEnrollmentAsync`, `VerifyAsync`, `CompleteMfaLoginAsync`, `ITokenService.GenerateTokenPairAsync`, `ISessionStore.CreateAsync`.

**Suggestion**: treat a successful enrollment completion as a completed MFA verification and issue the session with the `amr=mfa` + `mfa_method` markers, without re-requesting a code.

**Valid alternatives**: later re-authentication with a new code (e.g., after 30 seconds), password + new code, or any other policy defined by the implementer.

**Bad practices to avoid:**
1. Reusing the same TOTP code from the enrollment for an immediate login verification (fails due to code single-use, ±1 step window; designed behavior, not a bug).
2. Issuing `amr=mfa` or tokens without `CompleteEnrollmentAsync` returning `true`.
3. Not persisting the refresh token in `ISessionStore` when issuing a post-enrollment session (orphaned / non-revocable session).
4. Not resetting `MfaFailedAttemptsCount` after a successful enrollment.
5. Leaving the enrollment `mfaSessionToken` reusable (it must be consumed, single-use).

### 7.8. OAuthClaimHelper — Secure OIDC Claim Extraction

Static helper in `SecureCore.Auth.OAuth` that extracts claims from `JwtSecurityToken` preserving the original short JWT claim types (avoiding the URI mapping done by `ClaimsPrincipal`):

```csharp
// Usage in OAuth validators:
var sub = OAuthClaimHelper.GetClaim(jwt, "sub");
var email = OAuthClaimHelper.GetClaim(jwt, "email");
```

### 7.9. OAuth redirect_uri and URL Normalization

The OAuth provider `redirect_uri` is **always the API callback URL** (`{base}{CallbackPrefix}/{provider}/callback`), never the SPA URL. Providers (Google, Microsoft, etc.) require it to match exactly the one registered in their console, both on the `/authorize` request and on the token exchange in `/callback`.

The callback URL is computed once in `/authorize` (using `PublicBaseUrl` or derived from the request) and stored in the OAuth state so `/callback` reuses the exact same value (no drift).

The `/authorize` endpoint normalizes the `redirectUri` by removing the `www.` prefix from the host to match the redirect URIs registered with OAuth providers. The `redirectUri` query param is the **SPA post-login target** (not the provider `redirect_uri`); it is accepted only if HTTPS and its host is in `AllowedPostLoginHosts` or matches `PostLoginRedirectUrl`, otherwise the request fails with `400 invalid_redirect_uri`.

> **Deployment requirement**: register the exact API callback URL in each provider console (e.g. `https://api.example.com/auth/oauth/google/callback`).

### 7.10. CI/CD (v2.4.0)

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

#### Dedicated throttling of `/forgot-password` (v3.2.0)

The anonymous `/forgot-password` endpoint uses a **keyed, dedicated** limiter (`"forgot-password"` in DI), so it does not share budget with the login one. It is configured with `SecureAuthOptions.ForgotPasswordRateLimiter` (default: 5 requests/hour per IP). The throttling is **silent**: when the limit is exceeded the request is discarded but the endpoint still responds with the same blind 200, giving no oracle to the attacker.

In multi-instance architectures, replace the default (in-memory) implementation with a distributed one:

```csharp
services.AddKeyedSingleton<IRateLimiter>("forgot-password",
    (sp, _) => new RedisRateLimiter(max: 5, window: TimeSpan.FromHours(1)));
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
