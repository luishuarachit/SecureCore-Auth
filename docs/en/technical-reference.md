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
| `SigningKey` | `string` | Symmetric key for HS256 signing. | Minimum 32 characters (256 bits) |
| `Algorithm` | `string` | Signing algorithm (Default: `HS256`). | Required |

### 2.2. SecureAuthOptions
Defines session lifecycle parameters and lockout policies.

| Property | Type | Default Value | Validation |
| :--- | :--- | :--- | :--- |
| `AccessTokenLifetime` | `TimeSpan` | 15 min | Required |
| `RefreshTokenLifetime` | `TimeSpan` | 7 days | Required |
| `GracePeriodSeconds` | `int` | 30 sec | [0, 300] |
| `MaxFailedAttempts` | `int` | 5 | [1, 100] |
| `LockoutDurations` | `TimeSpan[]` | [1m, 5m, 15m, 1h] | Required |
| `ClockSkew` | `TimeSpan` | 5 min | Required |

### 2.3. Argon2Options
Configuration for password hashing using Argon2id.

| Property | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `MemorySize` | `int` | 65536 | Memory in KB (64MB). |
| `Iterations` | `int` | 3 | Passes over the memory block. |
| `Parallelism` | `int` | 4 | Number of simultaneous threads. |
| `HashSize` | `int` | 32 | Resulting hash length in bytes. |

### 2.4. PasswordResetOptions
Defines the account recovery policy.

| Property | Type | Default Value | Validation |
| :--- | :--- | :--- | :--- |
| `TokenLifetimeMinutes` | `int` | 15 | [1, 1440] |
| `TokenSizeBytes` | `int` | 32 | [16, 64] |
| `MaxRequestsPerHour` | `int` | 3 | [0, 100] |

---

## 3. Infrastructure Interfaces (SPI)

To integrate the framework, persistence interfaces must be implemented.

### 3.1. IUserStore
Defines access to identity entities.

- `ValueTask<UserIdentity?> FindByIdAsync(string userId, CancellationToken ct)`
- `ValueTask<UserIdentity?> FindByEmailAsync(string email, CancellationToken ct)`
- `Task UpdateSecurityStampAsync(string userId, string newStamp, CancellationToken ct)`
- `Task<int> IncrementFailedAccessCountAsync(string userId, CancellationToken ct)`

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

### 6.2. Enumeration Mitigation
The framework guarantees constant response time on authentication failures by injecting dummy hashing operations when the user is not found in the data store.
