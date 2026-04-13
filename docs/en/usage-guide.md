# SecureCore Auth Framework

## What is SecureCore Auth?

SecureCore Auth is an **authentication and authorization library** for web applications built with C# and ASP.NET Core. If you come from other languages, think of it as the equivalent of:

- **Passport.js** in Node.js
- **Django Auth** in Python
- **Devise** in Ruby on Rails
- **Spring Security** in Java

But with a modern security-first approach: **Passkeys**, automatic token rotation, and built-in protection against common attacks.

### What problems does it solve?

When building a web application, you need users to:

1. **Register** with an email and password (or with Passkeys)
2. **Log in** securely
3. **Stay authenticated** without entering their password on every request
4. **Log out** from one device or all devices at once
5. **Be protected** against brute-force attacks, token theft, etc.

SecureCore Auth implements all of this following OWASP security best practices, without requiring you to be a cryptography expert.

### Architecture: How is it organized?

The library is split into 4 packages you can use as needed:

```
┌──────────────────────────────────────────────────────────┐
│             Your Application (API or WebApp)              │
├──────────────────────────────────────────────────────────┤
│     SecureCore.Auth.AspNetCore  (Integration)             │
│     Fluent API · Middleware · Ready-made Endpoints         │
├──────────────────────────────────────────────────────────┤
│  SecureCore.Auth.Core    │  SecureCore.Auth.WebAuthn      │
│  Passwords · JWT         │  Passkeys · FIDO2              │
│  Sessions · Lockout      │                                │
├──────────────────────────────────────────────────────────┤
│           SecureCore.Auth.Abstractions                    │
│           Interfaces · Models · Contracts                  │
└──────────────────────────────────────────────────────────┘
```

- **Abstractions**: Defines the "rules of the game" — interfaces you implement to connect your database.
- **Core**: Authentication logic — password hashing, JWT tokens, session management.
- **WebAuthn**: Passkey support (passwordless authentication).
- **AspNetCore**: ASP.NET Core integration — everything you need to plug the library into your app.

---

## Fundamental Concepts

Before getting started, let's review some key concepts. If you already know them, skip to [Quick Start](#quick-start).

### What is a JWT?

A **JWT** (JSON Web Token) is like a digital "access pass". When a user logs in successfully, the server gives them a JWT that says "this user is who they claim to be". The user includes this token in every subsequent request to prove their identity without sending their password each time.

```
Real-world analogy:
Imagine you check into a hotel. At the front desk they give you a key card (JWT).
You use that card to open your room without showing your passport each time.
The card has an expiration date and only works for your room.
```

### What is a Refresh Token?

A JWT has a short lifespan (15 minutes by default). When it expires, instead of asking the user to log in again, we use a **Refresh Token** — a long-lived token that allows obtaining a new JWT without a password.

```
Analogy:
Your hotel key card expires every day at noon.
But you have a voucher (Refresh Token) that lets you go to the front desk
and get a new card without showing your passport again.
The voucher lasts the entire week (7 days).
```

### What are Passkeys?

**Passkeys** are a modern authentication method that replaces passwords. They use your device's biometrics (fingerprint, Face ID) or a USB security key. They are immune to phishing and cannot be stolen from a database because the private key never leaves the user's device.

### What is the Store pattern?

SecureCore Auth **doesn't know how you store your data**. It doesn't matter if you use PostgreSQL, MongoDB, Redis, or a text file. The library defines interfaces (contracts) that you implement to connect it with your storage system. This is called "dependency inversion" and gives you complete freedom.

---

## Quick Start

### Prerequisites

- **.NET 8 SDK** or later installed ([download here](https://dotnet.microsoft.com/download))
- A code editor (VS Code, Visual Studio, Rider, etc.)
- An existing ASP.NET Core application or a new one

If you don't have an application, create one with:
```bash
dotnet new webapi -o MyApp
cd MyApp
```

### Step 1: Install the package

```bash
dotnet add package SecureCore.Auth.AspNetCore
```

This installs everything needed (Abstractions, Core, WebAuthn are included as transitive dependencies).

### Step 2: Implement the Stores (connect your database)

This is the most important step: **you tell the library how to access your data**. You need to implement at least 2 interfaces.

#### IUserStore — Where users live

This interface tells the library how to find, create, and modify users. Here's a complete example using Entity Framework Core (.NET's most popular ORM):

```csharp
using Microsoft.EntityFrameworkCore;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;

// This class connects SecureCore Auth to your user database.
// You only need to implement the methods the library requires.
public class MyUserStore : IUserStore
{
    private readonly MyDbContext _db; // Your Entity Framework context

    public MyUserStore(MyDbContext db)
    {
        _db = db;
    }

    // Find a user by their unique ID
    public async ValueTask<UserIdentity?> FindByIdAsync(
        string userId, CancellationToken ct = default)
    {
        return await _db.Users.FindAsync([userId], ct);
    }

    // Find a user by their email
    public async ValueTask<UserIdentity?> FindByEmailAsync(
        string email, CancellationToken ct = default)
    {
        return await _db.Users
            .FirstOrDefaultAsync(u => u.Email == email.ToLower(), ct);
    }

    // Find by external provider (Google, GitHub, etc.)
    public ValueTask<UserIdentity?> FindByExternalProviderAsync(
        string provider, string providerKey, CancellationToken ct = default)
    {
        return ValueTask.FromResult<UserIdentity?>(null);
    }

    // Update password hash (used during reset)
    public async Task UpdatePasswordHashAsync(
        string userId, string newPasswordHash, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        if (user is not null)
        {
            user.PasswordHash = newPasswordHash;
            await _db.SaveChangesAsync(ct);
        }
    }

    // Update the SecurityStamp
    public async Task UpdateSecurityStampAsync(
        string userId, string newStamp, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        if (user is not null)
        {
            user.SecurityStamp = newStamp;
            await _db.SaveChangesAsync(ct);
        }
    }

    // Get the current SecurityStamp
    public async ValueTask<string?> GetSecurityStampAsync(
        string userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        return user?.SecurityStamp;
    }

    // Increment the failed login attempts counter
    public async Task<int> IncrementFailedAccessCountAsync(
        string userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        if (user is not null)
        {
            user.FailedAccessCount++;
            await _db.SaveChangesAsync(ct);
            return user.FailedAccessCount;
        }
        return 0;
    }

    // Reset the counter
    public async Task ResetFailedAccessCountAsync(
        string userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        if (user is not null)
        {
            user.FailedAccessCount = 0;
            await _db.SaveChangesAsync(ct);
        }
    }

    // Set until when the account is locked
    public async Task SetLockoutEndAsync(
        string userId, DateTimeOffset? lockoutEnd, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        if (user is not null)
        {
            user.LockoutEnd = lockoutEnd;
            await _db.SaveChangesAsync(ct);
        }
    }
}
```

#### ISessionStore — Where sessions are stored

This interface manages Refresh Tokens (the user's "sessions").

```csharp
using Microsoft.EntityFrameworkCore;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

public class MySessionStore : ISessionStore
{
    private readonly MyDbContext _db;

    public MySessionStore(MyDbContext db) => _db = db;

    public async Task CreateAsync(RefreshTokenEntry entry, CancellationToken ct = default)
    {
        _db.RefreshTokens.Add(entry);
        await _db.SaveChangesAsync(ct);
    }

    public async ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(
        string tokenHash, CancellationToken ct = default)
    {
        return await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);
    }

    public async Task RevokeAsync(
        string tokenHash, string? replacedByHash = null, CancellationToken ct = default)
    {
        var token = await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);
        if (token is not null)
        {
            token.IsRevoked = true;
            token.ReplacedByTokenHash = replacedByHash;
            token.ReplacedAtUtc = DateTime.UtcNow;
            await _db.SaveChangesAsync(ct);
        }
    }

    public async Task RevokeByFamilyAsync(
        string familyId, CancellationToken ct = default)
    {
        var tokens = await _db.RefreshTokens
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToListAsync(ct);

        foreach (var token in tokens)
            token.IsRevoked = true;

        await _db.SaveChangesAsync(ct);
    }

    public async Task RevokeAllByUserAsync(
        string userId, CancellationToken ct = default)
    {
        var tokens = await _db.RefreshTokens
            .Where(t => t.UserId == userId && !t.IsRevoked)
            .ToListAsync(ct);

        foreach (var token in tokens)
            token.IsRevoked = true;

        await _db.SaveChangesAsync(ct);
    }
}
```

#### IPasswordResetStore — Recovery Token Control

If you want to enable password recovery, you need to implement this store to save the hashes of the temporary tokens.

```csharp
using Microsoft.EntityFrameworkCore;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

public class MyPasswordResetStore : IPasswordResetStore
{
    private readonly MyDbContext _db;
    public MyPasswordResetStore(MyDbContext db) => _db = db;

    // Store the hash of the generated token
    public async Task StoreAsync(PasswordResetEntry entry, CancellationToken ct)
    {
        _db.PasswordResets.Add(entry);
        await _db.SaveChangesAsync(ct);
    }

    // Find by hash
    public async ValueTask<PasswordResetEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)
    {
        return await _db.PasswordResets.FirstOrDefaultAsync(x => x.TokenHash == tokenHash, ct);
    }

    // Invalidate token after use
    public async Task MarkAsUsedAsync(string tokenHash, CancellationToken ct)
    {
        var entry = await _db.PasswordResets.FirstOrDefaultAsync(x => x.TokenHash == tokenHash, ct);
        if (entry != null) {
            entry.IsUsed = true;
            await _db.SaveChangesAsync(ct);
        }
    }

    // Count for Rate Limiting
    public async ValueTask<int> CountRecentRequestsAsync(string userId, DateTime since, CancellationToken ct)
    {
        return await _db.PasswordResets.CountAsync(x => x.UserId == userId && x.CreatedAtUtc > since, ct);
    }

    public async Task DeleteExpiredAsync(CancellationToken ct)
    {
        var expired = _db.PasswordResets.Where(x => x.ExpiresAtUtc < DateTime.UtcNow);
        _db.PasswordResets.RemoveRange(expired);
        await _db.SaveChangesAsync(ct);
    }
}
```

#### IResetTokenMailer — How to send the email

This is an **agnostic** interface. You decide whether to use SMTP, SendGrid, Amazon SES, etc. The library only gives you the user's email and the **raw token** (which is only visible at this moment).

```csharp
using SecureCore.Auth.Abstractions.Interfaces;

public class MyEmailMailer : IResetTokenMailer
{
    public Task SendResetEmailAsync(string toEmail, string rawToken, CancellationToken ct)
    {
        // IMPORTANT: Build here the link that will go to your frontend application
        var url = $"https://myapp.com/reset-password?token={rawToken}";
        
        // Real email sending logic goes here...
        Console.WriteLine($"[EMAIL] Sending to {toEmail}: Click here {url}");
        return Task.CompletedTask;
    }
}
```

---

### Step 3: Configure the library in Program.cs

Now that you have your Stores, you need to tell the application to use them:

```csharp
using SecureCore.Auth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// ─── 1. Register your Stores ───
// AddScoped means a new instance is created for each HTTP request
builder.Services.AddScoped<IUserStore, MyUserStore>();
builder.Services.AddScoped<ISessionStore, MySessionStore>();

// ─── 2. Register distributed cache ───
// In development you can use in-memory. In production, use Redis
builder.Services.AddDistributedMemoryCache(); // Development
// builder.Services.AddStackExchangeRedisCache(...); // Production

// ─── 3. Configure SecureCore Auth ───
builder.Services.AddSecureAuth(options =>
{
    // JWT — the "digital passport" for your users
    options.Jwt.Issuer = "myapp.com";           // Who issues the token?
    options.Jwt.Audience = "myapp-api";          // Who is it for?
    options.Jwt.SigningKey = builder.Configuration["Jwt:Key"]!; // Secret key (minimum 32 characters)

    // Token lifetimes
    options.Auth.AccessTokenLifetime = TimeSpan.FromMinutes(15);  // JWT lasts 15 min
    options.Auth.RefreshTokenLifetime = TimeSpan.FromDays(7);     // Refresh lasts 7 days

    // Brute-force protection
    options.Auth.MaxFailedAttempts = 5; // Lock after 5 attempts
})
.AddPasswordAuthentication();  // Enable email + password login

var app = builder.Build();

// ─── 4. Configure the HTTP request pipeline ───
// Order matters:
app.UseAuthentication();       // 1st — Reads the JWT from the Authorization header
app.UseSecureAuthValidation(); // 2nd — Verifies the session hasn't been revoked
app.UseAuthorization();        // 3rd — Checks permissions

// ─── 5. Map the authentication endpoints ───
app.MapSecureAuthEndpoints("/auth");
// This automatically creates:
//   POST /auth/login       — Log in
//   POST /auth/refresh     — Refresh token
//   POST /auth/logout      — Log out
//   POST /auth/revoke-all  — Close ALL sessions

app.Run();
```

### Step 4: Configure secrets

In `appsettings.json` (development only):

```json
{
  "Jwt": {
    "Key": "MySuperSecretKey_And_VeryLong_At_Least_32_Bytes!"
  }
}
```

> ⚠️ **In production**, use environment variables or a secrets service:
> ```bash
> export Jwt__Key="MyProductionSecretKey..."
> ```

---

## Use Cases: Step-by-Step Guide

### Use Case 1: Login with email and password

**Scenario**: A user enters their email and password in your app.

**What happens internally**:

```
User                       Your App                    SecureCore Auth
  │                          │                              │
  │─── POST /auth/login ────►│                              │
  │    email + password       │── SignInWithPasswordAsync ──►│
  │                          │                              │
  │                          │    1. Finds user by email     │
  │                          │    2. Checks if account locked│
  │                          │    3. Compares password (Argon2id)
  │                          │    4. If OK: generates JWT + Refresh Token
  │                          │    5. Saves session in ISessionStore
  │                          │    6. Resets failed attempts counter
  │                          │                              │
  │◄── 200 OK ──────────────│◄──── TokenResponse ──────────│
  │    accessToken           │                              │
  │    refreshToken          │                              │
  │    expiresAt             │                              │
```

**HTTP Request**:
```http
POST /auth/login
Content-Type: application/json

{
  "email": "maria@example.com",
  "password": "MySecure!Password123"
}
```

**Successful response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl...",
  "expiresAt": "2024-01-15T10:15:00Z"
}
```

**Invalid credentials response** (401):
```json
{
  "error": "invalid_credentials",
  "message": "The credentials provided are not valid."
}
```
> 💡 **Security note**: The system protects against **user enumeration** in two ways:
> 1. The error message is generic ("invalid credentials").
> 2. A constant-time verification is performed (`VerifyDummyPassword`). Even if the email doesn't exist, the server takes the same time to respond, preventing an attacker from using timing attacks to guess registered emails.

**Account locked response** (429):
```json
{
  "error": "account_locked",
  "message": "The account is temporarily locked. Please try again later."
}
```

---

### Use Case 2: Accessing a protected resource

**Scenario**: An authenticated user wants to view their profile.

After login, the user has an `accessToken`. They include it in the `Authorization` header of every request:

```http
GET /api/profile
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**How to create a protected endpoint**:

```csharp
// This endpoint is only accessible to authenticated users
app.MapGet("/api/profile", (HttpContext context) =>
{
    // The authentication middleware already verified the JWT
    // We can read the user's data from the token:
    var userId = context.User.FindFirst("sub")?.Value;
    var email = context.User.FindFirst("email")?.Value;

    return Results.Ok(new
    {
        message = "Welcome!",
        userId,
        email
    });
})
.RequireAuthorization(); // ← This ensures only authenticated users can access it
```

If the user has NO token or the token has expired, they'll automatically receive a `401 Unauthorized`.

---

### Use Case 3: Refreshing an expired token

**Scenario**: 15 minutes have passed and the JWT expired, but the user doesn't want to enter their password again.

Your frontend app detects the JWT has expired (via `expiresAt`) and uses the Refresh Token to get new tokens:

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl..."
}
```

**What happens internally**:

```
1. The Refresh Token is looked up by its SHA-256 hash
2. It's verified that it's NOT revoked or expired
3. The current token is INVALIDATED (can't be used again)
4. A NEW pair of tokens is generated (JWT + Refresh Token)
5. The new Refresh Token inherits the "FamilyId" from the old one
```

**Response** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...(new)...",
  "refreshToken": "bnVldk9UZXh0by1yZWZyZXNo...(new)...",
  "expiresAt": "2024-01-15T10:30:00Z"
}
```

> 🔒 **What if someone steals an old Refresh Token and tries to use it?**
> The library detects the reuse, revokes the **ENTIRE family** of tokens (for that device), and emits a `SuspiciousActivityDetected` event. This is called **Refresh Token Rotation (RTR)**.

---

### Use Case 4: Logging out

**Scenario**: The user clicks "Log out" on their device.

```http
POST /auth/logout
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json

{
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl..."
}
```

This invalidates the specific Refresh Token for that device. The JWT will remain valid until it expires (max 15 min), but it cannot be refreshed.

---

### Use Case 5: Close ALL sessions ("Panic Button")

**Scenario**: The user suspects someone accessed their account from another device. They want to log out everywhere immediately.

```http
POST /auth/revoke-all
Authorization: Bearer eyJhbGciOi...
```

**What happens internally**:

```
1. A new SecurityStamp (random GUID) is generated for the user
2. The cache entry for the previous stamp is invalidated
3. ALL of the user's Refresh Tokens are revoked
4. Result: ALL active JWTs will fail on the next request
   (because the middleware compares the JWT's "ssv" with the current SecurityStamp)
```

> 💡 Revocation is **instantaneous** thanks to the `UseSecureAuthValidation()` middleware that verifies the SecurityStamp on every request.

---

### Use Case 6: Brute-force protection

**Scenario**: An attacker tries to guess a user's password.

You don't need to do anything — protection is automatic:

```
Attempt 1: ❌ Wrong password (counter: 1)
Attempt 2: ❌ Wrong password (counter: 2)
Attempt 3: ❌ Wrong password (counter: 3)
Attempt 4: ❌ Wrong password (counter: 4)
Attempt 5: ❌ LOCKED! 🔒 (1 minute)
<< 1 minute later >>
Attempt 6-10: ❌ LOCKED! 🔒 (5 minutes)
<< 5 minutes later >>
Attempt 11-15: ❌ LOCKED! 🔒 (15 minutes)
<< 15 minutes later >>
Attempt 16+: ❌ LOCKED! 🔒 (1 hour)
```

Durations are configurable:

```csharp
options.Auth.MaxFailedAttempts = 5;
options.Auth.LockoutDurations = new[]
{
    TimeSpan.FromMinutes(1),
    TimeSpan.FromMinutes(5),
    TimeSpan.FromMinutes(15),
    TimeSpan.FromHours(1)
};
```

---

### Case 7: External Login (Google, GitHub, OAuth)

**Scenario**: You want to allow your users to log in with their Google or GitHub accounts.

**Implementation**:

1. **Configure ASP.NET Core**: Use the standard Microsoft packages (`Microsoft.AspNetCore.Authentication.Google`, etc.).
2. **Provider Callback**: In your callback controller, once the user is externally authenticated, you use `IdentityOrchestrator` to generate the SecureCore tokens.

```csharp
[HttpGet("callback-google")]
public async Task<IResult> GoogleCallback(IdentityOrchestrator orchestrator)
{
    // 1. Get the external authentication information from ASP.NET Core
    var authResult = await HttpContext.AuthenticateAsync("Google");
    
    if (!authResult.Succeeded) return Results.Unauthorized();

    // 2. Extract the provider's unique ID (Subject)
    var providerKey = authResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
    var provider = "Google";

    // 3. Let SecureCore orchestrate the login
    // It will check if the user is already linked and generate JWT + Refresh Token
    var (result, tokens) = await orchestrator.SignInExternalAsync(provider, providerKey);

    if (result.Succeeded) return Results.Ok(tokens);
    
    // If the user doesn't exist, you can redirect them to a registration page
    // or create them automatically using the email from Google's claims.
    return Results.BadRequest(new { error = "user_not_found" });
}
```

---

### Use Case 8: Password Reset (Forgot your password?)

**Scenario**: A user has forgotten their password and wants to recover it safely.

**Security Flow**:

1.  **Request**: The user submits their email. The server always responds with "If the email exists, you will receive instructions," avoiding confirmation of whether the account exists (anti-enumeration).
2.  **Opaque Token**: A cryptographic random token (CSPRNG) is generated. Only its **SHA-256 hash** is saved in the database. Even if your database is breached, the tokens are useless to an attacker.
3.  **Confirmation**: The user receives the token via email and submits it along with their new password.
4.  **Global Cleanup**: Upon successfully changing the password, the system invokes `RevokeAllSessions`, logging out all other devices for immediate security.

**Request 1: Request recovery**
```http
POST /auth/forgot-password
{ "email": "user@example.com" }
```

**Request 2: Set new password**
```http
POST /auth/reset-password
{ 
  "token": "TOKEN_RECEIVED_IN_EMAIL",
  "newPassword": "NewSuperSecurePassword"
}
```

---

## Advanced Features

### Passkeys / WebAuthn

Passkeys allow users to log in **without a password**, using their device's biometrics.

#### Enabling them

```csharp
builder.Services.AddSecureAuth(options => { /* ... */ })
    .AddPasswordAuthentication()
    .AddWebAuthn(webauthn =>
    {
        webauthn.RelyingPartyName = "My App";      // Name visible to the user
        webauthn.RelyingPartyId = "myapp.com";      // Your domain
        webauthn.Origins = new() { "https://myapp.com" };
    });
```

#### Registering a Passkey (2 steps)

**Step 1** — The server generates a "challenge":
```csharp
// Your API endpoint
app.MapPost("/api/passkeys/register/begin", async (
    PasskeyService passkeyService,
    HttpContext ctx) =>
{
    var userId = ctx.User.FindFirst("sub")!.Value;
    var user = await userStore.FindByIdAsync(userId);

    // Generates a cryptographic challenge that the device must sign
    var options = await passkeyService.BeginRegistrationAsync(user!);

    // Save the options in session to verify later
    ctx.Session.SetString("fido2.register", options.ToJson());

    return Results.Ok(options);
});
```

**Step 2** — The device responds and the server verifies:
```csharp
app.MapPost("/api/passkeys/register/complete", async (
    AuthenticatorAttestationRawResponse response,
    PasskeyService passkeyService,
    HttpContext ctx) =>
{
    var optionsJson = ctx.Session.GetString("fido2.register");
    var options = CredentialCreateOptions.FromJson(optionsJson);
    var userId = ctx.User.FindFirst("sub")!.Value;

    // Verifies the authenticator's response and stores the public key
    var credential = await passkeyService.CompleteRegistrationAsync(
        response, options, userId, "My iPhone");

    return credential is not null
        ? Results.Ok(new { message = "Passkey registered!" })
        : Results.BadRequest(new { error = "Verification failed" });
});
```

#### Passkey Login (2 steps)

**Step 1** — Generate assertion options:
```csharp
app.MapPost("/api/passkeys/login/begin", async (
    PasskeyService passkeyService) =>
{
    // null = Discoverable Credentials (the authenticator chooses which credential to use)
    var options = await passkeyService.BeginAssertionAsync(null);
    return Results.Ok(options);
});
```

**Step 2** — Verify the signature:
```csharp
app.MapPost("/api/passkeys/login/complete", async (
    AuthenticatorAssertionRawResponse response,
    PasskeyService passkeyService,
    ITokenService tokenService,
    HttpContext ctx) =>
{
    var optionsJson = ctx.Session.GetString("fido2.login");
    var options = AssertionOptions.FromJson(optionsJson);

    // Verifies the signature is valid and returns the user
    var user = await passkeyService.CompleteAssertionAsync(response, options);

    if (user is null)
        return Results.Unauthorized();

    // Generate tokens just like with password login
    var tokens = await tokenService.GenerateTokenPairAsync(user);
    return Results.Ok(tokens);
});
```

---

### Domain Events (Observability)

SecureCore Auth emits events every time something important happens. You can capture them to:

- **Send alerts** when suspicious activity is detected
- **Log audits** of who logged in and when
- **Send emails** when sessions are closed on all devices
- **Metrics** for monitoring (Prometheus, DataDog, etc.)

#### Available events

| Event | When it fires | Use case |
|-------|--------------|----------|
| `LoginSuccess` | Successful login | Log time and IP of login |
| `LoginFailed` | Wrong password | Detect intrusion attempts |
| `AccountLockedOut` | Account locked | Notify user by email |
| `TokenRotated` | Refresh Token renewed | Session auditing |
| `GlobalLogout` | All sessions closed | Security email to user |
| `SuspiciousActivityDetected` | Revoked token reuse | SECURITY ALERT! |
| `PasskeyRegistered` | New passkey registered | Confirmation to user |
| `PasskeyLoginSuccess` | Passkey login | Log access method |
| `Logout` | Individual logout | Auditing |
| `PasswordResetRequested` | Reset request initiated | Optional secondary email notification |
| `PasswordResetCompleted` | Password changed successfully | Security notification |

#### Implementing a custom handler

```csharp
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

// This handler executes every time an authentication event occurs
public class MyEventHandler : IAuthEventHandler
{
    private readonly IEmailService _emailService; // Your email service
    private readonly ILogger<MyEventHandler> _logger;

    public MyEventHandler(IEmailService emailService, ILogger<MyEventHandler> logger)
    {
        _emailService = emailService;
        _logger = logger;
    }

    public async Task HandleAsync(AuthEvent authEvent, CancellationToken ct)
    {
        switch (authEvent.EventType)
        {
            // When a potential attack is detected:
            case AuthEventType.SuspiciousActivityDetected:
                _logger.LogCritical(
                    "🚨 Suspicious activity for user {UserId}", authEvent.UserId);
                await _emailService.SendAlertAsync(authEvent.UserId,
                    "Suspicious activity was detected on your account. " +
                    "All your sessions have been closed for security.");
                break;

            // When the user closes all sessions:
            case AuthEventType.GlobalLogout:
                await _emailService.SendConfirmationAsync(authEvent.UserId,
                    "You have been logged out from all devices.");
                break;

            // Log all logins for auditing:
            case AuthEventType.LoginSuccess:
                _logger.LogInformation(
                    "Successful login: user {UserId}, IP: {IP}",
                    authEvent.UserId,
                    authEvent.Metadata?.GetValueOrDefault("ip", "unknown"));
                break;
        }
    }
}

// Register the handler in Program.cs:
builder.Services.AddTransient<IAuthEventHandler, MyEventHandler>();
```

---

## Full Configuration Reference

```csharp
builder.Services.AddSecureAuth(options =>
{
    // ═══ JWT ═══
    options.Jwt.Issuer = "myapp.com";        // Token issuer
    options.Jwt.Audience = "myapp-api";       // Token audience
    options.Jwt.SigningKey = "...";            // Signing key (REQUIRED: min 32 chars)
    options.Jwt.Algorithm = "HS256";           // Signing algorithm (default)

    // ═══ Session tokens ═══
    options.Auth.AccessTokenLifetime = TimeSpan.FromMinutes(15);  // JWT lifetime
    options.Auth.RefreshTokenLifetime = TimeSpan.FromDays(7);     // Refresh lifetime
    options.Auth.GracePeriodSeconds = 30;      // Tolerance for duplicate submissions
    options.Auth.ClockSkew = TimeSpan.FromMinutes(5); // Clock tolerance

    // ═══ Brute-force protection ═══
    options.Auth.MaxFailedAttempts = 5;
    options.Auth.LockoutDurations = new[]      // Exponential escalation
    {
        TimeSpan.FromMinutes(1),   // 1st lockout
        TimeSpan.FromMinutes(5),   // 2nd lockout
        TimeSpan.FromMinutes(15),  // 3rd lockout
        TimeSpan.FromHours(1)      // 4th+ lockout
    };

    // ═══ SecurityStamp cache ═══
    options.Auth.SecurityStampCacheDuration = TimeSpan.FromMinutes(5);

    // ═══ Argon2 Password Hashing ═══
    options.Argon2.MemorySize = 65536;  // 64 MB of RAM per hash
    options.Argon2.Iterations = 3;       // 3 passes
    options.Argon2.Parallelism = 4;      // 4 parallel threads

    // ═══ Password Reset ═══
    // options.AddPasswordReset(reset => { ... }); // Use the builder
});

// Extended Reset Configuration (via .AddPasswordReset)
builder.Services.AddSecureAuth(...)
    .AddPasswordReset(reset => 
    {
        reset.TokenLifetimeMinutes = 15; // Token expiration
        reset.TokenSizeBytes = 32;       // Token security
        reset.MaxRequestsPerHour = 3;    // Rate limiting per user
    });
```

---

## Sample Project

The repository includes a complete sample API in `samples/SampleApi/` that you can run immediately:

```bash
dotnet run --project samples/SampleApi
```

Open `http://localhost:5000/swagger` to explore the endpoints interactively.

**The pre-loaded test user is**:
- Email: `demo@securecore.dev`
- Password: `P@ssw0rd123!`
