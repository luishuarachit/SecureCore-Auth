# SecureCore Auth Framework

## ¿Qué es SecureCore Auth?

SecureCore Auth es una **librería de autenticación y autorización** para aplicaciones web escritas en C# con ASP.NET Core. Si vienes de otros lenguajes, piensa en ella como el equivalente a:

- **Passport.js** en Node.js
- **Django Auth** en Python
- **Devise** en Ruby on Rails
- **Spring Security** en Java

Pero con un enfoque moderno centrado en seguridad: **Passkeys**, rotación automática de tokens, y protección contra ataques comunes.

### ¿Qué problemas resuelve?

Cuando construyes una aplicación web, necesitas que los usuarios:

1. **Se registren** con un email y contraseña (o con Passkeys)
2. **Inicien sesión** de forma segura
3. **Se mantengan autenticados** sin tener que ingresar su contraseña en cada petición
4. **Cierren sesión** en un dispositivo o en todos a la vez
5. **Estén protegidos** contra ataques de fuerza bruta, robo de tokens, etc.

SecureCore Auth implementa todo esto siguiendo las mejores prácticas de seguridad de OWASP, sin que tú tengas que ser un experto en criptografía.

### Arquitectura: ¿Cómo está organizada?

La librería se divide en 4 paquetes que puedes usar según necesites:

```
┌──────────────────────────────────────────────────────────┐
│              Tu Aplicación (API o WebApp)                 │
├──────────────────────────────────────────────────────────┤
│     SecureCore.Auth.AspNetCore  (Integración)            │
│     Fluent API · Middleware · Endpoints listos            │
├──────────────────────────────────────────────────────────┤
│  SecureCore.Auth.Core    │  SecureCore.Auth.WebAuthn     │
│  Contraseñas · JWT       │  Passkeys · FIDO2             │
│  Sesiones · Bloqueo      │                               │
├──────────────────────────────────────────────────────────┤
│           SecureCore.Auth.Abstractions                    │
│           Interfaces · Modelos · Contratos                │
└──────────────────────────────────────────────────────────┘
```

- **Abstractions**: Define las "reglas del juego" — interfaces que tú implementas para conectar tu base de datos.
- **Core**: La lógica de autenticación — hashing de contraseñas, tokens JWT, manejo de sesiones.
- **WebAuthn**: Soporte para Passkeys (autenticación sin contraseña).
- **AspNetCore**: La integración con ASP.NET Core — todo lo que necesitas para conectar la librería con tu app.

---

## Conceptos Fundamentales

Antes de empezar, repasemos algunos conceptos clave. Si ya los conoces, salta a la sección [Inicio Rápido](#inicio-rápido).

### ¿Qué es un JWT?

Un **JWT** (JSON Web Token) es como un "pase de acceso" digital. Cuando un usuario inicia sesión correctamente, el servidor le entrega un JWT que dice "este usuario es quien dice ser". El usuario incluye este token en cada petición posterior para demostrar su identidad sin tener que enviar su contraseña cada vez.

```
Analogía del mundo real:
Imagina que vas a un hotel. En recepción te dan una tarjeta magnética (JWT).
Con esa tarjeta abres tu habitación sin mostrar tu pasaporte cada vez.
La tarjeta tiene una fecha de expiración y solo funciona en tu habitación.
```

### ¿Qué es un Refresh Token?

El JWT tiene una vida corta (15 minutos por defecto). Cuando expira, en lugar de pedirle al usuario que vuelva a iniciar sesión, usamos un **Refresh Token** — un token de larga duración que permite obtener un nuevo JWT sin contraseña.

```
Analogía:
Tu tarjeta del hotel expira cada día a las 12:00.
Pero tienes un cupón (Refresh Token) que te permite ir a recepción
y pedir una nueva tarjeta sin mostrar tu pasaporte de nuevo.
El cupón dura toda la semana (7 días).
```

### ¿Qué son los Passkeys?

Los **Passkeys** son una forma moderna de autenticación que reemplaza a las contraseñas. Usan la biometría de tu dispositivo (huella dactilar, Face ID) o una llave de seguridad USB. Son inmunes a phishing y no pueden ser robados de una base de datos porque la clave privada nunca sale del dispositivo del usuario.

### ¿Qué es el patrón Store?

SecureCore Auth **no sabe cómo guardas tus datos**. No importa si usas PostgreSQL, MongoDB, Redis o un archivo de texto. La librería define interfaces (contratos) que tú implementas para conectarla con tu sistema de almacenamiento. Esto se llama "inversión de dependencias" y te da total libertad.

---

## Inicio Rápido

### Requisitos previos

- **.NET 8 SDK** o superior instalado ([descargar aquí](https://dotnet.microsoft.com/download))
- Un editor de código (VS Code, Visual Studio, Rider, etc.)
- Una aplicación ASP.NET Core existente o una nueva

Si no tienes una aplicación, crea una con:
```bash
dotnet new webapi -o MiApp
cd MiApp
```

### Paso 1: Instalar el paquete

```bash
dotnet add package SecureCore.Auth.AspNetCore
```

Esto instala todo lo necesario (Abstractions, Core, WebAuthn se incluyen como dependencias transitivas).

### Paso 2: Implementar los Stores (conectar tu base de datos)

Este es el paso más importante: **le dices a la librería cómo acceder a tus datos**. Necesitas implementar al menos 2 interfaces.

#### IUserStore — Dónde están los usuarios

Esta interfaz le dice a la librería cómo buscar, crear y modificar usuarios. Aquí tienes un ejemplo completo usando Entity Framework Core (el ORM más popular de .NET):

```csharp
using Microsoft.EntityFrameworkCore;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;

// Esta clase conecta SecureCore Auth con tu base de datos de usuarios.
// Solo necesitas implementar los métodos que la librería requiere.
public class MiUserStore : IUserStore
{
    private readonly MiDbContext _db; // Tu contexto de Entity Framework

    public MiUserStore(MiDbContext db)
    {
        _db = db;
    }

    // Buscar un usuario por su ID único
    // Se usa internamente cuando la librería necesita cargar un usuario
    // (por ejemplo, al renovar un token o validar una sesión)
    public async ValueTask<UserIdentity?> FindByIdAsync(
        string userId, CancellationToken ct = default)
    {
        return await _db.Users.FindAsync([userId], ct);
    }

    // Buscar un usuario por su email
    // Se usa durante el login: el usuario escribe su email y la librería
    // busca si existe en la base de datos
    public async ValueTask<UserIdentity?> FindByEmailAsync(
        string email, CancellationToken ct = default)
    {
        return await _db.Users
            .FirstOrDefaultAsync(u => u.Email == email.ToLower(), ct);
    }

    // Buscar por proveedor externo (Google, GitHub, etc.)
    // Si no usas login social, puedes retornar null
    public ValueTask<UserIdentity?> FindByExternalProviderAsync(
        string provider, string providerKey, CancellationToken ct = default)
    {
        return ValueTask.FromResult<UserIdentity?>(null);
    }

    // Actualizar el SecurityStamp
    // Esto se llama cuando el usuario cierra TODAS sus sesiones
    // o cuando cambia su contraseña
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

    // Obtener el SecurityStamp actual
    // Se usa para verificar si las sesiones del usuario siguen siendo válidas
    public async ValueTask<string?> GetSecurityStampAsync(
        string userId, CancellationToken ct = default)
    {
        var user = await _db.Users.FindAsync([userId], ct);
        return user?.SecurityStamp;
    }

    // Incrementar el contador de intentos fallidos de login
    // Sirve para bloquear la cuenta después de N intentos incorrectos
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

    // Resetear el contador cuando el login es exitoso
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

    // Establecer hasta cuándo está bloqueada la cuenta
    // Null = desbloqueada. Una fecha futura = bloqueada hasta esa fecha
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

#### ISessionStore — Dónde se guardan las sesiones

Esta interfaz gestiona los Refresh Tokens (las "sesiones" del usuario). Cada vez que un usuario inicia sesión, se crea una entrada aquí.

```csharp
using Microsoft.EntityFrameworkCore;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

public class MiSessionStore : ISessionStore
{
    private readonly MiDbContext _db;

    public MiSessionStore(MiDbContext db) => _db = db;

    // Guardar un nuevo Refresh Token
    // Se llama cada vez que un usuario inicia sesión o renueva su token
    public async Task CreateAsync(RefreshTokenEntry entry, CancellationToken ct = default)
    {
        _db.RefreshTokens.Add(entry);
        await _db.SaveChangesAsync(ct);
    }

    // Buscar un token por su hash
    // IMPORTANTE: nunca guardamos el token en texto plano, solo su hash SHA-256
    // Es como guardar el hash de una contraseña en vez de la contraseña
    public async ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(
        string tokenHash, CancellationToken ct = default)
    {
        return await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);
    }

    // Revocar (invalidar) un token específico
    // Se llama cuando el usuario cierra sesión o cuando se rota el token
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

    // Revocar TODOS los tokens de una "familia"
    // Una familia es una cadena de tokens rotados. Si alguien intenta
    // reusar un token viejo, se revocan TODOS como medida de seguridad
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

    // Revocar TODAS las sesiones de un usuario
    // Se usa con el "botón de pánico" para cerrar todas las sesiones
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

### Paso 3: Configurar la librería en Program.cs

Ahora que tienes tus Stores, necesitas decirle a la aplicación que los use:

```csharp
using SecureCore.Auth.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// ─── 1. Registrar tus Stores ───
// AddScoped significa que se crea una nueva instancia por cada petición HTTP
builder.Services.AddScoped<IUserStore, MiUserStore>();
builder.Services.AddScoped<ISessionStore, MiSessionStore>();

// ─── 2. Registrar caché distribuida ───
// En desarrollo puedes usar memoria. En producción, usa Redis
builder.Services.AddDistributedMemoryCache(); // Desarrollo
// builder.Services.AddStackExchangeRedisCache(...); // Producción

// ─── 3. Configurar SecureCore Auth ───
builder.Services.AddSecureAuth(options =>
{
    // JWT — el "pasaporte digital" de tus usuarios
    options.Jwt.Issuer = "miapp.com";           // ¿Quién emite el token?
    options.Jwt.Audience = "miapp-api";          // ¿Para quién es?
    options.Jwt.SigningKey = builder.Configuration["Jwt:Key"]!; // Clave secreta (mínimo 32 caracteres)

    // Tiempos de vida de los tokens
    options.Auth.AccessTokenLifetime = TimeSpan.FromMinutes(15);  // JWT dura 15 min
    options.Auth.RefreshTokenLifetime = TimeSpan.FromDays(7);     // Refresh Token dura 7 días

    // Protección contra fuerza bruta
    options.Auth.MaxFailedAttempts = 5; // Bloquear tras 5 intentos
})
.AddPasswordAuthentication();  // Habilitar login con email + contraseña

var app = builder.Build();

// ─── 4. Configurar el pipeline de peticiones HTTP ───
// El orden importa:
app.UseAuthentication();       // 1° — Lee el JWT del header Authorization
app.UseSecureAuthValidation(); // 2° — Verifica que la sesión no esté revocada
app.UseAuthorization();        // 3° — Verifica permisos

// ─── 5. Mapear los endpoints de autenticación ───
app.MapSecureAuthEndpoints("/auth");
// Esto crea automáticamente:
//   POST /auth/login       — Iniciar sesión
//   POST /auth/refresh     — Renovar token
//   POST /auth/logout      — Cerrar sesión
//   POST /auth/revoke-all  — Cerrar TODAS las sesiones

app.Run();
```

### Paso 4: Configurar secretos

En `appsettings.json` (solo para desarrollo):

```json
{
  "Jwt": {
    "Key": "MiClaveSuperSecreta_Y_MuyLarga_De_Al_Menos_32_Bytes!"
  }
}
```

> ⚠️ **En producción**, usa variables de entorno o un servicio de secretos:
> ```bash
> export Jwt__Key="MiClaveSecretaDeProduccion..."
> ```

---

## Casos de Uso: Guía Paso a Paso

### Caso 1: Login con email y contraseña

**Escenario**: Un usuario ingresa su email y contraseña en tu app.

**Lo que pasa internamente**:

```
Usuario                    Tu App                     SecureCore Auth
  │                          │                              │
  │─── POST /auth/login ────►│                              │
  │    email + password       │── SignInWithPasswordAsync ──►│
  │                          │                              │
  │                          │    1. Busca usuario por email │
  │                          │    2. Verifica si está bloqueado
  │                          │    3. Compara contraseña (Argon2id)
  │                          │    4. Si OK: genera JWT + Refresh Token
  │                          │    5. Guarda sesión en ISessionStore
  │                          │    6. Resetea contador de fallos
  │                          │                              │
  │◄── 200 OK ──────────────│◄──── TokenResponse ──────────│
  │    accessToken           │                              │
  │    refreshToken          │                              │
  │    expiresAt             │                              │
```

**Petición HTTP**:
```http
POST /auth/login
Content-Type: application/json

{
  "email": "maria@ejemplo.com",
  "password": "MiContraseña!Segura123"
}
```

**Respuesta exitosa** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl...",
  "expiresAt": "2024-01-15T10:15:00Z"
}
```

**Respuesta con credenciales inválidas** (401):
```json
{
  "error": "invalid_credentials",
  "message": "Las credenciales proporcionadas no son válidas."
}
```
> 💡 **Nota de seguridad**: El sistema protege contra la **enumeración de usuarios** de dos formas:
> 1. El mensaje de error es genérico ("credenciales inválidas").
> 2. Se realiza una verificación de tiempo constante (`VerifyDummyPassword`). Aunque el email no exista, el servidor tarda lo mismo en responder, evitando que un atacante use ataques de tiempo para adivinar emails registrados.

**Respuesta con cuenta bloqueada** (429):
```json
{
  "error": "account_locked",
  "message": "La cuenta está temporalmente bloqueada. Intente más tarde."
}
```

---

### Caso 2: Acceder a un recurso protegido

**Escenario**: Un usuario autenticado quiere ver su perfil.

Después del login, el usuario tiene un `accessToken`. Lo incluye en el header `Authorization` de cada petición:

```http
GET /api/perfil
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Cómo crear un endpoint protegido**:

```csharp
// Este endpoint solo es accesible para usuarios autenticados
app.MapGet("/api/perfil", (HttpContext context) =>
{
    // El middleware de autenticación ya verificó el JWT
    // Podemos leer los datos del usuario desde el token:
    var userId = context.User.FindFirst("sub")?.Value;
    var email = context.User.FindFirst("email")?.Value;

    return Results.Ok(new
    {
        mensaje = "¡Bienvenido!",
        userId,
        email
    });
})
.RequireAuthorization(); // ← Esto hace que solo los usuarios autenticados puedan acceder
```

Si el usuario NO tiene token o el token expiró, recibirá automáticamente un `401 Unauthorized`.

---

### Caso 3: Renovar un token expirado

**Escenario**: Han pasado 15 minutos y el JWT expiró, pero el usuario no quiere volver a ingresar su contraseña.

Tu aplicación frontend detecta que el JWT expiró (por el `expiresAt`) y usa el Refresh Token para obtener nuevos tokens:

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl..."
}
```

**Lo que pasa internamente**:

```
1. Se busca el Refresh Token por su hash SHA-256
2. Se verifica que NO esté revocado ni expirado
3. Se INVALIDA el token actual (ya no se puede usar más)
4. Se genera un NUEVO par de tokens (JWT + Refresh Token)
5. El nuevo Refresh Token hereda el "FamilyId" del anterior
```

**Respuesta** (200 OK):
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...(nuevo)...",
  "refreshToken": "bnVldk9UZXh0by1yZWZyZXNo...(nuevo)...",
  "expiresAt": "2024-01-15T10:30:00Z"
}
```

> 🔒 **¿Qué pasa si alguien roba un Refresh Token antiguo y trata de usarlo?**
> La librería detecta el reuso, revoca **TODA la familia** de tokens (para ese dispositivo) y emite un evento `SuspiciousActivityDetected`. Esto se llama **Refresh Token Rotation (RTR)**.

---

### Caso 4: Cerrar sesión

**Escenario**: El usuario presiona "Cerrar sesión" en su dispositivo.

```http
POST /auth/logout
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json

{
  "refreshToken": "dGVzdC1yZWZyZXNoLXRva2VuLXZhbHVl..."
}
```

Esto invalida el Refresh Token específico de ese dispositivo. El JWT seguirá siendo válido hasta que expire (máx. 15 min), pero no podrá renovarse.

---

### Caso 5: Cerrar TODAS las sesiones ("Botón de Pánico")

**Escenario**: El usuario sospecha que alguien accedió a su cuenta desde otro dispositivo. Quiere cerrar sesión en TODAS partes inmediatamente.

```http
POST /auth/revoke-all
Authorization: Bearer eyJhbGciOi...
```

**Lo que pasa internamente**:

```
1. Se genera un nuevo SecurityStamp (un GUID aleatorio) para el usuario
2. Se invalida la entrada de caché del stamp anterior
3. Se revocan TODOS los Refresh Tokens del usuario
4. Resultado: TODOS los JWT activos fallarán en la siguiente petición
   (porque el middleware compara el "ssv" del JWT con el SecurityStamp actual)
```

> 💡 La revocación es **instantánea** gracias al middleware `UseSecureAuthValidation()` que verifica el SecurityStamp en cada petición.

---

### Caso 6: Protección contra fuerza bruta

**Escenario**: Un atacante intenta adivinar la contraseña de un usuario.

No necesitas hacer nada — la protección es automática:

```
Intento 1: ❌ Contraseña incorrecta (contador: 1)
Intento 2: ❌ Contraseña incorrecta (contador: 2)
Intento 3: ❌ Contraseña incorrecta (contador: 3)
Intento 4: ❌ Contraseña incorrecta (contador: 4)
Intento 5: ❌ ¡BLOQUEADO! 🔒 (1 minuto)
<< 1 minuto después >>
Intento 6-10: ❌ ¡BLOQUEADO! 🔒 (5 minutos)
<< 5 minutos después >>
Intento 11-15: ❌ ¡BLOQUEADO! 🔒 (15 minutos)
<< 15 minutos después >>
Intento 16+: ❌ ¡BLOQUEADO! 🔒 (1 hora)
```

Las duraciones son configurables:

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

### Caso 7: Inicio de sesión externo (Google, GitHub, OAuth)

**Escenario**: Quieres permitir que tus usuarios inicien sesión con sus cuentas de Google o GitHub.

**Implementación**:

1. **Configurar ASP.NET Core**: Usa los paquetes estándar de Microsoft (`Microsoft.AspNetCore.Authentication.Google`, etc.).
2. **Callback del Proveedor**: En tu controlador de callback, una vez que el usuario está autenticado externamente, usas `IdentityOrchestrator` para generar los tokens de SecureCore.

```csharp
[HttpGet("callback-google")]
public async Task<IResult> GoogleCallback(IdentityOrchestrator orchestrator)
{
    // 1. Obtener la información de la autenticación externa de ASP.NET Core
    var authResult = await HttpContext.AuthenticateAsync("Google");
    
    if (!authResult.Succeeded) return Results.Unauthorized();

    // 2. Extraer el ID único del proveedor (Subject)
    var providerKey = authResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier);
    var provider = "Google";

    // 3. Dejar que SecureCore orqueste el login
    // Buscará si el usuario ya está vinculado y generará JWT + Refresh Token
    var (result, tokens) = await orchestrator.SignInExternalAsync(provider, providerKey);

    if (result.Succeeded) return Results.Ok(tokens);
    
    // Si el usuario no existe, puedes redirigirlo a una página de registro
    // o crearlo automáticamente usando el correo de los claims de Google.
    return Results.BadRequest(new { error = "user_not_found" });
}
```

---

## Funcionalidades Avanzadas

### Passkeys / WebAuthn

Las Passkeys permiten que los usuarios inicien sesión **sin contraseña**, usando la biometría de su dispositivo.

#### Habilitarlas

```csharp
builder.Services.AddSecureAuth(options => { /* ... */ })
    .AddPasswordAuthentication()
    .AddWebAuthn(webauthn =>
    {
        webauthn.RelyingPartyName = "Mi App";     // Nombre visible al usuario
        webauthn.RelyingPartyId = "miapp.com";     // Tu dominio
        webauthn.Origins = new() { "https://miapp.com" };
    });
```

#### Registrar una Passkey (2 pasos)

**Paso 1** — El servidor genera un "desafío":
```csharp
// Tu endpoint de API
app.MapPost("/api/passkeys/register/begin", async (
    PasskeyService passkeyService,
    HttpContext ctx) =>
{
    var userId = ctx.User.FindFirst("sub")!.Value;
    var user = await userStore.FindByIdAsync(userId);

    // Genera un desafío criptográfico que el dispositivo debe firmar
    var options = await passkeyService.BeginRegistrationAsync(user!);

    // Guarda las opciones en sesión para verificar después
    ctx.Session.SetString("fido2.register", options.ToJson());

    return Results.Ok(options);
});
```

**Paso 2** — El dispositivo responde y el servidor verifica:
```csharp
app.MapPost("/api/passkeys/register/complete", async (
    AuthenticatorAttestationRawResponse response,
    PasskeyService passkeyService,
    HttpContext ctx) =>
{
    var optionsJson = ctx.Session.GetString("fido2.register");
    var options = CredentialCreateOptions.FromJson(optionsJson);
    var userId = ctx.User.FindFirst("sub")!.Value;

    // Verifica la respuesta del autenticador y guarda la clave pública
    var credential = await passkeyService.CompleteRegistrationAsync(
        response, options, userId, "Mi iPhone");

    return credential is not null
        ? Results.Ok(new { message = "¡Passkey registrada!" })
        : Results.BadRequest(new { error = "La verificación falló" });
});
```

#### Login con Passkey (2 pasos)

**Paso 1** — Generar opciones de aserción:
```csharp
app.MapPost("/api/passkeys/login/begin", async (
    PasskeyService passkeyService) =>
{
    // null = Discoverable Credentials (el autenticador elige qué credencial usar)
    var options = await passkeyService.BeginAssertionAsync(null);
    return Results.Ok(options);
});
```

**Paso 2** — Verificar la firma:
```csharp
app.MapPost("/api/passkeys/login/complete", async (
    AuthenticatorAssertionRawResponse response,
    PasskeyService passkeyService,
    ITokenService tokenService,
    HttpContext ctx) =>
{
    var optionsJson = ctx.Session.GetString("fido2.login");
    var options = AssertionOptions.FromJson(optionsJson);

    // Verifica que la firma sea válida y retorna el usuario
    var user = await passkeyService.CompleteAssertionAsync(response, options);

    if (user is null)
        return Results.Unauthorized();

    // Generar tokens igual que en login con contraseña
    var tokens = await tokenService.GenerateTokenPairAsync(user);
    return Results.Ok(tokens);
});
```

---

### Eventos de Dominio (Observabilidad)

SecureCore Auth emite eventos cada vez que algo importante sucede. Puedes capturarlos para:

- **Enviar alertas** cuando se detecta actividad sospechosa
- **Registrar auditoría** de quién inició sesión y cuándo
- **Enviar emails** cuando se cierra sesión en todos los dispositivos
- **Métricas** para monitoreo (Prometheus, DataDog, etc.)

#### Eventos disponibles

| Evento | Cuándo se dispara | Caso de uso |
|--------|-------------------|-------------|
| `LoginSuccess` | Login exitoso | Registrar hora y IP del login |
| `LoginFailed` | Contraseña incorrecta | Detectar intentos de intrusión |
| `AccountLockedOut` | Cuenta bloqueada | Notificar al usuario por email |
| `TokenRotated` | Refresh Token renovado | Auditoría de sesiones |
| `GlobalLogout` | Todas las sesiones cerradas | Email de seguridad al usuario |
| `SuspiciousActivityDetected` | Reuso de token revocado | ¡ALERTA DE SEGURIDAD! |
| `PasskeyRegistered` | Nueva passkey registrada | Confirmación al usuario |
| `PasskeyLoginSuccess` | Login con passkey | Registro de método de acceso |
| `Logout` | Cierre de sesión individual | Auditoría |

#### Implementar un handler personalizado

```csharp
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;

// Este handler se ejecuta cada vez que ocurre un evento de autenticación
public class MiEventHandler : IAuthEventHandler
{
    private readonly IEmailService _emailService; // Tu servicio de emails
    private readonly ILogger<MiEventHandler> _logger;

    public MiEventHandler(IEmailService emailService, ILogger<MiEventHandler> logger)
    {
        _emailService = emailService;
        _logger = logger;
    }

    public async Task HandleAsync(AuthEvent evento, CancellationToken ct)
    {
        switch (evento.EventType)
        {
            // Cuando se detecta un posible ataque:
            case AuthEventType.SuspiciousActivityDetected:
                _logger.LogCritical(
                    "🚨 Actividad sospechosa para usuario {UserId}", evento.UserId);
                await _emailService.EnviarAlertaAsync(evento.UserId,
                    "Se detectó actividad sospechosa en tu cuenta. " +
                    "Todas tus sesiones han sido cerradas por seguridad.");
                break;

            // Cuando el usuario cierra todas las sesiones:
            case AuthEventType.GlobalLogout:
                await _emailService.EnviarConfirmacionAsync(evento.UserId,
                    "Has cerrado sesión en todos los dispositivos.");
                break;

            // Registrar todos los logins para auditoría:
            case AuthEventType.LoginSuccess:
                _logger.LogInformation(
                    "Login exitoso: usuario {UserId}, IP: {IP}",
                    evento.UserId,
                    evento.Metadata?.GetValueOrDefault("ip", "desconocida"));
                break;
        }
    }
}

// Registrar el handler en Program.cs:
builder.Services.AddTransient<IAuthEventHandler, MiEventHandler>();
```

---

## Referencia de Configuración Completa

```csharp
builder.Services.AddSecureAuth(options =>
{
    // ═══ JWT ═══
    options.Jwt.Issuer = "miapp.com";        // Emisor del token
    options.Jwt.Audience = "miapp-api";       // Destinatario del token
    options.Jwt.SigningKey = "...";            // Clave para firmar (REQUERIDO: mín. 32 caracteres)
    options.Jwt.Algorithm = "HS256";           // Algoritmo de firma (por defecto)

    // ═══ Tokens de sesión ═══
    options.Auth.AccessTokenLifetime = TimeSpan.FromMinutes(15);  // Vida del JWT
    options.Auth.RefreshTokenLifetime = TimeSpan.FromDays(7);     // Vida del Refresh
    options.Auth.GracePeriodSeconds = 30;      // Tolerancia para envíos duplicados
    options.Auth.ClockSkew = TimeSpan.FromMinutes(5); // Tolerancia de reloj

    // ═══ Protección contra fuerza bruta ═══
    options.Auth.MaxFailedAttempts = 5;
    options.Auth.LockoutDurations = new[]      // Escalado exponencial
    {
        TimeSpan.FromMinutes(1),   // 1° bloqueo
        TimeSpan.FromMinutes(5),   // 2° bloqueo
        TimeSpan.FromMinutes(15),  // 3° bloqueo
        TimeSpan.FromHours(1)      // 4°+ bloqueo
    };

    // ═══ Caché del SecurityStamp ═══
    options.Auth.SecurityStampCacheDuration = TimeSpan.FromMinutes(5);

    // ═══ Hashing de contraseñas (Argon2id) ═══
    options.Argon2.MemorySize = 65536;  // 64 MB de RAM por hash
    options.Argon2.Iterations = 3;       // 3 pasadas
    options.Argon2.Parallelism = 4;      // 4 hilos paralelos
});
```

---

## Proyecto de Ejemplo

El repositorio incluye una API de ejemplo completa en `samples/SampleApi/` que puedes ejecutar inmediatamente:

```bash
dotnet run --project samples/SampleApi
```

Abre `http://localhost:5000/swagger` para explorar los endpoints interactivamente.

**El usuario de prueba pre-cargado es**:
- Email: `demo@securecore.dev`
- Contraseña: `P@ssw0rd123!`
