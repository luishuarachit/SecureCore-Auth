# Referencia Técnica: SecureCore Auth Framework

Esta documentación proporciona una especificación técnica detallada de los miembros, interfaces y mecanismos internos del framework SecureCore Auth, dirigida a ingenieros de software y arquitectos.

---

## 1. Arquitectura y Principios de Diseño

SecureCore Auth está diseñado bajo una arquitectura agnóstica al almacenamiento y desacoplada del framework de UI.

- **Inversión de Dependencia**: La lógica core depende de interfaces (`IUserStore`, `ISessionStore`) que deben ser implementadas por la capa de infraestructura.
- **Orquestación**: El flujo de identidad se maneja a través de un orquestador central que coordina validaciones criptográficas, gestión de estado y despacho de eventos.
- **Seguridad por Diseño**: Implementación nativa de mitigaciones contra ataques de enumeración (verificación de tiempo constante) y rotación de tokens (RTR).

---

## 2. Configuración y Opciones

El framework utiliza el patrón `IOptions<T>` de .NET y permite validación en tiempo de arranque (`ValidateOnStart`).

### 2.1. JwtOptions
Gestiona los parámetros del esquema de autenticación Bearer mediante JWT.

| Propiedad | Tipo | Descripción | Requisito/Validación |
| :--- | :--- | :--- | :--- |
| `Issuer` | `string` | Identificador del emisor del token. | Requerido |
| `Audience` | `string` | Identificador del destinatario del token. | Requerido |
| `SigningKey` | `string?` | Clave simétrica para firma HS256. | Mínimo 32 caracteres (256 bits). Solo si Algorithm=HS256. |
| `PrivateKey` | `string?` | Clave privada RSA/ECDSA en formato PEM. | Requiere Algorithm=RS256 o ES256. |
| `PublicKey` | `string?` | Clave pública RSA/ECDSA en formato PEM. | Requiere Algorithm=RS256 o ES256. |
| `Algorithm` | `string` | Algoritmo de firma (Default: `RS256`). | Valores: HS256, RS256, ES256, ES384, ES512 |

> **NOTA DE SEGURIDAD**: Se recomienda **RS256 o ES256** para producción. Estos algoritmos usan criptografía asimétrica:
> - **HS256 (simétrico)**: La misma clave firma y valida. Si se filtra, cualquiera puede伪造 tokens.
> - **RS256/ES256 (asimétrico)**: Usa clave privada para firmar y clave pública para validar. La clave pública puede distribuirse; la privada permanece segura en el servidor.

### 2.2. SecureAuthOptions
Define parámetros del ciclo de vida de la sesión y políticas de bloqueo.

| Propiedad | Tipo | Valor Default | Validación |
| :--- | :--- | :--- | :--- |
| `AccessTokenLifetime` | `TimeSpan` | 15 min | Requerido |
| `RefreshTokenLifetime` | `TimeSpan` | 7 días | Requerido |
| `GracePeriodSeconds` | `int` | 30 seg | [0, 300] |
| `MaxFailedAttempts` | `int` | 5 | [1, 100] |
| `LockoutDurations` | `TimeSpan[]` | [1m, 5m, 15m, 1h] | Requerido |
| `ClockSkew` | `TimeSpan` | 30 seg | Requerido |
| `SecurityStampCacheDuration` | `TimeSpan` | 1 min | Requerido |
| `LoginRateLimitMaxAttempts` | `int` | 10 | [1, 1000] |
| `LoginRateLimitWindow` | `TimeSpan` | 1 min | Requerido |

#### Guía de Configuración de AccessTokenLifetime

El tiempo de vida del Access Token es un balance entre seguridad y experiencia de usuario:

| Escenario | AccessTokenLifetime | RefreshTokenLifetime | Justificación |
| :--- | :--- | :--- | :--- |
| **Apps sensibles** (finanzas, admin) | 5-15 min | 24h | Ventana de ataque mínima si el token es robado. Refresh frecuente. |
| **Apps normales** (default) | 15-30 min | 7 días | Balance entre UX y seguridad. |
| **APIs internas** | 1+ hora | 7 días | Solo si hay firewall robusto. **No recomendado** para exposición directa a internet. |

**Recomendación para operaciones sensibles**: Para tareas críticas (pagos, eliminación de datos), implemente verificación adicional como re-autenticación explícita o tokens de vida muy corta específicos para esas operaciones.

### 2.3. Argon2Options
Configuración del hashing de contraseñas mediante Argon2id.

| Propiedad | Tipo | Valor Default | Descripción |
| :--- | :--- | :--- | :--- |
| `MemorySize` | `int` | 65536 | Memoria en KB (64MB). |
| `Iterations` | `int` | 3 | Pasadas sobre el bloque de memoria. |
| `Parallelism` | `int` | 4 | Número de hilos simultáneos. |
| `HashSize` | `int` | 32 | Longitud del hash resultante en bytes. |

> **NOTA DE RENDIMIENTO - Métodos Async**: IPasswordHasher incluye versiones asíncronas de los métodos principales:
> - `HashPasswordAsync()` - Versión async de HashPassword
> - `VerifyPasswordAsync()` - Versión async de VerifyPassword
> - `VerifyDummyPasswordAsync()` - Versión async de VerifyDummyPassword
>
> Estos métodos usan `Task.Run` para ejecutar las operaciones CPU-intensivas de Argon2 en el thread pool, evitando bloquear el thread de la request HTTP.
>
> **CUÁNDO USAR MÉTODOS ASYNC**:
> - **Bajo load** (pocas autenticaciones simultáneas): Use los métodos síncronos
> - **Alta carga** (muchas autenticaciones simultáneas): Use métodos async para no agotar el thread pool
> - **single-instance** con load moderado: Métodos síncronos son suficientes
> - **Alto volumen** de logins simultáneos: Métodos async + rate limiting

### 2.4. PasswordResetOptions
Define la política de recuperación de cuentas.

| Propiedad | Tipo | Valor Default | Validación |
| :--- | :--- | :--- | :--- |
| `TokenLifetimeMinutes` | `int` | 15 | [1, 1440] |
| `TokenSizeBytes` | `int` | 32 | [16, 64] |
| `MaxRequestsPerHour` | `int` | 3 | [0, 100] |

---

## 3. Interfaces de Infraestructura (SPI)

Para integrar el framework, se deben implementar las interfaces de persistencia.

### 3.1. IUserStore
Define el acceso a las entidades de identidad.

- `ValueTask<UserIdentity?> FindByIdAsync(string userId, CancellationToken ct)`
- `ValueTask<UserIdentity?> FindByEmailAsync(string email, CancellationToken ct)`
- `Task UpdateSecurityStampAsync(string userId, string newStamp, CancellationToken ct)`
- `Task<int> IncrementFailedAccessCountAsync(string userId, CancellationToken ct)`

### 3.2. ISessionStore
Gestiona la persistencia de los Refresh Tokens para RTR (Refresh Token Rotation).

- `Task CreateAsync(RefreshTokenEntry entry, CancellationToken ct)`
- `ValueTask<RefreshTokenEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task RevokeAsync(string tokenHash, string? replacedByHash, CancellationToken ct)`
- `Task RevokeByFamilyAsync(string familyId, CancellationToken ct)`

### 3.3. IPasswordResetStore
Persistencia de tokens de un solo uso.
- `Task StoreAsync(PasswordResetEntry entry, CancellationToken ct)`
- `ValueTask<PasswordResetEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task MarkAsUsedAsync(string tokenHash, CancellationToken ct)`
- `ValueTask<int> CountRecentRequestsAsync(string userId, DateTime since, CancellationToken ct)`

### 3.4. IResetTokenMailer
Interfaz para el dispatch de notificaciones de recuperación.
- `Task SendResetEmailAsync(string email, string rawToken, CancellationToken ct)`

---

## 4. Servicios Core (API)

### 4.1. IdentityOrchestrator
Coordina el flujo de autenticación. No contiene lógica criptográfica pero orquesta cada paso.

- **`SignInWithPasswordAsync(email, password)`**: Ejecuta búsqueda, validación de bloqueo, hashing de tiempo constante y generación de tokens.
  - Implementa `VerifyDummyPassword` para mitigar ataques de tiempo si el usuario no existe.
- **`SignInExternalAsync(provider, providerKey)`**: Procesa el login para usuarios autenticados vía OAuth (Google, GitHub, etc.). Vincula la identidad externa con una sesión local.

### 4.2. ITokenService (JwtTokenService)
Responsable de la generación y validación de tokens.

- **`GenerateTokenPairAsync(UserIdentity user)`**: Genera Access Token (JWT) y Refresh Token (Base64Url).
- **`HashRefreshToken(string token)`**: Genera hash SHA256 para almacenamiento seguro de tokens de sesión.

### 4.3. PasswordResetOrchestrator
Maneja el ciclo de vida del restablecimiento.
- **`RequestPasswordResetAsync(email)`**: Valida existencia (tiempo constante), aplica rate limiting, genera token opaco y despacha email.
- **`ConfirmPasswordResetAsync(token, newPassword)`**: Valida hash de token, actualiza credenciales y dispara `RevokeAllSessionsAsync`.

### 4.4. LoginRateLimiter
Protege el endpoint de login contra ataques de fuerza bruta distribuidos por IP.

- **Configuración por defecto**: 10 intentos por minuto por dirección IP.
- **Propósito**: Complementa el bloqueo por cuenta (`LockoutManager`) protegiendo contra atacantes que prueban muchas cuentas diferentes desde la misma IP.
- **Comportamiento**: Retorna HTTP 429 Too Many Requests cuando se excede el límite.

#### Opciones configurables

El implementador puede ajustar el comportamiento según sus necesidades via `SecureAuthOptions`:

| Propiedad | Default | Descripción |
| :--- | :--- | :--- |
| `LoginRateLimitMaxAttempts` | 10 | Intentos máximos permitidos en la ventana |
| `LoginRateLimitWindow` | 1 min | Ventana de tiempo para contar intentos |

**Ejemplos de configuración:**

```csharp
// Seguridad estricta (5 intentos/min)
options.LoginRateLimitMaxAttempts = 5;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);

// Balance (default: 10 intentos/min)
options.LoginRateLimitMaxAttempts = 10;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);

// Permisivo (20 intentos/min) - solo para APIs internas
options.LoginRateLimitMaxAttempts = 20;
options.LoginRateLimitWindow = TimeSpan.FromMinutes(1);
```

---

> **NOTA**: El sistema de seguridad de AuthCore funciona en dos capas:
> 1. **Protección por cuenta**: `LockoutManager` bloquea cuentas individuales tras múltiples intentos fallidos (bloqueo exponencial).
> 2. **Protección global por IP**: `LoginRateLimiter` limita intentos agregados desde cualquier IP, evitando ataques distribuidos.

### 4.5. ExternalTokenStore y Persistencia de Tokens OAuth

**A-07: NullExternalTokenStore Warning**

Cuando `PersistProviderTokens = true` pero no se registra un `IExternalTokenStore` personalizado, AuthCore emitirá un warning en los logs indicando que los tokens OAuth no se persistirán.

```csharp
// Si necesitas guardar tokens de acceso del proveedor (ej: para llamadas a Graph API de Microsoft):
public class MyExternalTokenStore : IExternalTokenStore
{
    public async Task SaveAsync(ExternalTokenEntry entry, CancellationToken ct) { ... }
    public async ValueTask<ExternalTokenEntry?> GetAsync(string userId, string provider, CancellationToken ct) { ... }
    public async Task RevokeAsync(string userId, string provider, CancellationToken ct) { ... }
}

// Registrarlo antes de AddOAuth()
services.AddScoped<IExternalTokenStore, MyExternalTokenStore>();
builder.AddOAuth(...);
```

### 4.6. Request Size Limit (A-10)

Los endpoints de autenticación pueden ser objetivo de ataques DoS con payloads grandes. Se recomienda configurar límites de tamaño de request a nivel de Kestrel:

```csharp
// Program.cs - Limitar tamaño de request a 4KB para toda la API
builder.WebHost.ConfigureKestrel(opt =>
{
    opt.Limits.MaxRequestBodySize = 4096;
});

// O específicamente para endpoints de auth (más restrictivo: 2KB)
builder.WebHost.ConfigureKestrel(opt =>
{
    opt.Limits.MaxRequestBodySize = 4096; // global: 4KB
});
```

> **NOTA**: Los endpoints de AuthCore (/auth/login, /auth/refresh, /auth/forgot-password, /auth/reset-password) típicamente reciben payloads menores a 1KB (email + password). Un límite de 4KB es razonable y seguro.

---

## 5. Middleware y Endpoints de Integración

El paquete `SecureCore.Auth.AspNetCore` expone métodos de extensión para el pipeline de ASP.NET Core.

### 5.1. Registro de Servicios
```csharp
services.AddSecureAuth(options => { ... })
        .AddPasswordAuthentication();
```

### 5.2. Pipeline de Procesamiento
1. `app.UseAuthentication()`: Establece el `ClaimsPrincipal` a partir del JWT.
2. `app.UseSecureAuthValidation()`: Middleware de validación activa del SecurityStamp (contra caché/almacenamiento) y revocación de sesión.
3. `app.UseAuthorization()`: Evaluación de políticas de acceso.

### 5.3. Endpoints Automáticos
`app.MapSecureAuthEndpoints("/base-path")` registra:
- `POST /login`: Recepción de credenciales.
- `POST /refresh`: Rotación de Refresh Tokens.
- `POST /logout`: Revocación del token actual.
- `POST /revoke-all`: Reset global de sesiones (cambio de SecurityStamp).
- `POST /forgot-password`: Inicio de flujo de recuperación.
- `POST /reset-password`: Confirmación y cambio de credenciales.

---

## 6. Seguridad y Observabilidad

### 6.1. Sistema de Eventos
El sistema despacha eventos de dominio asíncronos mediante `IAuthEventDispatcher`.

**Eventos Clave:**
- `LoginSuccess`: Login exitoso procesado.
- `LoginFailed`: Credencial inválida (con metadatos de intentos).
- `SuspiciousActivityDetected`: Detectado intento de reuso de un Refresh Token ya rotado.
- `PasswordResetRequested`: Solicitud de reset iniciada por email.
- `PasswordResetCompleted`: Cambio de contraseña exitoso mediante token.

### 6.2. Mitigación contra Enumeración
El framework garantiza un tiempo de respuesta constante en fallos de autenticación mediante la inyección de operaciones de hashing ficticias cuando no se localiza el usuario en el almacén de datos.

---

## 7. Ecosistema OAuth 2.0 / OIDC (v2.0.0)

A partir de la versión 2.0.0, el framework incluye una arquitectura de validación de identidad externa desacoplada.

### 7.1. IOAuthProviderValidator
Interfaz que deben implementar todos los validadores de proveedores.

- `Task<OAuthIdentityResult> ValidateIdTokenAsync(string idToken, string? expectedNonce, CancellationToken ct)`
- `Task<OAuthIdentityResult> ExchangeCodeAsync(string code, string redirectUri, string? expectedNonce, CancellationToken ct)`

### 7.2. Mecanismos de Seguridad Implementados

| Característica | Propósito | Implementación |
| :--- | :--- | :--- |
| **Nonce Enforcement** | Previene ataques de Replay. | Validación estricta en proveedores OIDC (Google, MS, LinkedIn, Apple). |
| **JWKS Caching + Auto-Retry** | Rendimiento y resiliencia. | Caché en memoria con `Lazy<Task>` (expiración 24h) + reintento automático ante `SecurityTokenSignatureKeyNotFoundException` o `SecurityTokenInvalidSignatureException`. El patrón `Lazy<Task>` evita el cuello de botella que producía `SemaphoreSlim(1,1)` en alta concurrencia. |
| **AppSecret Proof** | Seguridad Servidor-Servidor. | HMAC-SHA256(AccessToken, ClientSecret) en Facebook. |
| **Issuer Dinámico** | Multi-tenancy. | Validación por regex/prefijo en Microsoft Entra ID. |
| **Anti-Replay de State** | Previene reutilización del state OAuth. | `ConsumeAsync` usa GET + REMOVE no atómico. Para aplicaciones de alto riesgo, implementar versión con Redis GETDEL. |

> **NOTA DE SEGURIDAD - TOCTOU en OAuth State**: El método `ConsumeAsync` de `DistributedCacheOAuthStateStore` usa una operación GET + REMOVE no atómica. La ventana de race condition es ~1ms y requeriría coordinación exacta entre dos requests.
>
> Para aplicaciones de alto riesgo que requieren operación atómica, implemente su propia versión de `IOAuthStateStore` usando Redis con el comando GETDEL. El riesgo en la práctica es mínimo para la mayoría de aplicaciones.

### 7.3. Proveedores Soportados

1. **Google**: OpenID Connect (v2.0).
2. **Microsoft**: Entra ID (v2.0) con soporte multi-tenant.
3. **Facebook**: OAuth 2.0 + Graph API + AppSecret Proof.
4. **GitHub**: OAuth 2.0 + User Email API.
5. **LinkedIn**: OpenID Connect.
6. **TikTok**: OAuth 2.0 (Login Kit V2) con manejo de errores adaptado.
7. **Apple**: Sign In with Apple (OIDC) con generación dinámica de Client Secret vía **ES256**.

### 7.4. Estandarización de Resultados SignIn (v2.4.0)

`OAuthSignInResult` incluye una propiedad `ErrorCode` estandarizada para manejo programático de errores:

| ErrorCode | Significado |
| :--- | :--- |
| `oauth_provider_not_configured` | El proveedor solicitado no está registrado. |
| `oauth_user_not_found` | Usuario no encontrado y registro implícito deshabilitado. |
| `oauth_account_locked` | La cuenta está bloqueada temporalmente por intentos fallidos. |
| `oauth_validation_failed` | La validación del ID Token o código de autorización falló. |
| `oauth_invalid_request` | La solicitud carece de campos requeridos (IdToken o Code). |
| `oauth_factory_not_registered` | `AllowImplicitRegistration=true` pero falta `IExternalUserFactory`. |

### 7.5. Protección de Claims JWT (v2.4.0)

`JwtTokenService` incluye un blocklist estático `SystemClaims` que previene la inyección de 17 claims sensibles desde `UserIdentity.Claims`:

- **Identidad**: `sub`, `email`, `name`
- **Control de token**: `jti`, `iss`, `aud`, `exp`, `iat`, `nbf`
- **Seguridad**: `ssv` (SecurityStamp), `nonce`
- **Autorización**: `role`, `roles`, `auth_time`, `amr`, `acr`, `azp`

Cualquier intento de sobrescribir estos claims via `UserIdentity.Claims` es ignorado silenciosamente.

### 7.6. CI/CD (v2.4.0)

El repositorio incluye un flujo de GitHub Actions (`.github/workflows/ci.yml`) que se ejecuta en push/PR a `main`:
- Compilación (`dotnet build --configuration Release`)
- Pruebas (`dotnet test --configuration Release`)
- Verificación de formato (`dotnet format --verify-no-changes`)

Adicionalmente, un `.editorconfig` aplica convenciones de estilo C# 12: namespaces file-scoped, primary constructors, pattern matching (`is not null`), preferencia por `sealed class`, y uso de `nameof`.

---

## 8. IOperationLock - Locks para Operaciones Críticas

### Propósito

La interfaz `IOperationLock` proporciona un mecanismo para serializar el acceso a recursos compartidos durante operaciones críticas, principalmente la **Rotación de Refresh Tokens (RTR)**.

### Interfaz

```csharp
public interface IOperationLock
{
    Task<IDisposable> AcquireAsync(
        string key, 
        TimeSpan timeout, 
        CancellationToken cancellationToken);
}
```

### Implementación por Defecto: InMemoryOperationLock

La librería incluye `InMemoryOperationLock` que usa `SemaphoreSlim` internamente:

```csharp
public sealed class InMemoryOperationLock : IOperationLock
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new();

    public async Task<IDisposable> AcquireAsync(string key, TimeSpan timeout, CancellationToken ct)
    {
        var semaphore = _locks.GetOrAdd(key, _ => new SemaphoreSlim(1, 1));
        if (!await semaphore.WaitAsync(timeout, ct))
            throw new TimeoutException($"No se pudo acquire lock: {key}");
        return new LockReleaser(semaphore);
    }
}
```

### Uso en SessionOrchestrator

```csharp
// En RotateRefreshTokenAsync:
using var @lock = await operationLock.AcquireAsync($"rtr:{familyId}", timeout, ct);
// ... operaciones atómicas de RTR ...
```

### Limitaciones y Recomendaciones

| Escenario | Implementación Requerida | Notas |
| :--- | :--- | :--- |
| **Single-instance** | Ninguna (default) | Funciona out-of-the-box |
| **Multi-instancia (Redis)** | Personalizada | Usar `SETNX` con TTL |
| **Multi-instancia (SQL)** | Personalizada | Usar `sp_getapplock` |

> **IMPORTANTE**: Si usa la implementación por defecto en arquitecturas distribuidas, NO tendrá protección contra race conditions. Documente esta limitación claramente.

### Configuración

```json
{
  "SecureAuth": {
    "OperationLock": {
      "TimeoutSeconds": 5
    }
  }
}
```

El timeout por defecto (5 segundos) es suficiente para operaciones típicas de base de datos (&lt;100ms). Solo incremento si sus operaciones son particularmente lentas.

---

## 9. IRateLimiter - Rate Limiting para Prevención de Ataques

### Propósito

La interfaz `IRateLimiter` proporciona un mecanismo para limitar el número de solicitudes desde una fuente específica (IP, usuario) dentro de un período de tiempo. Protege contra:

- **Fuerza bruta**: Múltiples intentos de contraseña
- **Credential stuffing**: Probando contraseñas filtradas en múltiples cuentas
- **DDoS**: Sobrecargar el servidor con solicitudes

### Interfaz

```csharp
public interface IRateLimiter
{
    bool IsAllowed(string key);
    void Reset(string key);
    int GetRemainingAttempts(string key);
}
```

### Implementación por Defecto: InMemoryRateLimiter

La librería incluye `InMemoryRateLimiter` que usa `ConcurrentDictionary` internamente:

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
        // Implementación con sliding window
    }

    public void Reset(string key) { /* ... */ }
    public int GetRemainingAttempts(string key) { /* ... */ }
}
```

### Uso en Endpoints

```csharp
// En endpoint de login:
if (!rateLimiter.IsAllowed(ipAddress))
    return Results.StatusCode(429);

// En login exitoso:
rateLimiter.Reset(ipAddress);
```

### Limitaciones y Recomendaciones

| Escenario | Implementación Requerida | Notas |
| :--- | :--- | :--- |
| **Single-instance** | Ninguna (default) | Funciona out-of-the-box |
| **Multi-instancia (Redis)** | Personalizada | Usar `StringIncrement` con TTL |
| **Multi-instancia (Middleware)** | AspNetCoreRateLimiter | Alternativa integrada |

> **IMPORTANTE**: La implementación por defecto NO funciona en arquitecturas distribuidas. Los atacantes pueden evadir los límites distribuyendo solicitudes entre servidores. Para producción con múltiples instancias, use Redis o un middleware de rate limiting.

### Configuración

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

