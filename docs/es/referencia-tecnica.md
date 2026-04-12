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
| `SigningKey` | `string` | Clave simétrica para firma HS256. | Mínimo 32 caracteres (256 bits) |
| `Algorithm` | `string` | Algoritmo de firma (Default: `HS256`). | Requerido |

### 2.2. SecureAuthOptions
Define parámetros del ciclo de vida de la sesión y políticas de bloqueo.

| Propiedad | Tipo | Valor Default | Validación |
| :--- | :--- | :--- | :--- |
| `AccessTokenLifetime` | `TimeSpan` | 15 min | Requerido |
| `RefreshTokenLifetime` | `TimeSpan` | 7 días | Requerido |
| `GracePeriodSeconds` | `int` | 30 seg | [0, 300] |
| `MaxFailedAttempts` | `int` | 5 | [1, 100] |
| `LockoutDurations` | `TimeSpan[]` | [1m, 5m, 15m, 1h] | Requerido |
| `ClockSkew` | `TimeSpan` | 5 min | Requerido |

### 2.3. Argon2Options
Configuración del hashing de contraseñas mediante Argon2id.

| Propiedad | Tipo | Valor Default | Descripción |
| :--- | :--- | :--- | :--- |
| `MemorySize` | `int` | 65536 | Memoria en KB (64MB). |
| `Iterations` | `int` | 3 | Pasadas sobre el bloque de memoria. |
| `Parallelism` | `int` | 4 | Número de hilos simultáneos. |
| `HashSize` | `int` | 32 | Longitud del hash resultante en bytes. |

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

---

## 6. Seguridad y Observabilidad

### 6.1. Sistema de Eventos
El sistema despacha eventos de dominio asíncronos mediante `IAuthEventDispatcher`.

**Eventos Clave:**
- `LoginSuccess`: Login exitoso procesado.
- `LoginFailed`: Credencial inválida (con metadatos de intentos).
- `SuspiciousActivityDetected`: Detectado intento de reuso de un Refresh Token ya rotado.

### 6.2. Mitigación contra Enumeración
El framework garantiza un tiempo de respuesta constante en fallos de autenticación mediante la inyección de operaciones de hashing ficticias cuando no se localiza el usuario en el almacén de datos.
