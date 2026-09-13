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
| `AllowedSystemClaims` | `HashSet<string>` | Claims del sistema que se permiten inyectar desde `UserIdentity.Claims`. | Default: vacío (todos bloqueados). Agregar `"role"`/`"roles"` para RBAC. |

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
| `ForgotPasswordRateLimiter` (v3.2.0) | `RateLimiterOptions?` | 5/hora por IP | Opcional (ver §9) |
| `MaxAuthRequestBodySize` (v3.2.0) | `int` | 2048 bytes | [256, 8192] (ver §4.6) |
| `AccessTokenLifetimeProvider` (v3.1.5) | `Func<UserIdentity, TimeSpan?>` | null | Opcional |
| `MfaVerifiedTtl` (v3.2.0, S3) | `TimeSpan` | 8 h | Ventana "mfa_verified"; ≤ 0 → fallback 8 h (ver §4.9) |
| `EmitAcr` (v3.2.0, S3) | `bool` | false | Emite claim `acr` en todos los tokens (opt-in) |
| `AcrLevel` (v3.2.0, S3) | `string` | "1" | Valor del claim `acr` cuando `EmitAcr` está activo |
| `EmitAmr` (v3.2.0, F6) | `bool` | false | Emite `amr` de forma consistente (RFC 8176): password→`pwd`, WebAuthn añade `mfa_method=webauthn` (opt-in) |

#### Per-Role Access Token Lifetime (v3.1.5)

`AccessTokenLifetimeProvider` permite resolver el TTL del Access Token por usuario (defensa en profundidad: superadmin 15m, admin 30m, support 1h). Si es `null` o devuelve `null`, se usa el `AccessTokenLifetime` global.

```csharp
options.AccessTokenLifetimeProvider = user =>
    user.Claims?.GetValueOrDefault("role") switch
    {
        "superadmin" => TimeSpan.FromMinutes(15),
        "admin"      => TimeSpan.FromMinutes(30),
        "support"    => TimeSpan.FromHours(1),
        _            => null // usa el TTL global
    };
```

**REQUISITOS**: el claim `role` debe fluir al JWT vía `JwtOptions.AllowedSystemClaims` (ver sección 7.5). Si no se configura, el provider recibe `Claims` vacío → devuelve null → TTL global (fail-secure). Si el provider lanza una excepción, se registra el warning y se usa el TTL global (no rompe disponibilidad).

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

### 2.5. AccountProtectionOptions (v3.2.0, S1)
Define la política de **anti-abuso por cuenta** (límites de intentos por factor). Es **opt-in** (default `Enabled = false`, principio D-03): sin registrar `AddSecureAuthAccountProtection()` el
comportamiento previo permanece intacto.

| Propiedad | Tipo | Valor Default | Validación / Nota |
| :--- | :--- | :--- | :--- |
| `Enabled` | `bool` | false | Activa el subsistema S1. |
| `Window` | `TimeSpan` | 5 min | Ventana deslizante: los fallos anteriores a `Window` no cuentan. |
| `MaxAttempts` | `IReadOnlyDictionary<AccountProtectionScope, int>` | Password 5, MfaLogin 5, Passkey 5, Recovery 3, VerifyAction 5, PasswordChange 5 | Límite por factor/acción. `GetMaxAttempts(scope)` fallback a 5 si no se configura un scope. |
| `EscalationDurations` | `IReadOnlyList<TimeSpan>` | [10 min, 30 min, 1 h, 24 h] | Duración del lockout por nivel de escalamiento. `GetLockDuration(level)` clamps dentro de la lista. |
| `MaxLockDuration` | `TimeSpan` | 24 h | Techo duro: ningún lockout supera esta duración. |

Sección de configuración: `SecureAuth:AccountProtection`.

```csharp
services.AddSecureAuth(options => { options.AccountProtection.Enabled = true; /* o vía appsettings */ });
services.AddSecureAuthAccountProtection(o =>
{
    o.Enabled = true;
    o.Window = TimeSpan.FromMinutes(10);
});
```

> **DIDÁCTICA — Escalamiento por nivel**: el nivel se conserva entre episodios mientras el proceso viva. Si una cuenta se bloquea (`Nivel 1` = 10 min), pasa a fallar, se desbloquea y vuelve a fallar, el segundo bloqueo es `Nivel 2` (30 min). Esto encarece progresivamente el ataque de fuerza bruta sin penalizar un único error puntual.
> **DIDÁCTICA — Alcance por factor**: los presupuestos son independientes por `AccountProtectionScope`. Un ataque a MfA (5 intentos) no consume el presupuesto de contraseña, y viceversa.

> **Seguridad (auditoría)**: `AddSecureAuthAccountProtection()` valida la configuración en arranque (`.Validate().ValidateOnStart()`): `Window > 0`, `MaxLockDuration > 0`, `EscalationDurations` no vacío con duraciones > 0 y `MaxAttempts ≥ 1`. También de uso defensivo, **incluso sin validación** (construcción directa del servicio): `GetWindow()`/`GetMaxLockDuration()` caen a los defaults (5 min / 24 h) ante valores ≤ 0, y `GetLockDuration(level)` clampa cada duración al techo `MaxLockDuration` y cualquier nivel fuera de rango/duración ≤ 0 a `MaxLockDuration` — la configuración inválida nunca degrada el lockout a inofensivo/fail-open.
>
> **DIDÁCTICA — Precedencia de configuración**: el `configure` de `AddSecureAuthAccountProtection(Action<AccountProtectionOptions>)` sobrescribe **en bloque** la sección `SecureAuth:AccountProtection` (todas las propiedades del objeto recibido, no solo las que se toquen). Para combinar fuentes, fija **todas** las propiedades activas en el `configure` o usa únicamente appsettings.

### 2.6. VerifyActionOptions (v3.2.0, S3)
Define el ciclo de vida del código OTP de **verify-action** (step-up de acciones sensibles). Se
registra con `AddVerifyAction()`, sección `SecureAuth:VerifyAction`, y valida en arranque
(`.ValidateDataAnnotations().ValidateOnStart()`).

| Propiedad | Tipo | Default | Validación |
| :--- | :--- | :--- | :--- |
| `TtlMinutes` | `int` | 5 | [1, 15] — el código expira aunque el intento falle |
| `CodeLength` | `int` | 6 | [6, 8] — dígitos del OTP |
| `MaxSendsPerWindow` (auditoría, S3) | `int` | 3 | [1, 10] — máximo de envíos por usuario y ventana (`TtlMinutes`) |

> **DIDÁCTICA** (H1, auditoría): `MaxSendsPerWindow` es un **throttle duro que aplica SIEMPRE**,
> incluso sin S1. Sin él, un atacante con sesión válida emitiría códigos sin límite y
> brute-forcearía el OTP (~10^6 combinaciones). Un código validado correctamente renueva el throttle
> (paridad con S1). Es en memoria por instancia: con S1 distribuido conviene mantener ambos.
>
> El step-up NO emite tokens por sí mismo: su éxito abre la ventana compartida
> `mfa_verified` (`SecureAuthOptions.MfaVerifiedTtl`). El host consulta
> `IMfaVerifiedSessionStore.IsVerifiedAsync(userId)` para decidir si una mutación sensible
> procede sin repetir el código (patrón 2FA-opcional sobre una sesión ya autenticada).

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
Persistencia de tokens de un solo uso. Solo se almacena el hash SHA-256 del token.
- `Task StoreAsync(PasswordResetEntry entry, CancellationToken ct)`
- `ValueTask<PasswordResetEntry?> FindByTokenHashAsync(string tokenHash, CancellationToken ct)`
- `Task MarkAsUsedAsync(string tokenHash, CancellationToken ct)`
- `ValueTask<int> CountRecentRequestsAsync(string userId, DateTime since, CancellationToken ct)`
- `Task DeleteExpiredAsync(CancellationToken ct)`: limpieza periódica de tokens expirados (invocar con un BackgroundService diario).
- `Task UpdateDeliveryStateAsync(string tokenHash, PasswordResetDeliveryState state, CancellationToken ct)` (v3.2.0): **miembro por defecto** (default interface member). Sobrescribirlo permite registrar si el email fue `Dispatched` o `Failed` (`PasswordResetEntry.DeliveryState`) para auditoría y limpieza de tokens huérfanos Pending/Failed (A-09). Si no se sobrescribe, no rompe nada: el estado queda en `Pending`.

### 3.4. IResetTokenMailer
Interfaz para el dispatch de notificaciones de recuperación.
- `Task SendResetEmailAsync(string email, string rawToken, CancellationToken ct)`

### 3.5. ISingleUseTokenStore (v3.2.0, S2)
Primitiva transversal de "consumir exactamente una vez" (equivalente a GETDEL). Base del
**anti-replay** para OAuth state (A-06), challenges WebAuthn (Fase 4) y recovery codes (Fase 5).

- `ValueTask SetAsync(string key, string value, TimeSpan ttl, CancellationToken ct)`
- `ValueTask<string?> GetAndRemoveAsync(string key, CancellationToken ct)`

**Contrato SPI distribuido**: `DistributedCacheOAuthStateStore` enruta por este SPI el **ciclo de
vida completo** del state (escritura y consumo) cuando está registrado. La implementación por
defecto `DistributedCacheSingleUseTokenStore` usa IDistributedCache con GET + REMOVE (**NO
atómico**, ventana residual ~1 ms). Para operación atómica en multi-instancia, implemente este
contrato sobre un backend que soporte GETDEL/Lua (Redis) u otro mecanismo transaccional — el store
debe ser **simétrico** (mismo backend y mismo formato de clave) y registrarse **antes de
`AddSecureAuth()`** (donde se registra el default con `TryAddScoped`). Las claves llevan el prefijo
del llamante por contexto (p. ej. `OAuthState_`).

### 3.6. IAccountProtectionService (v3.2.0, S1)
Servicio de **anti-abuso por cuenta y por factor** (A-02/A-15/A-19). Diseñado para ser
extensible (distribuible) mediante una implementación propia sobre un backend compartido;
la implementación por defecto es `InMemoryAccountProtectionService`.

- `ValueTask<AccountProtectionResult> CheckAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — estado actual del presupuesto para el factor.
- `Task RecordFailureAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — registra un fallo; al alcanzar `MaxAttempts` activa el lockout escalonado.
- `Task RecordSuccessAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — verificación correcta: limpia el presupuesto del scope.
- `Task ResetAsync(AccountProtectionScope scope, string key, CancellationToken ct)` — libera solo el scope indicado.
- `Task ResetAllForUserAsync(string key, CancellationToken ct)` — libera todos los scopes de la cuenta (mismo `key`).
- `ValueTask<bool> AnyActiveLockAsync(string key, CancellationToken ct)` — permite decidir respuestas homogéneas sin revelar qué factor está bloqueado.

`AccountProtectionResult` expone `Allowed`, `RemainingAttempts`, `LockEnd` y `EscalationLevel`
(ver § 4.8 para el wiring).

### 3.7. SPI de sesión verificada y OTP de step-up (v3.2.0, S3)

- `IMfaVerifiedSessionStore` — ventana "mfa_verified" (A-21): `SetVerifiedAsync(userId, method)`,
  `IsVerifiedAsync(userId)`, `ClearAsync(userId)`. Default `DistributedCacheMfaVerifiedSessionStore`
  (TTL `SecureAuthOptions.MfaVerifiedTtl`, fallback defensivo 8 h; la clave guarda el método
  verificado y su presencia = verificado). Registrado `TryAddScoped` en `AddMfa`,
  `AddPasswordAuthentication` y `AddVerifyAction`.
  - **Ciclo de vida (H2, auditoría)**: `SessionOrchestrator` (si lo resuelve con
    `IMfaVerifiedSessionStore` registrado) invoca `ClearAsync(userId)` tanto en
    `RevokeAllSessionsAsync` como en `LogoutAsync`: una sesión nueva (sin MFA) no debe heredar el
    paso elevado de una sesión revocada/cerrada por el atacante.
- `IEmailOtpStore` (A-22) — código OTP de step-up con consumo **single-use atómico**: solo persiste
  el hash SHA-256 (hex minúsculas), `ValidateAndRemoveCodeAsync` compara en tiempo constante
  (`CryptographicOperations.FixedTimeEquals` con guard de longitud) y consume la entrada delegando
  en `ISingleUseTokenStore` (S2). Default `DistributedCacheEmailOtpStore`.
- `IEmailOtpSender` (A-22) — transporta el código al destino. Default `EmailServiceEmailOtpSender`
  (adaptador sobre `IEmailService`). Registre su propia implementación ANTES de `AddVerifyAction()`
  para sobrescribirla (TryAdd).

### 3.8. IRecoveryCodeStore (v3.2.0, F5)

SPI de persistencia de los recovery codes de primera clase (A-18/A-20). El orquestador
(`RecoveryCodeOrchestrator`) NUNCA ve el código en claro: solo recibe/entrega hashes SHA-256
(hex minúsculas) y delega el **single-use atómico** en `ISingleUseTokenStore` (S2).

- `ValueTask CreateAsync(string userId, string codeHash, TimeSpan ttl, CancellationToken ct)` — persiste un código pendiente de redención con su TTL (`MfaOptions.RecoveryCodeLifetimeDays`).
- `ValueTask<RecoveryCodeStatus> GetStatusAsync(string userId, string codeHash, CancellationToken ct)` — **peek NO consumidor**: distingue `Valid` / `AlreadyUsed` / `Invalid` sin gastar el código (ver DIDÁCTICA en §4.10 sobre por qué el SPI tiene 4 métodos).
- `ValueTask<bool> RedeemAsync(string userId, string codeHash, CancellationToken ct)` — consume de forma **atómica** (delega en `ISingleUseTokenStore.GetAndRemoveAsync`); devuelve `true` una única vez. La redención se serializa con un `IOperationLock` por código (A2, auditoría): cierra la ventana TOCTOU del S2 por defecto (GET + REMOVE no atómico) en single-instance. Para multi-instancia sigue siendo necesaria una implementación S2 atómicamente consumidora (Redis GETDEL/Lua).
- `Task InvalidatePendingAsync(string userId, CancellationToken ct)` — al regenerar un lote, invalida los códigos pendientes del usuario (los ya consumidos no tienen token S2 que invalidar).

**Default**: `DistributedCacheRecoveryCodeStore` sobre `IDistributedCache` con dos claves:
- Token S2 por código: `"recovery:code:{userId}|{hash}"` (valor = hash; delimitador `|` — el hash es siempre un sufijo de 64 hex, clave inequívoca aunque el userId contenga el separador) — la **garantía de seguridad** (single-use atómico).
- Índice JSON por usuario: `"recovery:index:{userId}"` (lista de `{hash, used}`) — solo para distinguir `AlreadyUsed` vs `Invalid` en `GetStatusAsync`.

**Orden de escritura**: el índice se escribe PRIMERO y el token S2 DESPUÉS. Si el proceso muere
entre ambas escrituras durante una regeneración, el índice apunta a códigos cuyo token no existe
→ **no hay códigos huérfanos redimibles**. `RedeemAsync` decide SOLO por el token S2 (single-use
garantizado); el flag `used` del índice es best-effort (auditoría/estado). Al registrar `AddMfa()`,
el default se registra con `TryAddScoped`: implementa tu propia versión distribuida
(Redis GETDEL/Lua) ANTES de `AddSecureAuth()` y el orquestador la usará automáticamente.

---

## 4. Servicios Core (API)

### 4.1. IdentityOrchestrator
Coordina el flujo de autenticación. No contiene lógica criptográfica pero orquesta cada paso.

- **`SignInWithPasswordAsync(email, string? password)`** (F6, A-25): Ejecuta búsqueda, validación de bloqueo, hashing de tiempo constante y generación de tokens.
  - Implementa `VerifyDummyPassword` para mitigar ataques de tiempo si el usuario no existe.
  - **Password nullable de primera clase**: `password == null` → `SignInResult.PasswordlessRequiresCredential` **sin consultar el store** (señal a nivel de REQUEST, uniforme para todos los emails → sin oráculo de enumeración). `VerifyDummyPassword` solo se ejecuta con password no nulo.
  - `SignInResult` expone `ErrorCode` tipado (`SignInErrorCode`) para que el host decida su UX programáticamente: `InvalidCredentials`, `AccountLockedOut`, `TwoFactorRequired`, `TwoFactorRegistrationRequired`, `PasswordlessRequiresCredential`, `GenericFailure`. **Regla de seguridad**: no exponer `ErrorCode` a clientes no autenticados (distinguir códigos sería un oráculo de enumeración); el framework mantiene respuestas HTTP uniformes.
  - El camino de éxito emite `LoginSuccess` con metadata `method=password` y, con `EmitAmr` activo, el claim `amr=pwd` (RFC 8176).
- **`SignInExternalAsync(provider, providerKey)`**: Procesa el login para usuarios autenticados vía OAuth (Google, GitHub, etc.). Vincula la identidad externa con una sesión local. Con `EmitAmr` activo emite `amr=oauth` (y lo persiste en `RefreshTokenEntry.AuthMethod` para preservarlo en la rotación).
- **`CompleteMfaLoginWithRecoveryCodeAsync(mfaSessionToken, recoveryCode, rotateSecurityStamp, ct)`** (v3.2.0, A1 auditoría F5): completa el login con un recovery code ya redimido. A diferencia de `CompleteMfaLoginAsync` (que exige un `mfaCode` TOTP/email), este flujo redime el recovery code (single-use vía `RecoveryCodeOrchestrator.UseAsync`), consume el token de sesión, emite tokens con `amr=mfa`/`mfa_method=recovery` y abre la ventana `mfa_verified` (paridad S3). El flag `rotateSecurityStamp` (política del host) rota el SecurityStamp, invalida su caché y revoca **todas** las sesiones previas (recomendado tras pérdida/robo del dispositivo MFA); con `false`, la sesión y el stamp actuales se conservan. El bloqueo S1 (scope `Recovery`) se traduce a fallo genérico de login (sin revelar la causa). Requiere `AddMfa()` (sin `RecoveryCodeOrchestrator` registrado devuelve `Failed`).

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

Los endpoints de autenticación pueden ser objetivo de ataques DoS con payloads grandes. La librería acota el cuerpo de los endpoints anónimos `/auth/login`, `/auth/refresh`, `/auth/forgot-password` y `/auth/reset-password` con dos mecanismos complementarios:

- **`SecureAuthOptions.MaxAuthRequestBodySize`** (default: `2048` bytes, rango `[256, 8192]`): define el límite.
- **Endpoint filter** (`EnforceAnonymousRequestSizeLimit`): descarta rápido por `Content-Length` cualquier cuerpo válido que supere el límite, devolviendo `413 Payload Too Large` (JSON). Se añade automáticamente a los 4 endpoints anónimos y es verificable en TestServer.
- **Middleware** `UseSecureAuthRequestSizeLimit(prefix)`: asigna `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize` **antes** del binding, por lo que Kestrel rechaza con 413 también los cuerpos **chunked** (sin `Content-Length`).

> **IMPORTANTE**: En Minimal APIs los endpoint filters se ejecutan **después** del binding, por lo que un filter por sí solo no puede limitar cuerpos chunked. Registra el middleware con el mismo prefijo que `MapSecureAuthEndpoints`:

```csharp
app.MapSecureAuthEndpoints("/auth");
app.UseSecureAuthRequestSizeLimit("/auth");
```

Para límites globales de toda la API (fuera de los endpoints de auth), sigue usando la configuración de Kestrel (`Kestrel.MaxRequestBodySize`); el middleware no la reemplaza.

### 4.7. PasskeyService (WebAuthn)

Servicio de registro y verificación de Passkeys (FIDO2/WebAuthn) para el login sin contraseña.

- **`CompleteRegistrationAsync(response, options, userId, displayName)`**: registra una passkey nueva.
- **`BeginAssertionAsync(credentialIds)`**: genera el challenge de login (`null` = Discoverable Credentials).
- **`CompleteAssertionAsync(response, options)`**: verifica la firma y devuelve el usuario, o `null` si falla (ambiguo por diseño).
- **`CompleteAssertionDetailedAsync(response, options)`** (v3.2.0, A-17): verifica la firma y devuelve un `PasskeyAssertionResult` que permite distinguir el motivo:

| Propiedad | Significado |
| :--- | :--- |
| `User` | El sujeto resuelto (si pudo resolverse), útil para políticas por cuenta (lockout). |
| `CredentialFound` | Si la credencial referida por el cliente existe en el store. |
| `SignatureValid` | Si la firma del challenge se verificó correctamente. |

> **SEGURIDAD** (v3.2.0): Un `Id` de credencial malformado (no Base64) se trata como "credencial no encontrada" y nunca lanza excepción. `CredentialFound` es un oráculo de existencia de credenciales — necesario por diseño para el lockout por cuenta — pero **no expongas esta distinción al cliente**: devuelve siempre el mismo error de autenticación genérico.

#### 4.7.1. Resolución del credential ID (S4)

- **`TryResolveCredentialId(response)`** prefiere `response.RawId` — `byte[]` ya decodificado por el `Base64UrlConverter` de Fido2NetLib — y solo recurre a `response.Id` (string) como fallback vía **`TryDecodeBase64UrlCredentialId`**:
  - Normaliza Base64URL sin padding a Base64 estándar (`-`→`+`, `_`→`/`) y añade el padding sintético (`=`, `==`).
  - Un `length % 4 == 1` (padding inválido), un string vacío o un `FormatException` se traducen en `null` (credencial no encontrada), nunca en excepción.
  - `Convert.FromBase64String` estándar NO es Base64URL: el `Id` que envía el navegador (`-`/`_`, sin padding) fallaría ~100% de los casos. No lo uses sobre `response.Id`.

#### 4.7.2. Configuración FIDO2 automática (S4)

`AddWebAuthn()` registra con `TryAddSingleton`:

| Servicio | Derivación |
| :--- | :--- |
| `Fido2Configuration` | `ServerDomain = WebAuthnOptions.RelyingPartyId`, `ServerName = RelyingPartyName`, `Origins = WebAuthnOptions.Origins` |
| `Fido2` | Ctor `Fido2(Fido2Configuration, IMetadataService?)` (el metadata service se resuelve de DI si existe; opcional) |
| `IFido2` | Same instance que `Fido2` |

**Consecuencia de seguridad**: Fido2NetLib valida internamente el origin firmado en el `clientDataJSON` contra el `Fido2Configuration` del instance `Fido2`. Como ahora esa configuración se deriva de `WebAuthnOptions`, el origin verificado coincide con el que configuraste para la ceremonia — ya no hay config desacoplada del consumidor. `RelyingPartyId`/`RelyingPartyName` dejan de ser dead options.

#### 4.7.3. Anti-enumeración en `BeginLoginAsync` (S4)

- Por defecto (`DiscloseCredentialsInLoginBegin = false`) el oráculo de enumeración queda **cerrado**: `userId` no se propaga a `BeginAssertionAsync`, de modo que los `allowCredentials` no se filtran por usuario y la respuesta es idéntica para userIds existentes o no.
- Al activarlo (`= true`), `BeginLoginAsync` pasa `userId: userId` al challenge, propagando los credential IDs del usuario al autenticador (permite "esta cuenta no tiene passkeys" en el cliente). **Riesgo**: oráculo de enrollment por barrido de userIds.

#### 4.7.4. Rate limiting y payload (S4)

- **`/webauthn/login/begin`**: limiter keyed `"webauthn-begin"` (default 30 intentos/min por IP, `SecureAuthOptions.WebAuthnBeginRateLimiter`).
- **`/webauthn/login/complete`**: limiter keyed `"webauthn-complete"` (default 10 intentos/min por IP, `SecureAuthOptions.WebAuthnCompleteRateLimiter`); se resetea tras un login exitoso. La clave es `Connection.RemoteIpAddress` (IP real de la conexión TCP; leer la sección XFF — no usar el header como clave).
- Si el host no registra los limiters (app sin `AddSecureAuth`), los endpoints degradan con gracia y no fallan.
- **`/webauthn/*`**: `RequestSizeLimitMiddleware` asigna `MaxWebAuthnRequestBodySize` (default 65536 bytes, rango [4096, 1048576]) a `IHttpMaxRequestBodySizeFeature`. Los payloads FIDO2 (~KB) no dependen del tope de 2 KB de `/auth` ni quedan al default de Kestrel (~30 MB).

#### 4.7.5. Challenges tipados por ceremonia (S4)

- `StoreChallengeAsync` guarda con clave `"{tag}:{rawId}"` (`"register:…"` para registro, `"login:…"` para login); el `challengeId` devuelto al cliente es el `rawId` opaco.
- Al consumir, el orquestador recompone la clave tipada según la ceremonia: reuso cross-ceremony (un challenge de registro presentado en login o viceversa) es **fail-closed** — no encuentra la entrada con la clave de la ceremonia esperada y rechaza antes del parseo de la respuesta del autenticador. Combina con el single-use atómico de `ISingleUseTokenStore` (reutilizar el mismo `challengeId` en la misma ceremonia también falla).

### 4.8. Anti-abuso por cuenta (S1, v3.2.0)
Integración de `IAccountProtectionService` en los orquestadores. Se activa **únicamente** con
`AddSecureAuthAccountProtection()` (que registra el servicio y enlaza `AccountProtectionOptions`
desde `SecureAuth:AccountProtection`). Sin ese registro, `IdentityOrchestrator` y
`MfaOrchestrator` operan con su política legacy (bloqueo por DB) sin cambios.

| Flujo | Scope | Integración |
| :--- | :--- | :--- |
| `IdentityOrchestrator.SignInWithPasswordAsync` | `Password` | **Pre-check**: si `CheckAsync` deniega, se responde `SignInResult.LockedOut` con evento `AccountLockedOut (reason: account_protection_lock)`. **Fallo de contraseña**: `RecordFailureAsync`; al activarse el lockout, `LockedOut` + evento `AccountLockedOut (reason: lock_triggered, scope, level)`. **Éxito/RequiresMfa**: `RecordSuccessAsync` (reset del scope). El flujo legacy de `LockoutManager` (política de administración/DB) se conserva en paralelo. |
| `MfaOrchestrator.VerifyAsync` | `MfaLogin` | **Pre-check**: si el scope está bloqueado → `"Demasiados intentos. Intente más tarde."`. **Fallo**: `RecordFailureAsync`; el fallo que dispara el lockout responde `"Código inválido"` (genérico, sin oráculo de cuándo se bloquea). **Éxito**: `RecordSuccessAsync`. Sin S1, se mantiene el flujo legacy (`IncrementMfaFailedAttemptsAsync` + `ApplyMfaLockoutIfNeededAsync` con `MaxVerificationAttempts`/`CodeRetryWindowMinutes`). |

> **Transición legacy → S1 (fail-closed)**: al activar S1, `VerifyAsync` respeta un `LockoutEnd` vigente dejado por el flujo legacy en DB: un usuario con `MfaFailedAttemptsCount >= MaxVerificationAttempts` y lockout aún activo se bloquea aunque la ventana S1 no haya registrado fallos. La expiración se auto-resetea (T9: `IsMfaLockedOutAsync` limpia contador y lockout) y el flujo continúa — un bloqueo histórico no veta la cuenta para siempre.

> **DIDÁCTICA — Eventos por intento**: con S1 activo, `MfaVerificationFailed` se publica en **cada** fallo: la metadata `attempts` reporta los intentos restantes (presupuesto aún disponible) o `MaxAttempts` para el fallo que dispara el lockout. Sin S1 (legacy), el evento se emitía únicamente en el fallo que disparaba el bloqueo.

> **DIDÁCTICA — Lockout escalonado**: `InMemoryAccountProtectionService` guarda el
> `EscalationLevel` entre episodios; el 2º bloqueo de una misma cuenta dura 30 min (nivel 2), el
> 3º 1 h, etc. `LockEnd` se calcula como `now + GetLockDuration(level)`, con techo `MaxLockDuration`.
> Los fallos durante un lockout activo se **ignoran** (no gastan presupuesto, no extienden el lock).

### 4.9. Estado post-verificación, verify-action y contraseña (S3, v3.2.0)

**Ventana `mfa_verified`**: `IdentityOrchestrator.CompleteMfaLoginAsync` marca la ventana con el
método verificado (`SetVerifiedAsync(userId, method.ToLowerInvariant())`) **solo** cuando el login
MFA es exitoso — un fallo de MFA nunca la abre. La ventana es **aditiva**: sin
`IMfaVerifiedSessionStore` registrado, el flujo es exactamente el anterior.

**Step-up `VerifyActionOrchestrator`** (`AddVerifyAction()`):

| Método | Comportamiento |
| :--- | :--- |
| `SendVerifyCodeAsync(userId, channel, cancellationToken)` | Valida el canal (`VerifyActionChannel.Email`), aplica el **throttle duro** por usuario (H1, auditoría: `MaxSendsPerWindow` = 3 por ventana, siempre activo aunque S1 no esté habilitado), dispara el envío vía `IEmailOtpSender` y SOLO tras una entrega satisfactoria guarda el hash del OTP (`IEmailOtpStore`, TTL/`CodeLength` de `VerifyActionOptions`). Cada envío consume una unidad del scope `VerifyAction` de S1 (anti email-flood); al agotarse devuelve fallo genérico. Errores del sender → failure genérico sin persistir el hash ni consumir presupuesto (M2, auditoría; no-enumeración). |
| `VerifyActionAsync(userId, code, cancellationToken)` | Rechaza códigos con longitud distinta a `CodeLength` (H3, auditoría) antes de tocar el store. Valida con S1: fallo → consume presupuesto (el fallo que dispara lockout devuelve fallo genérico). Código correcto → consume **atómico** el single-use, `RecordSuccessAsync` + renueva el throttle duro (renuevan presupuesto), abre la ventana `mfa_verified` con el método verificado y dispara `VerifyActionCompleted` (éxito) o `VerifyActionFailed` (fallo). |

**Contraseña con step-up — `ChangePasswordOrchestrator`** (`AddChangePassword()`):

- `CreateAsync(userId, newPassword, cancellationToken)`: para cuentas **sin contraseña todavía**
  (flujo passwordless → password). Exige la ventana de verify-action **abierta** (M1, auditoría):
  el OTP ya se consumió en `VerifyActionAsync` (single-use), así que aquí solo se comprueba
  `IMfaVerifiedSessionStore.IsVerifiedAsync(userId)`; sin ventana → fail-closed
  `verify_action_required`. Code 409 `password_already_exists` si la cuenta ya tiene contraseña
  (invariante de idempotencia, no un fallo de seguridad).
- `ChangeAsync(userId, currentPassword, newPassword, cancellationToken)`: valida la contraseña
  actual con el hasher; devuelve `invalid_current_password` si no coincide (y consume el presupuesto
  `PasswordChange` de S1 — M4, auditoría — si está habilitado; la contraseña actual se acota a 1024
  caracteres antes de Argon2 para evitar amplificación de memoria/CPU — H3, auditoría). Si la cuenta
  no tiene contraseña registrada → `no_password_created`. `SuccessRehashNeeded` detecta hash
  desactualizado y lo actualiza.
- Ambos rotan el **SecurityStamp** (call a `IUserStore.UpdateSecurityStampAsync`), invalidan la
  caché de stamps (`SecurityStampValidator.InvalidateAsync`), revocan **todas** las sesiones previas
  (`RevokeAllAsync`) — re-emitiendo **un nuevo par de tokens** cuya familia de refresh es **nueva**
  (incluida la familia en uso) — y disparan `SecurityStampUpdated` (stamp: nuevo).
- Política de contraseña (NIST SP 800-63B): 8–1024 caracteres; **sin** reglas de composición;
  rechazo → fallo genérico (`invalid_password`).

> **NOTA**: `ChangePasswordOrchestrator` acepta `IPasswordHasher` e `ITokenService` opcionales
> (null → se resuelven de DI); `IUserStore` y `ISecurityStampValidator` son **requeridos** (sin
> implementación registrada, `AddChangePassword()` falla en ValidateOnBuild). Los endpoint
> `/create-password` y `/change-password` devuelven el **nuevo par de tokens** en el body
> (`success.tokens`) para que el cliente adopte la nueva familia.

### 4.10. Recovery codes de primera clase (F5, v3.2.0)

Los recovery codes de emergencia como **ciudadanos de primera clase** (A-18/A-20), no como un
string plano hasheado y olvidado (legacy `MfaOrchestrator.SetRecoveryCodesAsync`).

**`RecoveryCodeOrchestrator`** — `AddMfa()` lo registra siempre; `EnableRecoveryCodes` es
**late-bound** y se valida en cada llamada (un host que no lo quiera simplemente no mapea los
endpoints de §5.3).

| Método | Comportamiento |
| :--- | :--- |
| `GenerateAsync(userId)` | Valida `EnableRecoveryCodes`; guard defensivo `RecoveryCodeCount >= 1` (B5, auditoría: un count inválido NO invalida el lote anterior); genera `RecoveryCodeCount` códigos CSPRNG, hashea cada uno (SHA-256 hex minúsculas; rechazo barato `RecoveryCodeMaxLength = 128` antes de hashear), persiste SOLO hashes con TTL `MfaOptions.RecoveryCodeLifetimeDays` (default 90, rango [1,365]), invalida el lote anterior (`InvalidatePendingAsync`) y emite el evento `RecoveryCodesGenerated`. Devuelve los códigos en claro **una sola vez**. La regeneración se **serializa por usuario** con `IOperationLock` (B2, auditoría): dos `GenerateAsync` concurrentes (doble clic) no pueden intercalar el índice y dejar un lote de tokens S2 huérfanos redimibles. |
| `VerifyAsync(userId, code)` | Hash + `GetStatusAsync` (peek no consumidor). `IsValid` solo si el código es redimible. Con S1, cada fallo consume el scope `Recovery`; si el scope está bloqueado responde no válido (genérico, sin revelar el bloqueo). Éxito → `RecordSuccessAsync`. Un fallo que NO dispara lockout emite `RecoveryCodeVerificationFailed` (B3, auditoría). |
| `UseAsync(userId, code)` | Hash + `RedeemAsync` (single-use vía S2, serializado con `IOperationLock` por código — A2, auditoría). Éxito → `RecoveryCodeRedeemed` + `RecordSuccessAsync` (limpia el scope `Recovery`). Fallo → `RecordFailureAsync`; el fallo que dispara el lockout responde `LockedOut` (→ 429 en el endpoint) y emite `AccountLockedOut` con metadata `scope=recovery`, `reason=lock_triggered`; el fallo que NO dispara lockout emite `RecoveryCodeRedemptionFailed` (B3, auditoría). |

**Eventos nuevos**: `RecoveryCodesGenerated`, `RecoveryCodeRedeemed`, `RecoveryCodeVerificationFailed`, `RecoveryCodeRedemptionFailed` (ver §6.1).

> **DIDÁCTICA — ¿Por qué el SPI tiene 4 métodos y el plan F5 pedía 3?** El plan (Tarea 5.1)
> definía `Create`/`Redeem`/`Invalidate`. Sin `GetStatusAsync`, `VerifyAsync` no puede distinguir
> "es redimible" de "ya consumido" SIN CONSUMIR el código (y `RedeemAsync` debe seguir siendo el
> único camino de consumo). El peek no consumidor es la pieza que hace viable la verificación
> pre-login sin gastar el código de emergencia.

> **DIDÁCTICA — El flujo de negocio es del HOST (A1, auditoría F5)**: el endpoint `use` consume
> el código y emite el evento, pero completar el login es **`IdentityOrchestrator
> .CompleteMfaLoginWithRecoveryCodeAsync`** (§4.1) — el host NO debe reimplementar la emisión de
> tokens a mano: `CompleteMfaLoginAsync` exige un código TOTP/email y no puede verificar un
> recovery code. El `mfaSessionToken` se valida en `use`/`verify` SIN consumirse para que el host
> lo reutilice después en ese flujo.

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

> **DIDÁCTICA — Resolución scoped**: `SecurityStampValidator` es **scoped** y el middleware lo resuelve **por request** (vía `InvokeAsync`), no en su constructor. Los middleware se construyen una sola vez para toda la aplicación; inyectar un servicio scoped en el constructor crearía una **captive dependency** (una instancia scoped retenida por el root provider) y fallaría con `ValidateOnBuild`/`ValidateScopes`. Resolverlo por request garantiza que el validador siempre opere con un scope de request válido.

### 5.3. Endpoints Automáticos
`app.MapSecureAuthEndpoints("/base-path")` registra:
- `POST /login`: Recepción de credenciales.
- `POST /refresh`: Rotación de Refresh Tokens.
- `POST /logout`: Revocación del token actual.
- `POST /revoke-all`: Reset global de sesiones (cambio de SecurityStamp).
- `POST /forgot-password`: Inicio de flujo de recuperación.
- `POST /reset-password`: Confirmación y cambio de credenciales.

**S3 (v3.2.0) — endpoints opt-in** (requieren unos y autenticación Bearer; el `userId` proviene del
claim `sub`; respuestas con mensajes genéricos; 503 si el orquestador no está registrado):
- `POST /verify-action/send`: sin cuerpo — envía OTP de step-up (usuario por claim `sub`; canal fijo email en esta versión).
- `POST /verify-action/verify`: `{ code }` — consume el OTP y abre la ventana.
- `POST /create-password`: `{ newPassword }` — crea contraseña (requiere ventana de step-up abierta; sin `otp` en el cuerpo).
- `POST /change-password`: `{ currentPassword, newPassword }` — cambia contraseña (sin step-up).

**F6 (v3.2.0) — perfil autenticado**:

- `GET /me` — perfil del usuario autenticado (Bearer): `{ id, email, hasPassword, twoFactorEnabled, mfaEnrollmentStatus, preferredMfaMethod }`. `hasPassword` se lee del store en cada llamada (nunca de un claim, que mentiría tras crear la contraseña). 503 `me_not_configured` sin `IUserStore`; usuario no encontrado → 401 genérico. Es la pieza que permite a un cliente passwordless-first mostrar "tu cuenta no tiene contraseña" y ofrecer `/create-password`.

**F5 (v3.2.0) — recovery codes opt-in** (mapper dedicado `MapSecureAuthRecoveryCodesEndpoints(prefix = "/auth/recovery-codes")`;
requiere `AddMfa()`; respuestas genéricas y anti-enumeración; 503 si el orquestador no está registrado):

- `POST /generate`: autenticado — regenera el lote y devuelve los códigos en claro **una sola vez** (400 `recovery_codes_disabled` si `EnableRecoveryCodes=false`).
- `POST /verify`: anónimo, `{ mfaSessionToken, code }` — comprueba si el código es redimible **sin consumirlo**; responde `{ valid }` (anti-enumeración: token/código inválidos responden igual). Limitado por IP con el presupuesto keyed `"recovery-verify"` (`SecureAuthOptions.RecoveryVerifyRateLimiter`, default 10/min; B1, auditoría).
- `POST /use`: anónimo, `{ mfaSessionToken, code }` — consume el código (single-use atómico); 200 `{ redeemed: true }`, 429 `too_many_attempts` si el scope `Recovery` está bloqueado, 400 `invalid_code` genérico. Limitado por IP con el presupuesto keyed `"recovery-use"` (`SecureAuthOptions.RecoveryUseRateLimiter`, default 5/min; B1, auditoría). El éxito resetea el presupuesto por IP (no penalizar al legítimo).

> **DIDÁCTICA — por qué mapper dedicado y no dentro de `MapSecureAuthEndpoints`**: sigue el
> precedente de `MapSecureAuthWebAuthnEndpoints` (S4): cada subdominio opt-in de MFA agrupa sus
> rutas en su propio método. Además `verify`/`use` son anónimos pero tutelados: la cuenta se
> resuelve desde el `mfaSessionToken` (nunca desde un `userId` del cuerpo), impidiendo probar
> códigos contra cuentas arbitrarias.

**A-24 (v3.2.0) — Blacklist de access tokens (opt-in)**:

La revocación real de access tokens la aportan el SecurityStamp (global) y el RTR (familia); un
logout de sesión individual no rota el stamp, por lo que el access token seguiría vivo hasta
expirar. Para hosts que necesitan revocarlo:

- `ITokenBlacklist` (SPI): `AddAsync(jti, ttl)` / `IsBlacklistedAsync(jti)`. Default registrado
  `NoOpTokenBlacklist` (no-op) → sin una implementación real del host, **el comportamiento no
  cambia** (D-03).
- El endpoint `POST /logout` extrae el `jti` del access token (parseo sin validación) y lo
  blacklistea con TTL = vida restante.
- La validación JWT (hook `OnTokenValidated`) rechaza los jti blacklisted por request.
- El host registra su implementación (in-memory, Redis, etc.) ANTES de `AddSecureAuth()` (TryAdd).

**F7 (v3.2.0) — Kit HTTP componible (A-26)**:

La superficie HTTP deja de ser un bundle all-or-nothing:

- **Handlers públicos por feature** (`SecureAuthEndpoints.LoginHandler`, `MeHandler`, `RefreshHandler`,
  `LogoutHandler`, `RevokeAllHandler`, `ForgotPasswordHandler`, `ResetPasswordHandler`,
  `VerifyActionSendHandler`, `VerifyActionVerifyHandler`, `CreatePasswordHandler`, `ChangePasswordHandler`
  + `GenerateRecoveryCodesHandler`/`VerifyRecoveryCodeHandler`/`UseRecoveryCodeHandler` y los de
  `SecureAuthWebAuthnEndpoints`). El host los re-rutea: `app.MapPost("/custom", SecureAuthEndpoints.LoginHandler)`.
- **`AuthEndpointDescriptor`** (declarativo: Method, Route, Handler, authz, filtros, name, description)
  y **`MapAuthEndpoints(prefix, params descriptors)`** como compositor genérico (OCP: una feature
  nueva es un descriptor nuevo; el compositor no se modifica).
- **Mappers por grupo**: `MapSecureAuthSessionEndpoints` (login/me/refresh/logout/revoke-all),
  `MapSecureAuthPasswordResetEndpoints` (forgot/reset), `MapSecureAuthCredentialEndpoints`
  (create/change-password), `MapSecureAuthVerifyActionEndpoints` (verify-action/send|verify).
  `MapSecureAuthEndpoints` = composición de todos (no-breaking). Recovery y WebAuthn también son
  descriptores.
- **`EnforceAnonymousRequestSizeLimit` público**: reutilizable en la superficie propia del host.

**Wiring uniforme (F7 + F8)**: `SecureAuthOptions` se registra una vez y el merge appsettings ↔ Fluent
es estructural (F8): un `SecureAuthOptionsBootstrap` vincula `SecureAuth:`, `SecureAuth:Jwt:` y
`SecureAuth:Argon2:` y ejecuta el `configure` del host sobre esas instancias (appsettings = base,
Fluent = overlay). La validación JWT Bearer se configura desde `IOptions<JwtOptions>` (misma fuente
que la emisión). `MfaOptions` usa `BindConfiguration` + el `configure` de `AddMfa` sobre la instancia
vinculada. El stack MFA/password usa `TryAdd*` (overrides del host respetados). Los handlers
anónimos se auto-protegen con un check de `Content-Length` intrínseco (la protección viaja con el
handler re-ruteado). `SecureAuthConfiguration.Mfa` quedó `[Obsolete]` (dead property; eliminar en v4).

---

## 6. Seguridad y Observabilidad

### 6.1. Sistema de Eventos
El sistema despacha eventos de dominio asíncronos mediante `IAuthEventDispatcher`. El implementador puede suscribirse registrando un handler `IAuthEventHandler` en DI.

**Eventos Clave:**
- `LoginSuccess`: Login exitoso procesado.
- `LoginFailed`: Credencial inválida (con metadatos de intentos).
- `AccountLockedOut`: Cuenta bloqueada por exceso de intentos fallidos.
- `TokenRotated`: Refresh Token rotado exitosamente.
- `Logout` / `GlobalLogout`: Cierre de sesión individual / de todas las sesiones.
- `SuspiciousActivityDetected`: Detectado intento de reuso de un Refresh Token ya rotado.
- `PasskeyRegistered` / `PasskeyLoginSuccess`: Registro y login con WebAuthn/Passkey.
- `PasswordResetRequested`: Solicitud de reset iniciada por email.
- `PasswordResetCompleted`: Cambio de contraseña exitoso mediante token.
- `MfaEnrolled` / `MfaDisabled` / `MfaVerificationSuccess` / `MfaVerificationFailed`: Eventos del flujo MFA.
- `RecoveryCodesGenerated` / `RecoveryCodeRedeemed` (v3.2.0, F5): lote de recovery codes generado / código redimido (consumido) con éxito.
- `RecoveryCodeVerificationFailed` / `RecoveryCodeRedemptionFailed` (v3.2.0, F5): verificación/redención de recovery code fallida sin disparar lockout (B3, auditoría; paridad con `MfaVerificationFailed`).
- `AnonymousLoginFailed` (v3.1.5): Intento de login con email/usuario inexistente. `UserId = null`, sin datos sensibles en Metadata (anti-enumeración).
- `RateLimitExceeded` (v3.1.5): Rate limit de IP excedido en `/auth/login`. `UserId = null`.
- `PasskeyVerificationFailed`, `SecurityStampChanged`, `PasswordChangeFailed` (v3.1.5): Reservados para uso futuro.

**Enriquecimiento automático con contexto HTTP (v3.1.5):**
`AuthEventContextEnricher` es un decorator de `IAuthEventDispatcher` registrado automáticamente en DI. Agrega a `Metadata` sin intervención del implementador:
- `ip`: `RemoteIpAddress` (IP real de la conexión TCP).
- `path`: ruta del request.
- `ua`: header `User-Agent`.
- `xff`: header `X-Forwarded-For` (puede ser suplantado; se guarda separado de `ip`).
- `roles`: claims de rol del usuario autenticado (del `ClaimsPrincipal` ya validado por el middleware JWT).

**`AuthEvent.UserId` nullable (v3.1.5):** permite eventos anónimos (`AnonymousLoginFailed`, `RateLimitExceeded`) sin usuario identificado. Los handlers deben validar `UserId` antes de actuar sobre él.

### 6.2. Mitigación contra Enumeración
El framework garantiza un tiempo de respuesta constante en fallos de autenticación mediante la inyección de operaciones de hashing ficticias cuando no se localiza el usuario en el almacén de datos.

### 6.3. Uso adecuado de X-Forwarded-For

El header `X-Forwarded-For` (XFF) es informativo y **no se usa como clave de rate limiting ni como base de decisiones de seguridad** en la librería:

- **Rate limit por IP** (`/auth/login`): usa `Connection.RemoteIpAddress` (la IP real de la conexión TCP), **no** lee `X-Forwarded-For`. Enviar XFF no lo evade.
- **Verificación TOTP y enrollment**: el rate limit es **per-usuario** (`MfaFailedAttemptsCount`), independiente de la IP o del XFF.
- **Auditoría**: `AuthEventContextEnricher` guarda `xff` como metadato informativo, separado de `ip` (que es la IP real de la conexión).

**Cuándo usar XFF**: solo si la API está detrás de un proxy inverso (nginx, HAProxy, load balancer, Cloudflare), donde `RemoteIpAddress` es la IP del proxy. En ese caso, configure `ForwardedHeaders` de ASP.NET Core (`UseForwardedHeaders`) para que `RemoteIpAddress` refleje la IP real del cliente de forma **controlada** (solo confiando en los proxies configurados). Sin eso, detrás de un proxy todos los usuarios comparten la clave de rate limit.

**Riesgo**: si un implementador implementa un `IRateLimiter` personalizado usando el header `X-Forwarded-For` como clave, **un atacante puede evadir el rate limit falsificando el header**. No lo haga sin validar el origen del header (proxies de confianza).

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
| **Anti-Replay de State** | Previene reutilización del state OAuth. | `ConsumeAsync` delega en `ISingleUseTokenStore` (§3.5) — sobrescribible por una implementación atómica (Redis GETDEL/Lua). |

> **NOTA DE SEGURIDAD - TOCTOU en OAuth State**: Desde v3.2.0, `ConsumeAsync` de `DistributedCacheOAuthStateStore` delega en el SPI `ISingleUseTokenStore`. La implementación por defecto (`DistributedCacheSingleUseTokenStore`) usa GET + REMOVE no atómico (ventana de race ~1 ms).
>
> Para aplicaciones de alto riesgo que requieren operación atómica, implemente su propio `ISingleUseTokenStore` usando Redis con el comando GETDEL (o una operación transaccional equivalente); `DistributedCacheOAuthStateStore` la consumirá automáticamente. El riesgo en la práctica es mínimo para la mayoría de aplicaciones.

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

`JwtTokenService` incluye un blocklist `SystemClaims` que previene la inyección de claims sensibles desde `UserIdentity.Claims`. A partir de v3.1.0, este blocklist es configurable mediante `JwtOptions.AllowedSystemClaims`:

- **Por defecto**: Todos los system claims están bloqueados, incluyendo `role` y `roles`.
- **Para habilitar RBAC**: Agregar `"role"` y `"roles"` a `AllowedSystemClaims`. Esto permite inyectar roles desde `UserIdentity.Claims` para usar `[Authorize(Roles = "...")]`.

```csharp
// Habilitar RBAC en el JWT
options.Jwt.AllowedSystemClaims = new HashSet<string> { "role", "roles" };
```

> **v3.1.4 (fix)**: El Fluent API ahora propaga `AllowedSystemClaims` a los `JwtOptions` efectivos. Antes, configurarla solo vía Fluent API dejaba la lista vacía (RBAC roto). El bind por `appsettings.json` (`SecureAuth:Jwt:AllowedSystemClaims`) sigue soportado.

> **v3.1.5**: `ITokenService.GenerateAccessToken(UserIdentity, TimeSpan? lifetime = null)` acepta un TTL opcional. Si es null, usa el TTL global o el resuelto por `AccessTokenLifetimeProvider`.

**Claims bloqueados por defecto:**
- **Identidad**: `sub`, `email`, `name`
- **Control de token**: `jti`, `iss`, `aud`, `exp`, `iat`, `nbf`
- **Seguridad**: `ssv` (SecurityStamp), `nonce`
- **Autorización**: `role`, `roles`, `auth_time`, `amr`, `acr`, `azp`

Cualquier intento de sobrescribir estos claims via `UserIdentity.Claims` es ignorado silenciosamente, a menos que se permita explícitamente en `AllowedSystemClaims`.

### 7.6. OAuth SignIn Options (v3.1.0)

`OAuthSignInOptions` incluye nuevas propiedades para autenticación basada en cookies HttpOnly y para configurar el `redirect_uri` de OAuth:

| Propiedad | Tipo | Default | Descripción |
| :--- | :--- | :--- | :--- |
| `SetCookiesDirectly` | `bool` | false | Si es true, setea cookies HttpOnly y redirige al SPA en lugar de retornar JSON. |
| `CookieDomain` | `string?` | null | Dominio de las cookies (ej. ".example.com" para subdominios). |
| `PostLoginRedirectUrl` | `string?` | null | URL de redirección post-login para el SPA. Default: "/". |
| `PublicBaseUrl` | `string?` | null | Base pública de la API usada como `redirect_uri` del proveedor. Si es null, se deriva del request (scheme + host). Configúrala explícitamente si la API está detrás de un load balancer / TLS termination. |
| `CallbackPrefix` | `string` | `/auth/oauth` | Prefijo de ruta donde se mapean los endpoints OAuth. El `redirect_uri` del proveedor se construye como `{base}{CallbackPrefix}/{provider}/callback`. |
| `AllowedPostLoginHosts` | `string[]` | `[]` | Hosts extra permitidos como destino post-login del SPA. El query param `redirectUri` de `/authorize` solo se acepta si es https y su host está en esta lista o coincide con `PostLoginRedirectUrl`. Previene open redirect. |

```csharp
// Activar cookies HttpOnly para OAuth
services.Configure<OAuthSignInOptions>(opts =>
{
    opts.SetCookiesDirectly = true;
    opts.CookieDomain = ".example.com";
    opts.PostLoginRedirectUrl = "https://app.example.com/dashboard";
});
```

### 7.7. IMfaCodeStore — Almacenamiento de Códigos MFA (v3.1.0)

Nueva interfaz para almacenar y validar códigos MFA temporales (email):

```csharp
public interface IMfaCodeStore
{
    Task StoreCodeHashAsync(string key, string codeHash, TimeSpan ttl, CancellationToken ct);
    Task<bool> ValidateAndRemoveCodeAsync(string key, string code, CancellationToken ct);
}
```

**Implementación por defecto**: `DistributedCacheMfaCodeStore` usa `IDistributedCache` (compatible con MemoryCache, Redis, SQL Server).

**Seguridad**:
- Los códigos se almacenan como hash SHA-256, nunca en texto plano.
- La validación usa `CryptographicOperations.FixedTimeEquals` para prevenir timing attacks.
- Los códigos son single-use: se eliminan tras el primer intento de validación.

> **REQUISITO para MFA por email**: El `EmailMfaService` (implementación por defecto de `IEmailMfaService`) envía los códigos mediante `IEmailService`. SecureCore registra un `NullEmailService` por defecto (vía `TryAddScoped`) que **lanza** `InvalidOperationException` al usarse. Debes registrar tu propia implementación de `IEmailService` **antes** de `AddMfa()`/`AddPasswordAuthentication()`:
> ```csharp
> services.AddScoped<IEmailService, MyEmailService>();
> ```

### 7.11. Seguridad del flujo MFA/TOTP (v3.1.6)

Endurecimiento del enrollment y verificación MFA:

1. **Enrollment vinculado al token de sesión**: `CompleteEnrollmentAsync(userId, code, mfaSessionToken)` valida que el `mfaSessionToken` pertenezca al `userId` y lo **consume** (single-use). Solo quien inició el enrollment puede completarlo.

> **v3.1.8 (fix)**: el single-use del token ahora es real. El `jti` consumido se registra en `IMemoryCache` (expiración = `ValidTo` del token); una reutilización devuelve `null`. El claim `sub` se lee también como `ClaimTypes.NameIdentifier` (por el mapeo de `JwtSecurityTokenHandler`). Nota: el blacklist es in-memory (single-instance); para multi-instancia, sustituir `IMfaSessionStore` por una implementación distribuida.
2. **Anti-overwrite del secreto TOTP**: `StartEnrollmentAsync` rechaza si el usuario está `Enrolled` o si hay un enrollment `Pending` con secreto. `DisableAsync` permite cancelar un enrollment pendiente (evita quedar atascado si el token expiró).
3. **Anti-TOCTOU (fingerprint)**: se embebe un hash SHA-256 del secreto en el `mfaSessionToken`. Si el secreto cambia entre Start y Complete, la completación se rechaza.
4. **Single-use del código TOTP**: el mismo código no puede completar el enrollment ni verificar el login dos veces dentro de la ventana de tolerancia (±1 paso). Se marca como usado en `IMfaCodeStore` (clave `mfa_totp_used_code:{userId}`).
5. **Rate-limit de enrollment**: `CompleteEnrollmentAsync` aplica `MaxVerificationAttempts` (incrementa al fallar, resetea al acertar).
6. **Lockout temporal (no permanente)**: al superar `MaxVerificationAttempts` se fija `LockoutEnd = UtcNow + CodeRetryWindowMinutes`. Al expirar la ventana, el contador se resetea automáticamente. No sobrescribe un lockout de contraseña activo más largo.
7. **Base32 RFC 4648**: `TotpService` genera secretos de 20 bytes → 32 caracteres, sin pérdida de entropía (corrige el encoder anterior que producía 40 caracteres y ~140 bits efectivos).

#### 7.11.1. Flujo post-enrollment — sugerencia de autenticación

`CompleteEnrollmentAsync` retorna `true` cuando el usuario verifica un código de enrollment válido. Ese momento constituye una **prueba real de posesión del factor MFA**. La librería **no** emite tokens automáticamente al completar el enrollment; la política de continuación es decisión del implementador.

**Herramientas disponibles** (todas públicas): `CompleteEnrollmentAsync`, `VerifyAsync`, `CompleteMfaLoginAsync`, `ITokenService.GenerateTokenPairAsync`, `ISessionStore.CreateAsync`.

**Sugerencia**: tratar la completación exitosa del enrollment como una verificación MFA completada y emitir la sesión con la marca `amr=mfa` + `mfa_method`, sin re-solicitar código.

**Alternativas válidas**: re-autenticación posterior con un nuevo código (p. ej. tras 30 segundos), contraseña + nuevo código, o cualquier otra política definida por el implementador.

**Malas prácticas a evitar:**
1. Reutilizar el mismo código TOTP del enrollment para la verificación de login inmediata (falla por single-use del código, ventana ±1 paso; es comportamiento diseñado, no un bug).
2. Emitir `amr=mfa` o tokens sin que `CompleteEnrollmentAsync` haya retornado `true`.
3. No persistir el refresh token en `ISessionStore` al emitir sesión post-enrollment (sesión huérfana / no revocable).
4. No resetear `MfaFailedAttemptsCount` tras un enrollment exitoso.
5. Dejar reutilizable el `mfaSessionToken` del enrollment (debe consumirse, single-use).

### 7.8. OAuthClaimHelper — Extracción Segura de Claims OIDC

Helper estático en `SecureCore.Auth.OAuth` que extrae claims de `JwtSecurityToken` preservando los tipos cortos originales del JWT (evitando el mapeo a URIs que hace `ClaimsPrincipal`):

```csharp
// Uso en validadores OAuth:
var sub = OAuthClaimHelper.GetClaim(jwt, "sub");
var email = OAuthClaimHelper.GetClaim(jwt, "email");
```

### 7.9. redirect_uri de OAuth y Normalización de URLs

El `redirect_uri` del proveedor OAuth es **siempre la URL del callback de la API** (`{base}{CallbackPrefix}/{provider}/callback`), nunca la URL del SPA. Los proveedores (Google, Microsoft, etc.) exigen que coincida exactamente con el registrado en su consola, tanto en el request `/authorize` como en el intercambio de tokens de `/callback`.

La URL del callback se calcula una sola vez en `/authorize` (usando `PublicBaseUrl` o derivándola del request) y se guarda en el state de OAuth para que `/callback` reutilice exactamente el mismo valor (sin drift).

El endpoint `/authorize` normaliza la `redirectUri` eliminando el prefijo `www.` del host para coincidir con los redirect URIs registrados. El query param `redirectUri` es el **destino post-login del SPA** (no el `redirect_uri` del proveedor); solo se acepta si es https y su host está en `AllowedPostLoginHosts` o coincide con `PostLoginRedirectUrl`; de lo contrario el request falla con `400 invalid_redirect_uri`.

> **Requisito de deploy**: registra la URL exacta del callback de la API en cada consola de proveedor (ej. `https://api.example.com/auth/oauth/google/callback`).

### 7.10. CI/CD (v2.4.0)

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

#### Throttling dedicado de `/forgot-password` (v3.2.0)

El endpoint anónimo `/forgot-password` usa un limiter **dedicado y keyed** (`"forgot-password"` en DI), para no compartir presupuesto con el de login. Se configura con `SecureAuthOptions.ForgotPasswordRateLimiter` (default: 5 solicitudes/hora por IP). El throttling es **silencioso**: al superarse el límite la solicitud se descarta pero se responde el mismo 200 ciego, sin oráculo al atacante.

En arquitecturas multi-instancia, reemplaza la implementación default (in-memory) por una distribuida:

```csharp
services.AddKeyedSingleton<IRateLimiter>("forgot-password",
    (sp, _) => new RedisRateLimiter(max: 5, window: TimeSpan.FromHours(1)));
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

