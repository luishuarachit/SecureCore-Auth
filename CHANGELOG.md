# Changelog

Todas los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.7] - 2026-08-01

### Añadido (integración de feat/audit-and-per-role-ttl)
- **Enriquecimiento automático de eventos de auditoría con contexto HTTP**:
  - `AuthEventContextEnricher`: decorator de `IAuthEventDispatcher` que captura `ip`, `path`, `ua` (User-Agent), `xff` (X-Forwarded-For) y `roles` del usuario autenticado desde `HttpContext`.
  - Se registra automáticamente en DI sin configuración adicional. Sin HttpContext (tests), el enricher no lanza error.
  - `IHttpContextAccessor` se registra como singleton si no existe.
- **Nuevos `AuthEventType` para auditoría**:
  - `AnonymousLoginFailed`: intento de login con email/usuario inexistente (UserId=null, sin datos sensibles en Metadata).
  - `RateLimitExceeded`: rate limit de IP excedido en `/auth/login` (UserId=null).
  - `PasskeyVerificationFailed`, `SecurityStampChanged`, `PasswordChangeFailed`: reservados para uso futuro.
- **`AuthEvent.UserId` ahora es nullable** (`string?`) para soportar eventos anónimos sin usuario identificado.
- **Per-role Access Token Lifetime**:
  - `SecureAuthOptions.AccessTokenLifetimeProvider`: `Func<UserIdentity, TimeSpan?>` configurable para TTL por rol.
  - `JwtTokenService` resuelve el provider durante `GenerateTokenPairAsync`. Fallback al TTL global (fail-secure).
  - `ITokenService.GenerateAccessToken` acepta `TimeSpan? lifetime` opcional (backwards compatible).

### Corregido
- `IdentityOrchestrator.SignInWithPasswordAsync` dispara `AnonymousLoginFailed` cuando el email/usuario no existe.
- `SecureAuthEndpoints.MapPost("/login")` dispara `RateLimitExceeded` antes del 429.

## [3.1.6] - 2026-08-01

### Corregido
- **`Base32Encode` no cumplía RFC 4648 (TOTP)** — pérdida de entropía y secreto malformado:
  - El encoder procesaba byte a byte en lugar de agrupar de a 5 bits cruzando límites de byte. Un secreto de 20 bytes colapsaba de 160 a ~140 bits de entropía efectiva y generaba 40 caracteres en vez de 32.
  - Reescrito con acumulador de bits (RFC 4648). `Base32Decode(Base32Encode(bytes)) == bytes` garantizado. Backwards-compatible con secretos existentes (la app y la librería decodifican el mismo string).
  - Validado contra vectores RFC 6238/4648/4226 conocidos.

- **`CompleteEnrollmentAsync` no vinculaba el enrollment al token de sesión (brecha)**:
  - Cualquier llamada con `userId` + código válido completaba el enrollment sin el `mfaSessionToken` de `StartEnrollmentAsync`.
  - Ahora se valida y consume el token (single-use), replicando el patrón del login MFA.

- **`StartEnrollmentAsync` sobrescribía el secreto TOTP sin control**:
  - No rechazaba re-enrollment de un usuario ya enrolado ni un enrollment pendiente con secreto, permitiendo que un atacante sobrescribiera el secreto activo con uno propio.
  - Ahora se rechaza si el usuario está `Enrolled` o si hay un enrollment `Pending` con secreto. `DisableAsync` permite cancelar un enrollment pendiente (evita quedar atascado si el token expiró).

- **Race (TOCTOU) entre Start y Complete del enrollment**:
  - Se embebe un fingerprint (SHA-256) del secreto TOTP en el `mfaSessionToken`. Si el secreto cambia entre Start y Complete, se rechaza la completación.

- **Single-use del código TOTP (enrollment y login)**:
  - El mismo código TOTP ya no puede completar el enrollment ni verificar el login dos veces dentro de la ventana de tolerancia (±1 paso). Se marca como usado en `IMfaCodeStore`.

- **Límite de intentos en enrollment**:
  - `CompleteEnrollmentAsync` ahora aplica `MaxVerificationAttempts` (incrementa al fallar, resetea al acertar).

- **`CodeRetryWindowMinutes` no se aplicaba — bloqueo MFA permanente**:
  - Al superar `MaxVerificationAttempts` se fija `LockoutEnd = UtcNow + CodeRetryWindowMinutes` (lockout temporal, no permanente).
  - Al expirar la ventana se resetea el contador automáticamente.
  - No sobrescribe un lockout de contraseña activo más largo.

- **`JwtMfaSessionService`**: refactor de validación para soportar el claim `secret_fingerprint` en el token de sesión MFA.

### Seguridad
- Auditoría interna T1–T11: 3 hallazgos adicionales corregidos (usuario atascado en Pending, acortamiento de lockout de contraseña, reuso de código TOTP en login).

## [3.1.5] - 2026-08-01

### Añadido
- **Enriquecimiento automático de eventos de auditoría con contexto HTTP**:
  - `AuthEventContextEnricher`: decorator de `IAuthEventDispatcher` que captura `ip`, `path`, `ua` (User-Agent), `xff` (X-Forwarded-For) y `roles` del usuario autenticado desde `HttpContext`.
  - Se registra automáticamente en DI sin configuración adicional. Sin HttpContext (tests), el enricher no lanza error.
  - `IHttpContextAccessor` se registra como singleton si no existe.

- **Nuevos `AuthEventType` para auditoría**:
  - `AnonymousLoginFailed`: intento de login con email/usuario inexistente (UserId=null, sin datos sensibles en Metadata).
  - `RateLimitExceeded`: rate limit de IP excedido en `/auth/login` (UserId=null).
  - `PasskeyVerificationFailed`, `SecurityStampChanged`, `PasswordChangeFailed`: reservados para uso futuro en PasskeyService y SessionOrchestrator.

- **`AuthEvent.UserId` ahora es nullable** (`string?`) para soportar eventos anónimos sin usuario identificado.

- **Per-role Access Token Lifetime**:
  - `SecureAuthOptions.AccessTokenLifetimeProvider`: `Func<UserIdentity, TimeSpan?>` configurable para TTL por rol (superadmin 15m, admin 30m, support 1h).
  - `JwtTokenService` resuelve el provider durante `GenerateTokenPairAsync`. Si null, lanza excepción o devuelve null → fallback al `AccessTokenLifetime` global (fail-secure).
  - `ITokenService.GenerateAccessToken` acepta `TimeSpan? lifetime` opcional (backwards compatible).
  - Requiere que el claim `role` fluya vía `JwtOptions.AllowedSystemClaims` (corregido en v3.1.4).

### Corregido

- `IdentityOrchestrator.SignInWithPasswordAsync` ahora dispara `AnonymousLoginFailed` cuando el email/usuario no existe (antes retornaba Failed sin evento).
- `SecureAuthEndpoints.MapPost("/login")` ahora dispara `RateLimitExceeded` antes del 429 (antes retornaba directamente sin evento).

## [3.1.4] - 2026-08-01

### Corregido
- **`AllowedSystemClaims` del Fluent API no se propagaba a `JwtOptions` — RBAC completamente roto**:
  - El `PostConfigure` de `JwtOptions` copiaba `Issuer`, `Audience`, `SigningKey`, `Algorithm`, `PrivateKey` y `PublicKey` desde el Fluent API, pero omitía `AllowedSystemClaims`. Como la sección `SecureAuth:Jwt` rara vez se define en `appsettings.json`, la lista efectiva quedaba vacía → `role`/`roles` siempre bloqueados → `[Authorize(Roles = "...")]` y policies `RequireClaim(ClaimTypes.Role, ...)` nunca funcionaban (siempre 403).
  - Fix: ahora el `PostConfigure` también copia `AllowedSystemClaims`. Sin breaking changes: si no se configura, la lista vacía mantiene el comportamiento seguro por defecto.

## [3.1.3] - 2026-08-01

### Corregido
- **OAuth `redirect_uri` apuntaba al SPA** — los providers rechazaban el flujo con `400 invalid_request`:
  - `/authorize` usaba la URL del SPA como `redirect_uri` del proveedor. Ahora se construye el **callback de la API** (`{PublicBaseUrl | scheme+host}{CallbackPrefix}/{provider}/callback`) y se guarda en el state para que `/callback` reutilice exactamente el mismo valor en el exchange (sin drift).
  - Nueva opción `OAuthSignInOptions.PublicBaseUrl` para cuando la API está detrás de un load balancer / TLS termination; `CallbackPrefix` configura la ruta del callback.

- **Open redirect post-login OAuth**:
  - El `redirectUri` del SPA en `/authorize` solo se acepta si es **https** y su host está en `AllowedPostLoginHosts` o coincide con `PostLoginRedirectUrl`; de lo contrario se responde `400` y se usa el fallback configurado. Previene ataques de open redirect.

- **`SecurityStampValidator` scoped resuelto desde root provider**:
  - `SecurityStampMiddleware` inyectaba el validador en el constructor (instancia única para toda la app). Con `ValidateScopes=true` el host fallaba al arrancar (`Cannot resolve scoped service ... from root provider`).
  - Ahora se resuelve **por request** vía el parámetro de `InvokeAsync`, evitando la captive dependency y usando el scope del request.

- **`EmailMfaService` rompía el arranque sin `IEmailService` registrado**:
  - Con `ValidateOnBuild=true`, el descriptor de `EmailMfaService` fallaba al no existir una implementación de `IEmailService`.

### Añadido
- **`NullEmailService` como default de `IEmailService`**:
  - `AddMfa()` y `AddPasswordAuthentication()` registran `TryAddScoped<IEmailService, NullEmailService>()`.
  - Si el consumidor no registra su implementación, `NullEmailService` **lanza `InvalidOperationException`** al intentar enviar (nunca falla silenciosamente). Sobrescribible registrando la implementación real **antes** de `AddMfa()`.

- **`OAuthSignInOptions.PublicBaseUrl`, `CallbackPrefix` y `AllowedPostLoginHosts`** para controlar el callback OAuth y los destinos post-login permitidos.

- **Tests de integración con `Microsoft.AspNetCore.TestHost`**:
  - `OAuthEndpointsTests`: verifica que el exchange usa el callback de la API (nunca la URL del SPA) y que el destino post-login se valida.
  - `EmailServiceRegistrationTests`: cubre el build con `ValidateOnBuild=true`, el throw de `NullEmailService` y el override por `TryAdd`.

### Modificado
- **`.gitignore`**: se añaden `dist/` y `*.pem` para evitar commit accidental de claves de prueba (`jwt_private.pem`) y artefactos de build.
- **Limpieza de whitespace**: `dotnet format whitespace` aplicado en toda la solución (trailing whitespace y line endings).
- **Soporte .NET 8 eliminado**: se removieron carpetas residuales `bin/Debug/net8.0` y `obj/*/net8.0`. El repositorio solo apunta a **.NET 10**.

### Documentación
- Guías de uso (ES/EN): nueva sección "MFA por email — Cómo enviar el código" y requisito de registro de `IEmailService`.
- Referencias técnicas (ES/EN): nota de resolución scoped del `SecurityStampValidator` en el pipeline y requisito de `IEmailService` para MFA por email.
- Prerrequisitos actualizados a `.NET 10 SDK`.

## [3.1.0] - 2026-07-27

### Corregido
- **RSA/ECDsa descartados en `CreateIssuerSigningKey`** (P3-19):
  - `RSA.Create()` y `ECDsa.Create()` se llamaban dentro de `using`, descartando las claves inmediatamente. Las operaciones JWT posteriores lanzaban `ObjectDisposedException`.
  - Se removió `using` y se agregó comentario explicativo (misma práctica que `JwtTokenService`).

- **Claims OAuth OIDC no encontrados por mapeo de tipos** (P3-20):
  - `principal.FindFirst("sub")` retornaba `null` porque `ClaimsPrincipal` mapea los claims del JWT a URIs completas (`ClaimTypes.NameIdentifier`).
  - Afectaba a Google, Apple, Microsoft y LinkedIn — `ProviderKey`, `Email`, `DisplayName` y `AvatarUrl` eran `null`.
  - Se creó `OAuthClaimHelper.GetClaim(jwt, "sub")` como helper compartido en `SecureCore.Auth.OAuth`.
  - Se aplicó el fix a los 4 validadores afectados.

- **Email MFA aceptaba cualquier código** (P3-21) — CRÍTICO:
  - `CompleteEnrollmentAsync` y `VerifyAsync` asignaban `isValid = true` incondicionalmente para `method == "email"`.
  - Ahora los códigos se almacenan como hash SHA-256 y se validan con `CryptographicOperations.FixedTimeEquals`.

- **Usuarios OAuth sin contraseña no podían deshabilitar MFA** (P3-22):
  - `DisableAsync` ahora solo verifica contraseña si `user.PasswordHash is not null`.
  - Para usuarios con contraseña, SIEMPRE se requiere verificarla.

- **Test pre-existente corregido**:
  - `InvokeAsync_AuthenticatedWithoutSsvClaim_CallsNext` esperaba `nextCalled = true` pero el middleware correctamente rechaza tokens sin `ssv` con 401. El test ahora valida el comportamiento correcto.

### Añadido
- **`IMfaCodeStore` — Almacenamiento de códigos MFA** (P3-21):
  - Nueva interfaz en `Abstractions` para almacenar y validar códigos MFA temporales.
  - `DistributedCacheMfaCodeStore`: implementación por defecto usando `IDistributedCache`.
  - Registro automático en DI vía `AddPasswordAuthentication()` y `AddMfa()`.
  - Códigos almacenados como SHA-256, validados con `FixedTimeEquals`, single-use.

- **`OAuthClaimHelper` — Extracción segura de claims OIDC** (P3-20):
  - Helper estático en `SecureCore.Auth.OAuth` que lee claims de `JwtSecurityToken` preservando tipos cortos.
  - Previene el bug de mapeo de tipos en todos los validadores futuros.

- **Cookies HttpOnly en callback OAuth** (P3-23):
  - Nuevas opciones en `OAuthSignInOptions`: `SetCookiesDirectly`, `CookieDomain`, `PostLoginRedirectUrl`.
  - Cuando se activa, el callback OAuth setea cookies HttpOnly y redirige al SPA.
  - Backward compatible: comportamiento por defecto sigue retornando JSON.

- **`JwtOptions.AllowedSystemClaims` — RBAC configurable** (P3-24):
  - `SystemClaims` ahora es configurable. Agregar `"role"`/`"roles"` a `AllowedSystemClaims` permite RBAC con `[Authorize(Roles = "...")]`.
  - Seguro por defecto: todos los system claims bloqueados.

- **Normalización de URLs OAuth** (P3-25):
  - El endpoint `/authorize` ahora elimina `www.` del host para coincidir con redirect URIs registrados en los providers.

### Modificado
- **`MfaOrchestrator`** ahora recibe `IMfaCodeStore` como dependencia (constructor actualizado).
- **`ServiceCollectionExtensions`**: `AddMfa` y `AddPasswordAuthentication` registran `IMfaCodeStore`.
- **`SecurityStampMiddlewareTests`**: test corregido para reflejar comportamiento real del middleware.

### Documentación
- Actualizadas referencias técnicas (ES/EN) con nuevas interfaces, opciones y secciones:
  - `JwtOptions.AllowedSystemClaims`, `IMfaCodeStore`, `OAuthClaimHelper`, `OAuthSignInOptions` extendido.
- Actualizadas guías de uso (ES/EN) con ejemplos de cookies HttpOnly.

## [3.0.0] - 2026-05-17

### Añadido
- **Sistema completo de Autenticación Multifactor (MFA)** (P3-14):
  - `MfaOrchestrator`: orquestador principal para enrollment y verificación MFA
  - `TotpService`: implementación nativa RFC 6238 de TOTP (sin librerías externas)
  - `AesMfaEncryptionService`: cifrado AES-256-GCM para secretos TOTP almacenados
  - `EmailMfaService`: códigos MFA temporales enviados por email
  - `IMfaSessionStore`: gestión de tokens de sesión MFA con expiry
  - `MfaOptions`: configuración flexible (habilitado/por defecto, métodos permitidos, códigos de recuperación)
  - Modelos: `MfaEnrollmentStatus`, `MfaMethod`, `MfaEnrollmentResponse`, `MfaVerificationResult`
  - Flujo completo: `StartEnrollmentAsync` → `CompleteEnrollmentAsync` → verificación en login

- **Rate Limiter integrado** (P3-15):
  - `IRateLimiter`: interfaz para limitación de tasa sliding window
  - `InMemoryRateLimiter`: implementación thread-safe con ConcurrentDictionary
  - `IOperationLock`: interfaz para locks de operaciones (previene race conditions)
  - `InMemoryOperationLock`: implementación para bloqueos temporales de operaciones

- **PasswordHasher asíncrono** (P3-16):
  - Nuevo `IPasswordHasher` con métodos async: `HashPasswordAsync`, `VerifyPasswordAsync`
  - `Argon2PasswordHasher` ahora soporta operaciones async para evitar bloqueo de threads HTTP
  - Documentación sobre uso de `Task.Run` para operaciones CPU-bound

- **Soporte para JWT con algoritmos asimétricos** (P3-17):
  - Soporte para RS256, ES256, ES384, ES512 (firma asimétrica RSA/ECDSA)
  - Nuevas propiedades en `JwtOptions`: `PrivateKey` (PEM), `PublicKey` (PEM)
  - `SigningKey` ahora es opcional (solo requerido para HS256)
  - `Algorithm` por defecto cambiado a RS256 (recomendado para producción)
  - Cacheo de `SigningCredentials` para evitar recrear claves en cada request

- **SampleApi con ejemplos MFA**:
  - `InMemoryUserStore` con implementación completa de interfaces MFA
  - Ejemplos de configuración de todos los servicios

### Modificado
- **Migración a .NET 10 LTS** (P3-18):
  - Actualización de todos los proyectos a .NET 10
  - Nuevo `Directory.Build.props` para estandarizar configuración de build
  - Targets, propiedades y versiones centralizadas

- **SecureAuthOptions expandido**:
  - Nuevas opciones para MFA, rate limiting, password hasher, JWT
  - Configuración de issuer/audience más flexible

- **Mejoras en validadores OAuth OIDC**:
  - Mejor manejo de JWKS con cacheo optimizado
  - Refactor para reutilización de lógica de validación

### Documentación
- **Actualización completa de documentación técnica y de uso**:
  - docs/en/technical-reference.md: referencia técnica completa actualizada
  - docs/en/usage-guide.md: guía de uso en inglés
  - docs/es/guia-de-uso.md: guía de uso en español
  - docs/es/referencia-tecnica.md: referencia técnica en español
  - Cobertura de todas las nuevas features: MFA, rate limiting, algoritmos asimétricos

## [2.4.0] - 2026-05-15

### Corregido
- **Claims duplicados en `JwtTokenService.GenerateAccessToken`** (P3-8):
  - `sub` y `email` se incluían tanto en `Subject` como en `Claims` del JWT, generando claims duplicados.
  - Se eliminaron del diccionario `Claims`, dejándolos solo en `Subject`.

### Añadido
- **Validación de claims JWT con blocklist** (P3-12):
  - Nuevo `HashSet<string>` `SystemClaims` que bloquea 17 claims gestionados por el sistema (`sub`, `email`, `jti`, `ssv`, `iss`, `aud`, `role`, etc.).
  - Los claims de `UserIdentity.Claims` que coincidan con estos se ignoran silenciosamente, previniendo inyección de claims peligrosos.
- **`ErrorCode` estandarizado en `OAuthSignInResult`** (P3-13):
  - Nueva propiedad `ErrorCode` con códigos tipo `oauth_provider_not_configured`, `oauth_user_not_found`, `oauth_account_locked`, `oauth_validation_failed`, `oauth_invalid_request`, `oauth_factory_not_registered`.
  - Actualizados todos los callers en `OAuthOrchestrator` para incluir el código en cada `Failure()`.
- **Tests de integración OAuth** (P3-10):
  - Nuevo proyecto `SecureCore.Auth.OAuth.Tests` con 9 tests para `OAuthOrchestrator`.
  - Cobertura: provider no configurado, request inválido, validación fallida, usuario no encontrado, cuenta bloqueada, registro implícito (con y sin factory), flujo code, flujo id_token.
- **CI/CD + analizadores de código** (P3-11):
  - Nuevo flujo de GitHub Actions (`.github/workflows/ci.yml`) con build, test y verificación de formato.
  - Nuevo `.editorconfig` con reglas de estilo para C# 12 (primary constructors, pattern matching, file-scoped namespaces, sealed class, etc.).

## [2.3.0] - 2026-05-15

### Modificado
- **Refactor y retry JWKS en 4 validadores OIDC**:
  - Google, Microsoft, LinkedIn, Apple: refactor a 3 métodos (`ValidateIdTokenAsync`, `CoreAsync`, `WithKeysAsync`) para reutilización en retry.
  - Retry automático ante `SecurityTokenSignatureKeyNotFoundException` o `SecurityTokenInvalidSignatureException` (rotación de llaves).
  - `GetSigningKeysAsync` ahora con `forceRefresh` y double-checked locking.
  - Caché JWKS con `_keysCache.HasValue` (se descartó pattern matching `{ Expiry: expiry }` por CS0165/CS9135).
- **Unificación de `DateTime`** en `OAuthOrchestrator`:
  - `DateTimeOffset.UtcNow.UtcDateTime` → `DateTime.UtcNow` en los 3 dispatchs de eventos.

## [2.2.0] - 2026-05-15

### Corregido
- **Bug crítico en OAuthOrchestrator — registro implícito OAuth no funcional**:
    - Cuando `AllowImplicitRegistration=true` y el usuario no existía, `IExternalUserFactory.CreateFromOAuthAsync()` nunca era invocado.
    - Se inyectó `IServiceProvider` para resolver opcionalmente `IExternalUserFactory` desde DI (patrón consistente con `SecureAuthEndpoints`).
    - Se agregó logging informativo cuando se crea un usuario automáticamente desde un proveedor externo.
    - Se agregaron comentarios didácticos detallados explicando el flujo de registro implícito, cuándo usarlo y cómo registrar el factory.

### Añadido
- **Resiliencia ante rotación de llaves JWKS en todos los validadores OIDC**:
    - Google, Microsoft, LinkedIn y Apple ahora detectan automáticamente cuándo la validación falla por `SecurityTokenSignatureKeyNotFoundException` o `SecurityTokenInvalidSignatureException`.
    - En esos casos, invalidan la caché JWKS, descargan llaves frescas y reintentan la validación una vez antes de declarar el token inválido.
    - Se refactorizó `ValidateIdTokenAsync` en tres métodos (público con retry, `CoreAsync` y `WithKeysAsync`) para evitar duplicación de lógica en todos los validadores.
    - `GetSigningKeysAsync` ahora acepta parámetro `forceRefresh` para invalidar la caché bajo demanda.

### Eliminado
- **Archivo `Class1.cs` muerto** en `SecureCore.Auth.OAuth.GitHub` — era un stub vacío que no aportaba funcionalidad.

## [2.1.0] - 2026-05-09

### Añadido
- **Módulo OAuth para Apple (Sign In with Apple)**:
    - Generación dinámica de `client_secret` mediante JWT firmado con **ES256**.
    - Validación estricta de **Nonce** mediante hash SHA-256 (conformidad total con Apple).
    - Soporte para `response_mode=form_post`.
    - Caché inteligente de llaves públicas (JWKS).
    - Gestión segura del ciclo de vida de llaves ECDsa para evitar fugas de memoria.

## [2.0.0] - 2026-05-08

### Añadido
- **Ecosistema OAuth 2.0 / OIDC Modular**:
    - Arquitectura desacoplada para proveedores de identidad externos.
    - 6 Proveedores iniciales: **Google, Microsoft, Facebook, GitHub, LinkedIn, TikTok**.
    - Validación automática de OIDC (ID Tokens) y Nonces.
    - Soporte para `appsecret_proof` en Facebook para máxima seguridad.
- Nueva Fluent API para configuración de OAuth: `.AddOAuth()`.
- Middleware de callback universal para todos los proveedores.
- Gestión persistente de tokens de proveedores externos (`IExternalTokenStore`).

### Modificado
- Refactorización completa de `IdentityOrchestrator` para soportar flujos externos e internos de forma unificada.
- Mejora en el rendimiento de validación de JWT mediante caché de claves.

## [1.1.0] - 2026-04-13

### Añadido
- **Sistema de Restablecimiento Seguro de Contraseña**:
    - Flujo de dos pasos (`forgot-password` y `reset-password`).
    - Estrategia de **Anti-enumeración** de usuarios (tiempos de respuesta constantes).
    - Soporte para **Tokens Opacos** con almacenamiento de hash SHA-256.
    - Rate limiting integrado por usuario/hora para evitar abusos vía email.
    - Revocación global automática de sesiones tras el cambio de contraseña exitoso.
- Nuevas interfaces de infraestructura: `IPasswordResetStore` e `IResetTokenMailer`.
- Soporte en la Fluent API mediante el método `.AddPasswordReset()`.
- Nuevos tipos de eventos: `PasswordResetRequested` y `PasswordResetCompleted`.
- Documentación detallada en español para el flujo de restablecimiento (Guía de Uso y Referencia Técnica).

### Modificado
- `IUserStore` ahora incluye `UpdatePasswordHashAsync` para soportar cambios legítimos de credenciales.
- Mejora en los comentarios didácticos (`DIDÁCTICA:`) en múltiples componentes para mejorar la curva de aprendizaje.

## [1.0.0] - 2026-04-12

### Añadido
- Versión inicial del framework SecureCore Auth.
- Autenticación mediante email y contraseña (Argon2id).
- Soporte nativo para Passkeys (WebAuthn/FIDO2).
- Gestión de sesiones con rotación de Refresh Tokens (RTR).
- Middleware de validación activa mediante SecurityStamp.
- Protección contra ataques de fuerza bruta (Lockout exponencial).
- Sistema de eventos de dominio para observabilidad.
- Soporte para proveedores de identidad externos (OAuth/OIDC).
