# Changelog

Todas los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
