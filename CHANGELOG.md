# Changelog

Todas los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
