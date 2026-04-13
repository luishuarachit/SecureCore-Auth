# Changelog

Todas los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
