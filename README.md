# SecureCore Auth Framework 🛡️

[![Version](https://img.shields.io/badge/version-3.1.5-blue.svg)](https://github.com/luishuarachit/SecureCore-Auth)
[![.NET](https://img.shields.io/badge/.NET-10.0-unlocked.svg)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**SecureCore Auth** es una solución de identidad y gestión de sesiones modular, agnóstica a la base de datos y diseñada para aplicaciones .NET modernas que requieren un equilibrio entre ligereza y robustez.

---

## 🚀 Pilares Fundamentales

1.  **Seguridad Moderna**: Soporte nativo y prioritario para **Passkeys (WebAuthn)** y biometría.
2.  **Control Total de Sesión**: Gestión activa de Refresh Tokens con rotación (RTR) y capacidad de **revocación global** instántanea.
3.  **Desacoplamiento Absoluto**: Tú decides dónde y cómo guardas tus datos. La librería dicta la lógica, no la infraestructura.
4.  **Resistencia por Diseño**: Mitigaciones nativas contra ataques de enumeración y fuerza bruta.

---

## 📦 Estructura de Módulos

El framework está dividido en componentes independientes para que solo instales lo que necesites:

-   **SecureCore.Auth.Abstractions**: Contratos, interfaces y modelos base. Sin dependencias.
-   **SecureCore.Auth.Core**: El motor de orquestación, lógica de JWT, hashing (Argon2id) y MFA.
-   **SecureCore.Auth.WebAuthn**: Soporte para llaves físicas y biometría (FIDO2).
-   **SecureCore.Auth.AspNetCore**: Integración fluida con el pipeline de ASP.NET Core (Middleware y Endpoints).
-   **SecureCore.Auth.OAuth**: Orquestación OAuth2/OIDC y persistencia de tokens de proveedor.
-   **SecureCore.Auth.OAuth.{Apple, Facebook, GitHub, Google, LinkedIn, Microsoft, TikTok}**: Validadores específicos por proveedor (JWKS, nonce anti-replay, `appsecret_proof`).

---

## 🛠️ Inicio Rápido

### 1. Instalación
Agrega los paquetes necesarios a tu proyecto:

```bash
dotnet add package SecureCore.Auth.AspNetCore
dotnet add package SecureCore.Auth.Core
```

### 2. Configuración en Program.cs
Registra los servicios y configura las opciones de seguridad:

```csharp
builder.Services.AddSecureAuth(options => {
    options.Issuer = "tu-dominio.com";
    options.Audience = "tu-app";
    options.SigningKey = builder.Configuration["Jwt:Key"];
})
.AddPasswordAuthentication()
.AddWebAuthn(); // Opcional

var app = builder.Build();

app.UseAuthentication();
app.UseSecureAuthValidation(); // Validación activa de sesiones
app.UseAuthorization();

app.MapSecureAuthEndpoints("/auth"); // Mapea login, refresh, logout automáticamente
```

---

## 🔒 Características de Seguridad

-   **Argon2id**: Hashing de contraseñas de última generación.
-   **Refresh Token Rotation (RTR)**: Protege contra el robo de tokens en clientes (SPAs/Mobile).
-   **Security Stamp Versioning (SSV)**: Permite invalidar todas las sesiones de un usuario de forma inmediata (Panic Button).
-   **Constant-Time Verification**: Previene ataques de tiempo durante la validación de credenciales.
-   **Multi-Factor Authentication (MFA)**: TOTP (RFC 6238) y códigos por email con cifrado AES-256-GCM de secretos.
-   **OAuth2/OIDC**: Login social (Google, Microsoft, Apple, GitHub, Facebook, LinkedIn, TikTok) con validación criptográfica de JWKS.

---

## 📄 Documentación

Para más detalles, consulta la documentación extendida:
-   [Guía de Uso](docs/es/guia-de-uso.md)
-   [Referencia Técnica](docs/es/referencia-tecnica.md)

---

## 🤝 Contribución
Las contribuciones son bienvenidas. Asegúrate de seguir los estándares de código y mantener una cobertura de pruebas superior al 90%.

---

Desarrollado con ❤️ por el equipo de **SecureCore**.

---

> **TODO (sin commitear):** Hacer el README bilingüe. Traducción al inglés a continuación:

# SecureCore Auth Framework 🛡️

[![Version](https://img.shields.io/badge/version-3.1.5-blue.svg)](https://github.com/luishuarachit/SecureCore-Auth)
[![.NET](https://img.shields.io/badge/.NET-10.0-unlocked.svg)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**SecureCore Auth** is a modular, database-agnostic identity and session management solution designed for modern .NET applications that need a balance between lightness and robustness.

---

## 🚀 Core Pillars

1.  **Modern Security**: Native, prioritized support for **Passkeys (WebAuthn)** and biometrics.
2.  **Full Session Control**: Active Refresh Token management with rotation (RTR) and **instant global revocation**.
3.  **Total Decoupling**: You decide where and how you store your data. The library dictates the logic, not the infrastructure.
4.  **Security by Design**: Built-in mitigations against enumeration and brute-force attacks.

---

## 📦 Module Structure

The framework is split into independent components so you only install what you need:

-   **SecureCore.Auth.Abstractions**: Contracts, interfaces and base models. No dependencies.
-   **SecureCore.Auth.Core**: The orchestration engine, JWT logic, hashing (Argon2id) and MFA.
-   **SecureCore.Auth.WebAuthn**: Support for security keys and biometrics (FIDO2).
-   **SecureCore.Auth.AspNetCore**: Seamless integration with the ASP.NET Core pipeline (Middleware & Endpoints).
-   **SecureCore.Auth.OAuth**: OAuth2/OIDC orchestration and provider token persistence.
-   **SecureCore.Auth.OAuth.{Apple, Facebook, GitHub, Google, LinkedIn, Microsoft, TikTok}**: Provider-specific validators (JWKS, anti-replay nonce, `appsecret_proof`).

---

## 🛠️ Quick Start

### 1. Installation
Add the required packages to your project:

```bash
dotnet add package SecureCore.Auth.AspNetCore
dotnet add package SecureCore.Auth.Core
```

### 2. Configuration in Program.cs
Register the services and configure the security options:

```csharp
builder.Services.AddSecureAuth(options => {
    options.Issuer = "your-domain.com";
    options.Audience = "your-app";
    options.SigningKey = builder.Configuration["Jwt:Key"];
})
.AddPasswordAuthentication()
.AddWebAuthn(); // Optional

var app = builder.Build();

app.UseAuthentication();
app.UseSecureAuthValidation(); // Active session validation
app.UseAuthorization();

app.MapSecureAuthEndpoints("/auth"); // Maps login, refresh, logout automatically
```

---

## 🔒 Security Features

-   **Argon2id**: State-of-the-art password hashing.
-   **Refresh Token Rotation (RTR)**: Protects against token theft on clients (SPAs/Mobile).
-   **Security Stamp Versioning (SSV)**: Invalidate all of a user's sessions instantly (Panic Button).
-   **Constant-Time Verification**: Prevents timing attacks during credential validation.
-   **Multi-Factor Authentication (MFA)**: TOTP (RFC 6238) and email codes with AES-256-GCM secret encryption.
-   **OAuth2/OIDC**: Social login (Google, Microsoft, Apple, GitHub, Facebook, LinkedIn, TikTok) with cryptographic JWKS validation.

---

## 📄 Documentation

For more details, check the extended documentation:
-   [Usage Guide](docs/en/usage-guide.md)
-   [Technical Reference](docs/en/technical-reference.md)

---

## 🤝 Contribution
Contributions are welcome. Please follow the coding standards and keep test coverage above 90%.

---

Built with ❤️ by the **SecureCore** team.
