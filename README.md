# SecureCore Auth Framework 🛡️

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/luishuarachit/SecureCore-Auth)
[![.NET](https://img.shields.io/badge/.NET-8.0-unlocked.svg)](https://dotnet.microsoft.com/)
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
-   **SecureCore.Auth.Core**: El motor de orquestación, lógica de JWT y hashing (Argon2id).
-   **SecureCore.Auth.WebAuthn**: Soporte para llaves físicas y biometría (FIDO2).
-   **SecureCore.Auth.AspNetCore**: Integración fluida con el pipeline de ASP.NET Core (Middleware y Endpoints).

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
