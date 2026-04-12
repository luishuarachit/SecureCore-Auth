Especificación Técnica: SecureCore Auth Framework
Versión: 1.0
Objetivo: Proveer una solución de identidad y sesiones modular, agnóstica a la base de datos, compatible con Passkeys, con capacidad de revocación global y resistente contra ataques de fuerza bruta.

1. Visión y Propósito
El ecosistema de .NET carece de una librería intermedia que sea más ligera que IdentityServer pero más robusta y moderna que el ASP.NET Core Identity por defecto. SecureCore Auth llena este vacío enfocándose en tres pilares:
    1. Seguridad Moderna: Passkeys (WebAuthn) como ciudadano de primera clase.
    2. Control Total de Sesión: Gestión activa de Refresh Tokens con versionado para cierre de sesión global.
    3. Desacoplamiento Absoluto: El programador decide dónde y cómo guarda sus datos; la librería solo dicta la lógica.

2. Arquitectura de la Solución (Módulos)
El sistema se divide en proyectos independientes para asegurar que el cliente solo instale lo que necesita.
2.1. SecureCore.Auth.Abstractions
    • Propósito: Definir los contratos (interfaces) y modelos de datos (DTOs).
    • Responsabilidad: Contiene las interfaces IUserStore, ISessionStore, IPasswordHasher y los resultados de operación como SignInResult.
    • Dependencias: Ninguna. Es el núcleo puro.
2.2. SecureCore.Auth.Core
    • Propósito: El motor de orquestación.
    • Responsabilidad: Implementa la lógica de validación de contraseñas, la generación de JWT y la lógica de rotación de tokens.
    • Componente Clave: IdentityOrchestrator.
2.3. SecureCore.Auth.WebAuthn
    • Propósito: Soporte para biometría y llaves físicas.
    • Responsabilidad: Maneja las "ceremonias" de registro y aserción de FIDO2.
    • Dependencias: Fido2NetLib (sugerido) y .Abstractions.
2.4. SecureCore.Auth.AspNetCore
    • Propósito: Integración con el ecosistema web de Microsoft.
    • Responsabilidad: Proveer Middlewares, Filters de autorización y métodos de extensión para IServiceCollection.

3. Especificaciones del Identity Engine (Autenticación)
El objetivo es permitir múltiples métodos de entrada que resulten en una única identidad validada.
3.1. Estrategia de Autenticación
Utilizaremos el patrón Strategy. Cada método (Password, Passkey, OAuth) debe implementar una interfaz común.
    • Passwords: Se exige el uso de Argon2id para el hashing. Parámetros recomendados:
        ◦ $m = 65536$ (64 MB de memoria)
        ◦ $t = 3$ (iteraciones)
        ◦ $p = 4$ (paralelismo)
    • OAuth: La librería debe manejar el estado Nonce y PKCE (Proof Key for Code Exchange) para prevenir ataques de interceptación.
    • Passkeys: El flujo debe ser asíncrono. El servidor emite un Challenge que debe expirar en 60 segundos si no es respondido.
3.2. Gestión de MFA (Multi-Factor)
La autenticación no es binaria (Éxito/Fallo). El SignInResult debe soportar:
    • Success: Acceso total.
    • RequiresTwoFactor: Credencial primaria válida, requiere un segundo paso.
    • LockedOut: Cuenta suspendida temporalmente por fuerza bruta.
    • RequiresTwoFactorRegistration: El usuario está obligado a registrar MFA antes de continuar.

4. Especificaciones del Session Orchestrator (Sesiones)
Este es el bloque diferencial de nuestra librería.
4.1. El Token de Acceso (JWT)
El JWT debe ser ligero pero informativo. Debe incluir un Claim personalizado: ssv (Security Stamp Version).
    • Validación de SSV: En cada petición, el middleware comparará el ssv del token con el valor actual en la caché/DB del usuario. Si el usuario cerró sesión globalmente, el ssv en la DB habrá cambiado y el token será rechazado aunque su firma sea válida.
4.2. Refresh Token Rotation (RTR)
Para mitigar el robo de tokens en aplicaciones cliente (como SPAs), implementaremos rotación estricta:
    1. Al usar un RefreshToken_A, se invalida inmediatamente.
    2. Se emite un RefreshToken_B.
    3. Si alguien intenta re-usar el RefreshToken_A, el sistema detecta una anomalía, salvo que se encuentre dentro del corto periodo de gracia que evita errores de doble solicitud de refresh token, invalida todas las sesiones del usuario y emite una alerta de seguridad.
4.3. Cierre de Sesión Global (The "Panic Button")
Lógica:
    1. El usuario solicita RevokeAllSessions.
    2. El sistema incrementa el SecurityVersion del usuario en la base de datos (ej. de 1 a 2).
    3. Se limpian las entradas de caché relacionadas con ese usuario.
    4. Instantáneamente, todos los Access Tokens y Refresh Tokens en circulación quedan inutilizados.

5. Abstracción de Datos (Data Stores)
No implementaremos acceso a base de datos. Definiremos contratos que el desarrollador final debe proveer.
5.1. IUserStore
Debe permitir buscar usuarios por identificador, ID, o proveedor externo. Debe ser capaz de actualizar el SecurityVersion y los contadores de fallos de login.
5.2. ISessionStore
Debe manejar la persistencia de los Refresh Tokens. Se recomienda encarecidamente que la implementación del cliente use una base de datos con persistencia (SQL) pero con una capa de caché (Redis) para las verificaciones de cada petición.

6. Detalles de Seguridad (Hardening)
Como ingenieros, debemos prevenir los vectores de ataque conocidos:
    1. Enumeración de Usuarios: Las respuestas de error deben ser genéricas (ej: "Usuario o contraseña incorrectos") para no revelar si un email existe o no.
    2. Clock Skew: Configurar una tolerancia de 5 minutos para la expiración de tokens para evitar problemas con relojes desincronizados.
    3. Detección de Fuerza Bruta: Implementar un bloqueo exponencial (ej: 1 min, 5 min, 15 min, 1 hora).
    4. Secure Cookies: Si se opta por cookies en lugar de headers, deben ser obligatoriamente HttpOnly, Secure y SameSite=Strict.

7. Roadmap de Desarrollo (Fases)
Fase 1: Cimientos (Semanas 1-2)
    • Definición de interfaces en Abstractions.
    • Implementación de PasswordHasher con Argon2id.
    • Lógica base de generación de JWT en Core.
Fase 2: Sesiones Inteligentes (Semanas 3-4)
    • Desarrollo de la lógica de rotación de Refresh Tokens.
    • Implementación del middleware de validación de ssv (Security Stamp).
    • Mecanismo de revocación global.
Fase 3: Modernización con Passkeys (Semanas 5-7)
    • Integración del flujo WebAuthn.
    • Registro de dispositivos y validación de firmas criptográficas.
    • Lógica de "Login sin contraseña" (Discoverable Credentials).
Fase 4: Integración y DX (Semanas 8-9)
    • Creación de la Fluent API para el registro de servicios en ASP.NET Core.
    • Documentación de ejemplos de uso con Entity Framework y Dapper.
    • Pruebas de carga para asegurar que la validación de tokens no penalice el rendimiento.

8. Guía de Contribución y Estándares de Código
    • Pruebas Unitarias: Cobertura mínima del 90% en Core y WebAuthn.
    • Documentación: Todo método público debe tener comentarios XML (///).
    • Estilo: Seguir las convenciones de Microsoft (C# Coding Conventions).
    • Inmutabilidad: Preferir record para DTOs y evitar efectos secundarios en los servicios de validación.

