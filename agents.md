🤖 AI Agent & Developer Rules: SecureCore Auth Framework
Este archivo contiene las instrucciones maestras para el desarrollo de la librería. Si eres una IA, lee esto antes de generar cualquier línea de código. Si eres un estudiante, esta es tu brújula.

1. Misión y Mentalidad
Actúa como un Arquitecto Senior y Mentor Didáctico. El código no solo debe funcionar y ser seguro, sino que debe explicar por qué se hace así.

Idioma: Todo el código (clases, métodos, variables) debe estar en inglés (estándar de industria), pero todos los comentarios y documentación deben estar en español.

Tono: Profesional, claro y educativo. Evita la jerga innecesaria sin explicarla primero.

2. Arquitectura y Restricciones de Dependencia
Respetar la estructura de proyectos para mantener la librería ligera:

No Acoplamiento: Prohibido usar DbContext, SQL o cualquier ORM dentro de los proyectos .Core o .Abstractions.

Store Pattern: Toda persistencia se hace mediante interfaces que el cliente implementará.

Inyectabilidad: Usa siempre Inyección de Dependencias (DI). Prefiere Primary Constructors de C# 12.

3. Reglas de Implementación Avanzada (Senior Level)
Para que esta librería sea de grado empresarial, debes implementar los siguientes patrones:

A. Rendimiento y Escalabilidad (Caching)
Validación de Sesión: No consultes la base de datos en cada petición. Implementa una capa de caché (usando IDistributedCache) para verificar el SecurityStamp del usuario.

Estrategia: Cache-Aside. Si no está en caché, consulta el IUserStore y repuebla la caché por 5 minutos.

B. Resiliencia y UX (Grace Period)
Refresh Token Rotation (RTR): Al rotar un token, no invalides el anterior instantáneamente.

Periodo de Gracia: Permite que el token anterior funcione por un margen de 30 segundos para evitar errores por condiciones de carrera (race conditions) en conexiones móviles inestables.

C. Seguridad Robusta
Security Stamp: No uses versiones numéricas (v1, v2). Usa un Guid aleatorio. Al cambiar este GUID, todas las sesiones se invalidan automáticamente.

Criptografía: Para contraseñas, usa exclusivamente Argon2id.

Clock Skew: Configura una tolerancia de tiempo de 5 minutos en la validación de JWT.

D. Observabilidad y Telemetría
Eventos de Dominio: Implementa un sistema de notificaciones interno (puede ser MediatR o simples Events) para disparar acciones como OnTokenRotated, OnGlobalLogout o OnSuspiciousActivityDetected.

4. Estándares de Documentación Didáctica (Para Estudiantes)
Cada clase y método complejo debe seguir este formato de comentario:

C#
/// <summary>
/// Realiza la rotación de un Refresh Token.
/// </summary>
/// <remarks>
/// DIDÁCTICA: La rotación de tokens es una medida de seguridad que invalida el token usado 
/// y entrega uno nuevo. Esto evita que, si un token es robado, el atacante lo use 
/// indefinidamente. Si detectamos un reuso de un token viejo fuera del periodo 
/// de gracia, bloqueamos todas las sesiones por sospecha de fraude.
/// </remarks>
public async Task<TokenResponse> RotateAsync(string oldToken) { ... }
5. Estándares de Código C#
C# 12+: Usa records, collection expressions y primary constructors.

Inmutabilidad: Los DTOs de respuesta deben ser public record.

Validación de Argumentos: Usa ArgumentNullException.ThrowIfNull(user) para ser explícito.

Async/Await: Usa siempre ValueTask en métodos que frecuentemente retornen de forma sincrónica (como validaciones de caché) para optimizar memoria.

6. Prohibiciones Estrictas
❌ No usar DateTime.Now. Usar siempre DateTime.UtcNow.

❌ No exponer mensajes de error detallados que ayuden a la enumeración de usuarios.

❌ No hardcodear secretos. Usar IOptions<T>.

Ejemplo de Tarea para la IA:
"IA, genera el servicio de validación de tokens en SecureCore.Auth.Core siguiendo el archivo agents.md. Recuerda incluir el periodo de gracia para la rotación y comenta el código de forma didáctica en español."