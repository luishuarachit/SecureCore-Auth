# Changelog

Todas los cambios notables en este proyecto serán documentados en este archivo.

El formato está basado en [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
y este proyecto se adhiere a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2026-09-11

### Añadido
- **Límite de tamaño de payload en endpoints de autenticación (A-10)**:
  - `SecureAuthOptions.MaxAuthRequestBodySize` (default: 2048 bytes, rango [256, 8192]) acota el cuerpo de `/login`, `/refresh`, `/forgot-password` y `/reset-password`.
  - Protección en dos capas: endpoint filter automático (413 JSON por `Content-Length`, verificable en TestServer) + middleware `UseSecureAuthRequestSizeLimit("/auth")` que asigna `IHttpMaxRequestBodySizeFeature` **antes** del binding (Kestrel rechaza con 413 también cuerpos chunked).
- **Aserción de passkeys con motivo distinguible (A-17)**: `PasskeyService.CompleteAssertionDetailedAsync` devuelve `PasskeyAssertionResult` (`User`, `CredentialFound`, `SignatureValid`). Un `Id` de credencial malformado (no Base64) ya no lanza excepción: se trata como credencial no encontrada.
- **Estado de entrega del email de reset (A-09)**: `PasswordResetEntry.DeliveryState` (`Pending`/`Dispatched`/`Failed`) y miembro opcional (default interface member) `IPasswordResetStore.UpdateDeliveryStateAsync`. Las implementaciones existentes no se rompen: sin sobrescribirlo el estado queda en `Pending`.
- **Rate limiting dedicado por IP en `/forgot-password`**: limiter keyed `"forgot-password"` configurable con `SecureAuthOptions.ForgotPasswordRateLimiter` (default: 5 solicitudes/hora). El throttling es **silencioso**: al superarse el límite se descarta la solicitud y se responde el mismo 200 ciego.
- **Primitiva single-use atómica transversal (S2, Fase 1)**:
  - `ISingleUseTokenStore` (SPI): `SetAsync` + `GetAndRemoveAsync` — el equivalente a GETDEL. Base del anti-replay para OAuth state (A-06), challenges WebAuthn (Fase 4) y recovery codes (Fase 5).
  - `DistributedCacheSingleUseTokenStore` (default sobre `IDistributedCache`, GET + REMOVE no atómico con ventana residual `~1 ms` documentada). Para operación atómica en multi-instancia basta registrar una implementación sobre Redis GETDEL/Lua: `DistributedCacheOAuthStateStore` la consume automáticamente.
  - `DistributedCacheOAuthStateStore` ahora delega en `ISingleUseTokenStore` el **ciclo de vida completo** (escritura y consumo) cuando está registrado; fallback legacy por `IDistributedCache` si no. No-breaking: `new DistributedCacheOAuthStateStore(cache)` sigue funcionando.
  - Rechazo defensivo: `ttl <= 0` y `entry`/`value` nulos lanzan antes de tocar el almacén (evita entradas ya expiradas y escrituras vacías).
- **Anti-abuso unificado por cuenta (S1, Fase 2)**:
  - `IAccountProtectionService` (SPI) con scopes por factor y por acción (`Password`, `MfaLogin`, `Passkey`, `Recovery`, `VerifyAction`): `CheckAsync`, `RecordFailureAsync`, `RecordSuccessAsync`, `ResetAsync`, `ResetAllForUserAsync`, `AnyActiveLockAsync`.
  - `InMemoryAccountProtectionService` (default): contadores por `(scope, cuenta)` con ventana deslizante (`Window`, default 5 min), lockouts escalonados (10 → 30 → 60 min → 24 h, techo `MaxLockDuration`) y expiración perezosa. El nivel de escalamiento se conserva entre episodios: el 2º bloqueo de una misma cuenta dura más que el 1º.
  - Wiring (opt-in): `AddSecureAuthAccountProtection()` (default `Enabled: false`, principio D-03). Al activarlo, `IdentityOrchestrator.SignInWithPasswordAsync` (scope `Password`) y `MfaOrchestrator.VerifyAsync` (scope `MfaLogin`) integran el subsistema sin tocar el flujo legacy: sin registro, el comportamiento anterior permanece intacto.
  - El fallo que dispara el lockout responde el mismo mensaje genérico que cualquier fallo (sin oráculo de cuándo se bloquea); el siguiente intento recibe el mensaje de bloqueo. Los presupuestos son independientes por factor: un ataque a MfA (5 intentos) no consume el presupuesto de contraseña. `MfaVerificationFailed` se publica en **cada** intento fallido (con la metadata `attempts` restantes, o el máximo cuando el fallo dispara el lockout).
  - Configurable por sección `SecureAuth:AccountProtection` (`MaxAttempts` por scope: contraseña/MfA/passkey/verificación 5, recovery 3; `Window`; `EscalationDurations`; `MaxLockDuration`), con validación en arranque (`.Validate().ValidateOnStart()`): configuración inválida falla en startup en vez de degradarse a fail-open.
- **Fido2Configuration automática desde WebAuthnOptions (S4)**: `AddWebAuthn()` ahora registra `Fido2Configuration`, `Fido2` e `IFido2` (singleton) derivados de `WebAuthnOptions`. `RelyingPartyId` se mapea a `ServerDomain`, `RelyingPartyName` a `ServerName`, y `Origins` se propagan. El consumidor **no necesita** registrar `Fido2Configuration` ni `IFido2` manualmente; `WebAuthnOptions` es la fuente única. `TryAdd` respeta configuraciones personalizadas previas.
- **Oracle de enumeración de credenciales cerrado (S4)**: `WebAuthnOptions.DiscloseCredentialsInLoginBegin` (default `false`). Cuando está desactivado, `WebAuthnOrchestrator.BeginLoginAsync` pasa `userId: null` a `BeginAssertionAsync` → el autenticador usa Discoverable Credentials sin filtrar por usuario → respuesta idéntica para todos los userIds → el oráculo de enumeración por barrido queda cerrado por defecto.
- **Rate limiting por IP en endpoints WebAuthn (S4)**: `POST /webauthn/login/begin` (keyed `"webauthn-begin"`, default 30/min) y `POST /webauthn/login/complete` (keyed `"webauthn-complete"`, default 10/min) incluyen rate limiting por `Connection.RemoteIpAddress`. Configurable vía `SecureAuthOptions.WebAuthnBeginRateLimiter` / `WebAuthnCompleteRateLimiter`. Se resetea en login exitoso. Sin limiter registrado → se comporta como antes (graceful degradation).
- **Tope de payload WebAuthn explícito (S4)**: `RequestSizeLimitMiddleware` asigna `IHttpMaxRequestBodySizeFeature.MaxRequestBodySize = MaxWebAuthnRequestBodySize` (default 65536 / 64 KB, configurable [4096, 1048576]) a rutas `/webauthn/*`. Los payloads FIDO2 (clientDataJSON + attestationObject/authenticatorData en Base64URL) quedan acotados sin depender del tope general de 2048B de `/auth`.
- **Claves tipadas por ceremonia en challenge store (S4)**: `StoreChallengeAsync` almacena challenges bajo `"{tag}:{rawId}"` (`"register:"` o `"login:"`). El `challengeId` devuelto al cliente es el `rawId` opaco; el orquestador recompone la clave tipada al consumir. El reuso cross-ceremony (un challenge de registro usado en login o viceversa) ahora es **fail-closed** antes del parseo JSON.
- **Estado post-verificación y step-up (S3, Fase 3)**:
  - **Ventana "mfa_verified" (A-21)**: `IMfaVerifiedSessionStore` (SPI) con `SetVerifiedAsync`/`IsVerifiedAsync`/`ClearAsync` sobre TTL `SecureAuthOptions.MfaVerifiedTtl` (default 8 h; fallback defensivo 8 h). `IdentityOrchestrator.CompleteMfaLoginAsync` abre/renueva la ventana con el método verificado tras un login MFA exitoso. Registro `TryAddScoped` automático en `AddMfa`, `AddPasswordAuthentication` y `AddVerifyAction`; sin registro, el comportamiento previo es idéntico.
  - **Claim opcional `acr` (A-14)**: `SecureAuthOptions.EmitAcr` (default false, opt-in) emite `AcrLevel` (default `"1"`, NIST AAL) en todos los tokens. Un claim `acr` explícito del implementador vía `UserIdentity.Claims` gana sobre el valor global.
  - **Step-up genérico verify-action (A-22)**: `VerifyActionOrchestrator` + OTP por email de un solo uso (consumo atómico sobre S2, hash SHA-256 en reposo, comparación en tiempo constante). `VerifyActionOptions` (`SecureAuth:VerifyAction`: `TtlMinutes` 5, `CodeLength` 6, `MaxSendsPerWindow` 3). Nueva `AddVerifyAction()`: registra `IEmailOtpStore` (default `DistributedCacheEmailOtpStore`), `IEmailOtpSender` (default adaptador sobre `IEmailService`) y la ventana mfa_verified compartida. En S1 cada envío consume una unidad del scope `VerifyAction` (anti email-flood); un código correcto renueva el presupuesto y abre la ventana.
  - **Creación/cambio de contraseña (A-22, NIST SP 800-63B)**: `ChangePasswordOrchestrator` (nueva `AddChangePassword()`). `CreateAsync` exige la ventana de verify-action **abierta** para cuentas sin contraseña (flujo passwordless → password; el OTP ya se consumió en `verify-action/verify`, sin doble consumo); `ChangeAsync` valida la contraseña actual. Ambos rotan el SecurityStamp, invalidan la caché de stamps, revocan TODAS las sesiones previas y re-emiten un par de tokens con el novo stamp (`success` incluye `Tokens`). Política: 8–1024 caracteres, sin reglas de composición.
  - **Endpoints opt-in**: `POST /auth/verify-action/send`, `POST /auth/verify-action/verify`, `POST /auth/create-password`, `POST /auth/change-password` (autenticados, userId del claim `sub`, mensajes genéricos sin filtrar la causa; 503 si el orquestador no está registrado).
- **Recovery codes de primera clase (F5, A-18/A-20)**:
  - `IRecoveryCodeStore` (SPI, 4 métodos): `CreateAsync`, `GetStatusAsync` (peek **NO consumidor**: distingue `Valid`/`AlreadyUsed`/`Invalid` sin gastar el código), `RedeemAsync` (single-use atómico vía `ISingleUseTokenStore`) e `InvalidatePendingAsync`. Default `DistributedCacheRecoveryCodeStore` sobre `IDistributedCache` (token S2 `recovery:code:{userId}|{hash}` + índice JSON `recovery:index:{userId}`; el índice se escribe PRIMERO y el token DESPUÉS para que una caída durante la regeneración no deje códigos huérfanos redimibles).
  - `RecoveryCodeOrchestrator` (registrado siempre por `AddMfa()`; `EnableRecoveryCodes` es late-bound): `GenerateAsync` (CSPRNG + hash SHA-256 hex minúsculas, rechazo barato `MaxLength=128` antes de hashear, TTL `MfaOptions.RecoveryCodeLifetimeDays` default 90 días [1..365], invalida el lote anterior, emite `RecoveryCodesGenerated` y devuelve el plaintext UNA sola vez), `VerifyAsync` (peek no consumidor + scope S1 `Recovery`), `UseAsync` (consume atómico, emite `RecoveryCodeRedeemed`; el fallo que dispara lockout emite `AccountLockedOut` con `scope=recovery`).
  - Eventos nuevos: `RecoveryCodesGenerated`, `RecoveryCodeRedeemed`, `RecoveryCodeVerificationFailed`, `RecoveryCodeRedemptionFailed`.
  - Endpoints opt-in (mapper dedicado `MapSecureAuthRecoveryCodesEndpoints("/auth/recovery-codes")`): `POST /generate` (autenticado; 400 `recovery_codes_disabled`), `POST /verify` y `POST /use` (anónimos pero **tutelados por `mfaSessionToken`** — la cuenta se resuelve del token del login en curso, nunca de un `userId` del cuerpo; anti-enumeración; `use`: 200 `redeemed`, 429 `too_many_attempts`, 400 `invalid_code` genérico). 503 si `AddMfa()` no se registró.
  - **Login completo con recovery code (A1, auditoría F5)**: `IdentityOrchestrator.CompleteMfaLoginWithRecoveryCodeAsync(mfaSessionToken, recoveryCode, rotateSecurityStamp, ct)` — cierra el flujo A-20: redime el código (single-use vía S2), consume el token de sesión, emite tokens con `amr=mfa`/`mfa_method=recovery`, abre la ventana `mfa_verified` (paridad S3) y, por política del host (`rotateSecurityStamp`), rota el SecurityStamp revocando todas las sesiones previas. Antes, el host debía reimplementar la emisión de tokens (el único método de completar login exigía un código TOTP/email que un recovery code no es).
  - **Rate limiting por IP de `/verify` y `/use` (B1, auditoría F5)**: limitadores keyed `"recovery-verify"` (default 10/min) y `"recovery-use"` (default 5/min), configurables con `SecureAuthOptions.RecoveryVerifyRateLimiter`/`RecoveryUseRateLimiter`. El éxito resetea el presupuesto por IP. Sin `AddSecureAuth` no hay limiter registrado → degradación elegante.
- **Passwordless-first incremental (F6, A-25)**:
  - `SignInErrorCode` (enum tipado) + `SignInResult.ErrorCode` (string) + `RequiresPasswordlessCredential`: `SignInWithPasswordAsync(email, string? password)` acepta password nullable; `password == null` → `PasswordlessRequiresCredential` SIN consultar el store (señal de REQUEST uniforme, sin oráculo de enumeración; `VerifyDummyPassword` solo con password no nulo). Aditivo y non-breaking (los bools pre-existentes se conservan). El `ErrorCode` es para el host; no exponerlo a clientes no autenticados.
  - **Claim `amr` consistente (RFC 8176)**: nueva opción `SecureAuthOptions.EmitAmr` (default false, opt-in). Al activarla, el login por contraseña emite `amr=pwd` y el login WebAuthn añade `mfa_method=webauthn` (MFA ya emite `amr=mfa` + `mfa_method`). El evento `LoginSuccess` del login por contraseña gana metadata `method=password` (paridad de observabilidad).
  - **Endpoint `GET /auth/me`**: perfil autenticado `{ id, email, hasPassword, twoFactorEnabled, mfaEnrollmentStatus, preferredMfaMethod }`. `hasPassword` se lee fresco del store en cada llamada (nunca de un claim, que mentiría tras crear la contraseña). 503 sin `IUserStore`; usuario no encontrado → 401 genérico. `MfaEnrollmentStatus` ahora se serializa como string (JsonStringEnumConverter) en las respuestas del framework.
- **Blacklist de access tokens SPI opt-in (A-24)**: `ITokenBlacklist` (`AddAsync(jti, ttl)` / `IsBlacklistedAsync(jti)`) con default `NoOpTokenBlacklist` (no-op → comportamiento previo intacto, D-03). `POST /logout` extrae el `jti` del access token (parseo sin validación) y lo blacklistea con TTL = vida restante; la validación JWT (`OnTokenValidated`) lo rechaza por request. El host registra su implementación ANTES de `AddSecureAuth()`.
- **`amr=oauth` en login OAuth (F6, RFC 8176)**: con `EmitAmr`, `SignInExternalAsync` emite `amr=oauth` y lo persiste en `RefreshTokenEntry.AuthMethod` (completa la emisión por método `pwd|webauthn|oauth|mfa`).
## [3.2.1] - 2026-09-12

### Añadido
- **Kit HTTP componible (F7, A-26)**: la superficie HTTP deja de ser un bundle all-or-nothing.
  - **Handlers públicos por feature** (`SecureAuthEndpoints.LoginHandler`, `MeHandler`, `RefreshHandler`, `LogoutHandler`, `RevokeAllHandler`, `ForgotPasswordHandler`, `ResetPasswordHandler`, `VerifyActionSendHandler`, `VerifyActionVerifyHandler`, `CreatePasswordHandler`, `ChangePasswordHandler` + recovery y WebAuthn): el host los re-rutea a cualquier ruta/verbo (`app.MapPost("/custom", SecureAuthEndpoints.LoginHandler)`).
  - **`AuthEndpointDescriptor`** (Method, Route, Handler, authz, filters, name, description) + **`MapAuthEndpoints(prefix, descriptors)`** como compositor genérico (OCP: feature nueva = descriptor nuevo).
  - **Mappers por grupo**: `MapSecureAuthSessionEndpoints`, `MapSecureAuthPasswordResetEndpoints`, `MapSecureAuthCredentialEndpoints`, `MapSecureAuthVerifyActionEndpoints`. `MapSecureAuthEndpoints` = composición de todos (100% no-breaking). Recovery y WebAuthn también se convirtieron a descriptores.
  - **`EnforceAnonymousRequestSizeLimit` público**: reutilizable en la superficie propia del host.
- **Wiring uniforme (F7, A-26)**: la validación JWT Bearer se configura desde `IOptions<JwtOptions>` (misma fuente que la emisión) vía `ConfigureJwtBearerOptions`. `IPasswordHasher`/`ITotpService`/`IMfaSessionStore`/`IMfaEncryptionService`/`IEmailMfaService`/`IMfaService`/`RecoveryCodeOrchestrator` pasan a `TryAdd*` (se respetan overrides del host; `AddPasswordAuthentication().AddMfa()` no duplica). `JwtProductionSecurityValidator` deja de ser dead code (usa `IHostEnvironment` + logger real).
- **Merge estructural appsettings ↔ Fluent (F8, limitación A de F7)**: nuevo `SecureAuthOptionsBootstrap` que vincula `SecureAuth:`, `SecureAuth:Jwt:` y `SecureAuth:Argon2:` desde `IConfiguration` y ejecuta el `configure` del host UNA vez sobre esas instancias (appsettings = base, Fluent = overlay). `SecureAuthOptions`/`JwtOptions`/`Argon2Options` se configuran desde `IOptions` (se eliminan las guardas `if !IsNullOrEmpty` de JWT — de paso se arregla que `Algorithm` solo-appsettings cayera al default Fluent RS256). `MfaOptions` usa `BindConfiguration` + el `configure` de `AddMfa` sobre la instancia vinculada (appsettings sobrevive).
- **Protección de tamaño intrínseca a los handlers anónimos (F8, limitación C de F7)**: `LoginHandler`, `RefreshHandler`, `ForgotPasswordHandler`, `ResetPasswordHandler`, `VerifyRecoveryCodeHandler` y `UseRecoveryCodeHandler` comprueban `Content-Length` > `MaxAuthRequestBodySize` al inicio (413), de modo que la protección viaja con el handler a cualquier ruta re-ruteada. Se añadió `HttpContext` a `RefreshHandler`/`ResetPasswordHandler` (aditivo). El filtro público `EnforceAnonymousRequestSizeLimit` se conserva como utilidad/defensa en profundidad.
- **`SecureAuthConfiguration.Mfa` → `[Obsolete]` (F8, limitación B de F7)**: dead property nunca vinculada a `MfaOptions`; se eliminará en v4.

### Corregido
- Correcciones de la auditoría integral (F0-F6) — seguridad, funcionalidad rota y deuda "parche vs solución":
  - **RTR — grace period era código muerto + TOCTOU**: la rotación marcaba el token con `IsRevoked=true` y el chequeo de `IsRevoked` ocurría ANTES del de `ReplacedByTokenHash`, por lo que el periodo de gracia documentado era inalcanzable (una race condition legítima del cliente revocaba toda la familia). Ahora el chequeo de "reemplazado" (grace) precede al de "revocado", y las comprobaciones se re-leen DENTRO del lock por familia (dos rotaciones concurrentes del mismo token ya no crean dos tokens vivos; un replay paralelo no evade el single-use).
  - **Anti-replay TOTP destructible**: `DistributedCacheMfaCodeStore.ValidateAndRemoveCodeAsync` borraba la entrada SIEMPRE; un intento erróneo destruía el marcador del código ya usado y re-habilitaba su replay dentro de la ventana de tolerancia. Ahora la entrada solo se elimina cuando el código COINCIDE (single-use real); el abuso de reintentos lo acotan el lockout legacy (`MaxVerificationAttempts`) y el scope `MfaLogin` de S1.
  - **Recovery codes del enrollment legacy eran un orfanato (funcionalidad rota)**: `MfaOrchestrator.CompleteEnrollmentAsync` generaba códigos, escribía sus hashes en `IUserStore.SetRecoveryCodesAsync` y DESCARTABA el plaintext (el método retorna bool; el usuario jamás los veía), y nadie los redimía (A-18). Eliminado el bloque; la solución real es `RecoveryCodeOrchestrator.GenerateAsync` (F5), que sí devuelve el plaintext una sola vez. `SetRecoveryCodesAsync` queda `[Obsolete]` para v4.
  - **`client_secret` de Facebook en la URL (GET)**: quedaba en logs de proxies/servidores/referrers. Ahora el intercambio de código se hace con POST + `FormUrlEncodedContent` (el secreto viaja en el body).
  - **Nonce OIDC con comparación no constante**: los validadores Google/LinkedIn/Microsoft/Apple comparaban el nonce con `==` (timing side-channel). Nuevo helper `OAuthClaimHelper.FixedTimeEquals` y uso en los 4.
  - **Mensajes OAuth que filtraban internos y enumeraban cuentas**: los endpoints anónimos `/token` y `/callback` reenviaban `ErrorMessage` del resultado (ex.Message de proveedor, "User not found..."). Ahora responden mensajes GENÉRICOS; el host diagnostica con el `ErrorCode` tipado.
  - **`VerifyDummyPasswordAsync` con string fijo**: no hasheaba la contraseña provista (timing no idéntico al caso real). Ahora hashea la contraseña recibida (paridad con la versión síncrona).
  - **Modulo bias en OTP email**: `EmailMfaService.GenerateCode` usaba `uint % max`; ahora `RandomNumberGenerator.GetInt32(0, max)` (uniforme).
  - **Throttle de verify-action fail-open**: `TryAllowSend` devolvía `true` (envíos ilimitados) con configuración inválida (`window<=0 || maxSends<=0`); ahora es fail-closed (deniega).
  - **`catch` vacío en `JwtMfaSessionService`**: los fallos de validación del token MFA se tragaban sin log; ahora se registra un warning.
  - **Downgrade de aseguramiento en la rotación (amr/mfa_method)**: tras el primer refresh, una sesión iniciada con MFA/passkey se re-emitía sin `amr`/`mfa_method`. Nuevo `RefreshTokenEntry.AuthMethod`/`MfaMethod`, seteado en todos los sitios de emisión (password, MFA, recovery, WebAuthn) y propagado en la rotación y el grace period.
  - **`challengeId` WebAuthn con `Guid.NewGuid()`**: no es una fuente criptográfica (la doc afirmaba CSPRNG); ahora `RandomNumberGenerator.GetBytes(16)`.
  - Comentarios corruptos (caracteres chinos) en `JwtTokenService`/`JwtOptions`.
- Correcciones de la auditoría de seguridad de F6 (passwordless):
  - **Ramo muerto en `/login`**: el endpoint tenía un bloque `RequiresTwoFactor` inalcanzable (ya cubierto por la rama anterior) que respondía `200 {error:"two_factor_required"}`; se eliminó (el flujo MFA responde por la rama consolidada con `requiresTwoFactor`/`mfaSessionToken`).
- Correcciones de la auditoría de seguridad de F5 (recovery codes):
  - **A2 — atomicidad del single-use**: la redención dependía del GETDEL del S2 por defecto (GET + REMOVE NO atómico, TOCTOU ~1 ms): dos redenciones concurrentes del mismo código podían triunfar ambas en multi-instancia. `DistributedCacheRecoveryCodeStore.RedeemAsync` ahora serializa por código con `IOperationLock` (cierra la ventana en single-instance) y documenta que la atomicidad multi-instancia exige un S2 atómicamente consumidor (Redis GETDEL/Lua). Test de concurrencia añadido (10 tareas → exactamente 1 éxito).
  - **B2 — huérfanos por generación concurrente**: dos `GenerateAsync` en paralelo (doble clic) intercalaban el índice y dejaban un lote de tokens S2 redimibles no indexados. `RecoveryCodeOrchestrator.GenerateAsync` ahora se serializa por usuario con `IOperationLock`.
  - **B3 — auditoría de fallos**: `VerifyAsync` y `UseAsync` solo logueaban los fallos que no disparan lockout. Nuevos eventos `RecoveryCodeVerificationFailed` y `RecoveryCodeRedemptionFailed` (paridad con `MfaVerificationFailed`) para que el host detecte intentos de uso de códigos robados.
  - **B4 — delimitador de claves**: `BuildCodeKey` usaba `:` entre userId y hash; un userId con `:` ambigüaba la clave. Ahora `|` (el hash es sufijo fijo de 64 hex, clave inequívoca).
  - **B5 — guard defensivo**: `GenerateAsync` con `RecoveryCodeCount < 1` (config sin validar) invalidaba el lote anterior y generaba vacío. Ahora rechaza ANTES de invalidar.
- XML docs obsoletas de `MaxAuthRequestBodySize` y del filtro de endpoints: afirmaban que un endpoint filter rechazaba con 413 antes de deserializar; en Minimal APIs los filters se ejecutan **después** del binding. La protección real la aporta el middleware.
- `PasskeyService.CompleteAssertionDetailedAsync` propagaba `FormatException`/`ArgumentNullException` (→ HTTP 500) ante un `Id` de credencial malformado: ahora retorna credencial no encontrada mediante `TryDecodeBase64CredentialId` (aplicado también en el ramo de fallo de firma).
- Revisión de seguridad de S1 (hallazgos de la auditoría):
  - `GetLockDuration` podía devolver una duración mayor que `MaxLockDuration` si la escala lo pedía: ahora se **clampa** al techo y, defensivamente, cualquier duración ≤ 0 o nivel fuera de rango cae en `MaxLockDuration`.
  - `Window`/`MaxLockDuration` ≤ 0 (configuración directa sin validar) degradaban el lockout a inofensivo/fail-open: ahora `GetWindow()`/`GetMaxLockDuration()` usan fallback a los defaults (5 min / 24 h) y `AddSecureAuthAccountProtection` valida toda la configuración en startup.
  - Transición al activar S1 con lockouts legacy en DB: `VerifyAsync` con S1 activo ahora respeta un `LockoutEnd` vigente dejado por el flujo legacy (fail-closed); la expiración auto-resetea el contador (auto-curación) y el flujo continúa.
  - El `configure` de `AddSecureAuthAccountProtection` sobrescribe **en bloque** (todas las propiedades, no solo las indicadas) la sección appsettings: documentada la precedencia para evitar configuraciones mixtas accidentales.
- Correcciones de la auditoría de seguridad de S4 (WebAuthn/Passkeys):
  - `PasskeyService.TryResolveCredentialId` ahora prefiere `response.RawId` (byte[], decodificado directamente por `Base64UrlConverter` de Fido2NetLib) y solo recurre a `response.Id` (string) vía `TryDecodeBase64UrlCredentialId` como fallback. El decoder propio normaliza Base64URL (`-`→`+`, `_`→`/`, padding sintético). Un `Id` malformado o vacío retorna `null` (credencial no encontrada) sin lanzar excepción. Antes, `Convert.FromBase64String` (estándar, no Base64URL) sobre el string del navegador fallaba ~100% de los casos en login real.
  - `WebAuthnOrchestrator` clona `user.Claims` antes de mutar `amr` con `new Dictionary<string, string>(user.Claims ?? [])`. El diccionario fuente del store queda intacto y no contamina otros flujos con un claim `amr` espurio.
- Correcciones de la auditoría de seguridad de S3 (Fase 3):
  - `VerifyActionOrchestrator` persistía el hash del OTP ANTES de enviarlo: si el sender fallaba quedaba un hash huérfano en el store y el intento no se registraba contra S1. Ahora el hash se guarda SOLO tras una entrega satisfactoria y el envío fallido no consume presupuesto (M2).
  - `ChangePasswordOrchestrator.CreateAsync` consumía el OTP de verify-action que `VerifyActionAsync` ya había consumido de forma atómica (doble consumo → el flujo documentado era inviable, siempre `invalid_otp`). Ahora `CreateAsync` comprueba la ventana `mfa_verified` (`IsVerifiedAsync`) y devuelve `verify_action_required` si está cerrada (M1); se elimina el `otp` del cuerpo de `/create-password`.
  - `ChangePasswordOrchestrator.ChangeAsync` validaba la contraseña actual contra Argon2 sin acotar su longitud (amplificación de memoria/CPU por request) y sin anti-abuso: ahora la contraseña actual se limita a 1024 caracteres (`MaxLength` en el DTO y guard en el orquestador antes de `VerifyPasswordAsync`) y cada fallo consume el nuevo scope S1 `PasswordChange` (H3, M4).
  - `SessionOrchestrator` no limpiaba la ventana `mfa_verified` al revocar sesiones: ahora `RevokeAllSessionsAsync` y `LogoutAsync` invocan `IMfaVerifiedSessionStore.ClearAsync` cuando el store está registrado, de modo que una sesión nueva sin MFA no hereda el step-up (H2).

### Seguridad
- Throttling anti-abuso en `/forgot-password` sin exponer oráculo ni feedback de bloqueo (200 ciego).
- **Mitigación del TOCTOU en OAuth state (A-06)**: el consumo queda abstraído tras `ISingleUseTokenStore` (S2), extensible a operación atómica GETDEL/Lua sin cambios en el flujo OAuth.
- Documentado el riesgo de enumeración: no exponer al cliente la distinción `CredentialNotFound` vs `InvalidSignature` de las passkeys (`CredentialFound` es un oráculo necesario por diseño para lockout por cuenta).
- Documentada la responsabilidad de limpieza periódica de tokens de reset expirados (`IPasswordResetStore.DeleteExpiredAsync`) y de tokens huérfanos Pending/Failed (A-09).
- S1 (A-02/A-15/A-19): límite de intentos por cuenta y por factor con lockout escalonado. Los fallos durante un lockout activo se ignoran (no gastan presupuesto) y el conteo nunca ocurre sobre un estado bloqueado; el reset por éxito/no-restart queda restringido al scope correspondiente.
- S1: configuración inválida falla en startup (`.Validate().ValidateOnStart()`); la duración de lockout queda acotada por `MaxLockDuration`; los lockouts legacy en DB se respetan durante la activación del subsistema (sin ventana de fail-open).
- S3 (A-14/A-21/A-22): la ventana mfa_verified acota el step-up (una verificación no blinda la cuenta indefinidamente; TTL 8 h). El OTP de verify-action es single-use atómico (S2), expira (5 min por defecto) y se persiste solo su hash; los fallos y los envíos cuentan contra el scope `VerifyAction` de S1, y los mensajes de error son genéricos (no-enumeración, sin filtrar si el envío falló o el código era erróneo). Cambiar/crear contraseña revoca todas las sesiones (rotación del SecurityStamp) y cierra los refresh tokens previos, incluida la familia en uso; el cliente adopta el nuevo par de tokens emitido con el stamp nuevo en la respuesta.
- S3 (auditoría): **throttle duro de envíos de verify-action por usuario** (`MaxSendsPerWindow`, default 3, siempre activo incluso sin S1) impide la emisión ilimitada de códigos y el brute-force del OTP de 6 dígitos; un código correcto renueva el throttle (paridad con S1). El cambio de contraseña añade el scope S1 `PasswordChange` (default 5) contra el oráculo de la contraseña actual, y la contraseña actual y el cuerpo de `.../verify`/`create-password` quedan acotados (rechazo barato antes de SHA-256/Argon2).
- S4 (auditoría WebAuthn):
  - **Fail-closed por diseño**: los challenges WebAuthn son single-use atómicos (`ISingleUseTokenStore`) y se almacenan con clave tipada por ceremonia (`register:`/`login:`); el cross-ceremony reuso, la reentrega y el reuso de `challengeId` son rechazados antes del parseo de la respuesta del autenticador.
  - **Enumeración de cuentas cerrada**: `login/begin` no filtra `allowCredentials` por usuario por defecto (`DiscloseCredentialsInLoginBegin=false`) → respuesta idéntica para userIds existentes o no. Solo actívalo si entiendes el riesgo de oráculo (entornos con pocos usuarios).
  - **Anti-abuso en endpoints anónimos**: `/webauthn/login/begin` y `/webauthn/login/complete` limitan por IP real (`RemoteIpAddress`, no XFF). El costo de CPU de `CompleteLoginAsync` (verificación de firma ES256) queda acotado además por el límite de completaciones (10/min default).
  - **Payload acotado**: `/webauthn/*` tiene tope propio de 64 KB (`MaxWebAuthnRequestBodySize`) en vez de depender del límite general de 2 KB de `/auth`.
  - **Consistencia de origin**: la configuración FIDO2 interna de Fido2NetLib (que valida el origin firmado en el `clientDataJSON`) se deriva de `WebAuthnOptions` (`RelyingPartyId` → `ServerDomain`, `Origins`), de modo que el origin verificado coincide con el configurado para la ceremonia — no con una config desacoplada del consumidor.
- F5 (A-18/A-20): los recovery codes son credenciales de emergencia de alta sensibilidad: se persisten SOLO hashes SHA-256, expiran (`RecoveryCodeLifetimeDays`, default 90 días) y su redención es single-use atómico sobre S2 (reusar un código ya consumido falla). `verify` es un peek NO consumidor — nunca gasta el código — y es anti-enumeración (no distingue código inexistente/ya usado/cuenta bloqueada). El scope `Recovery` de S1 (default 3) acota el brute-force; el fallo que dispara el lockout responde genérico y `use` bloqueado devuelve 429 sin detalles. `verify`/`use` no aceptan un `userId` del cuerpo: la cuenta se resuelve del `mfaSessionToken` del login en curso (un atacante no puede probar códigos contra cuentas arbitrarias).
- F5 (auditoría): la redención se serializa por código (`IOperationLock`) para cerrar el TOCTOU del S2 por defecto (la atomicidad multi-instancia sigue requiriendo un S2 GETDEL/Lua); la regeneración se serializa por usuario para que una generación concurrente no deje códigos huérfanos redimibles; `verify`/`use` quedan acotados por IP (`RecoveryVerifyRateLimiter`/`RecoveryUseRateLimiter`) para impedir la amplificación de CPU/caché de endpoints anónimos; y completar el login con un recovery code pasa por `CompleteMfaLoginWithRecoveryCodeAsync` (nunca por `CompleteMfaLoginAsync`, que solo acepta TOTP/email), con rotación opcional del SecurityStamp como política del host.
- F6 (A-25): el camino passwordless no introduce oráculos — `PasswordlessRequiresCredential` es una señal de REQUEST uniforme (se devuelve antes de tocar el store; mismo resultado para emails existentes o no), el `ErrorCode` de `SignInResult` queda documentado como "solo host" (no exponer a clientes no autenticados), y `hasPassword` se consulta únicamente vía `/auth/me` (autenticado) — nunca en claims, que mentirían tras crear la contraseña. `EmitAmr` (opt-in) expresa el método de autenticación real en el token (RFC 8176) sin cambiar el default.

## [3.1.8] - 2026-08-01

### Corregido
- **`JwtMfaSessionService` no leía el claim `sub` tras el mapeo del handler (enrollment/login MFA bloqueados)**:
  - `JwtSecurityTokenHandler.ValidateToken` mapea el claim `sub` a `ClaimTypes.NameIdentifier` en el `ClaimsPrincipal` devuelto. `ValidateAndExtractUserIdAsync` solo buscaba `JwtRegisteredClaimNames.Sub` → siempre devolvía `null` → `CompleteEnrollmentAsync` y `CompleteMfaLoginAsync` fallaban con "token de sesión inválido o de otro usuario".
  - Ahora se lee `sub` **o** `NameIdentifier` (patrón consistente con `SecureAuthEndpoints`).

- **`ConsumeMfaSessionTokenAsync` no implementaba single-use real**:
  - El parámetro `consume` se ignoraba y no había blacklist de `jti` → un token de sesión MFA (5 min) era reutilizable, contradiciendo el contrato documentado.
  - Ahora el `jti` consumido se guarda en `IMemoryCache` (expiración = `ValidTo` del token). Una segunda `ValidateMfaSessionTokenAsync` o `ConsumeMfaSessionTokenAsync` devuelve `null`.
  - `AddMemoryCache()` se registra automáticamente en DI.
  - **Nota**: el blacklist es in-memory (single-instance), igual que `InMemoryRateLimiter`/`InMemoryOperationLock`. Para despliegues multi-instancia, sustituir `IMfaSessionStore` por una implementación distribuida.

### Seguridad
- Tests nuevos con el servicio REAL (`JwtMfaSessionServiceTests`): lectura de `sub`, single-use del token, tokens de issuer incorrecto/inválidos, fingerprint.

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
