using SampleApi.Stores;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.AspNetCore;

// ═══════════════════════════════════════════════════════════════════════════
//  SecureCore Auth Framework — API de Ejemplo
// ═══════════════════════════════════════════════════════════════════════════
// Este proyecto demuestra cómo integrar la librería en una aplicación
// ASP.NET Core real. Incluye:
//   1. Configuración mínima usando la Fluent API
//   2. Stores en memoria (para demo; en producción usar EF Core, Dapper, etc.)
//   3. Endpoints de autenticación listos para usar
//   4. Endpoint protegido de ejemplo
//   5. Usuario de prueba pre-cargado
// ═══════════════════════════════════════════════════════════════════════════

var builder = WebApplication.CreateBuilder(args);

// ─── Paso 1: Registrar los stores en memoria (singleton para persistir entre requests) ───
var userStore = new InMemoryUserStore();
var sessionStore = new InMemorySessionStore();
var credentialStore = new InMemoryCredentialStore();

builder.Services.AddSingleton<IUserStore>(userStore);
builder.Services.AddSingleton(userStore); // También como tipo concreto para el endpoint de registro
builder.Services.AddSingleton<ISessionStore>(sessionStore);
builder.Services.AddSingleton<ICredentialStore>(credentialStore);

// ─── Paso 2: Registrar caché distribuida en memoria (para SecurityStampValidator) ───
builder.Services.AddDistributedMemoryCache();

// ─── Paso 3: Configurar SecureCore Auth usando la Fluent API ───
builder.Services.AddSecureAuth(options =>
{
    // Configuración JWT — en producción, usar secrets/Key Vault
    options.Jwt.Issuer = builder.Configuration["SecureAuth:Jwt:Issuer"] ?? "sample-api";
    options.Jwt.Audience = builder.Configuration["SecureAuth:Jwt:Audience"] ?? "sample-api-client";
    options.Jwt.SigningKey = builder.Configuration["SecureAuth:Jwt:SigningKey"]
        ?? "SuperSecretKeyForDevelopment_ChangeThisInProduction_32chars!";

    // Configuración de autenticación
    options.Auth.AccessTokenLifetime = TimeSpan.FromMinutes(15);
    options.Auth.RefreshTokenLifetime = TimeSpan.FromDays(7);
    options.Auth.GracePeriodSeconds = 30;
    options.Auth.MaxFailedAttempts = 5;
})
.AddPasswordAuthentication();  // Habilita login con contraseña (Argon2id)

// Swagger/OpenAPI para explorar los endpoints
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "SecureCore Auth - Sample API", Version = "v1" });

    // Agregar soporte para JWT en Swagger
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization. Escriba 'Bearer {token}' en el campo.",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// ─── Paso 4: Configurar el pipeline ───
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseSecureAuthValidation(); // Middleware de validación de SecurityStamp
app.UseAuthorization();

// ─── Paso 5: Mapear endpoints de autenticación ───
// Esto crea: POST /auth/login, POST /auth/refresh, POST /auth/logout, POST /auth/revoke-all
app.MapSecureAuthEndpoints("/auth");

// ─── Paso 6: Endpoints de ejemplo ───

// Endpoint público (no requiere autenticación)
app.MapGet("/", () => Results.Ok(new
{
    message = "🔐 SecureCore Auth Framework — Sample API",
    docs = "/swagger",
    endpoints = new
    {
        login = "POST /auth/login",
        refresh = "POST /auth/refresh",
        logout = "POST /auth/logout",
        revokeAll = "POST /auth/revoke-all",
        profile = "GET /api/profile (requiere autenticación)",
        register = "POST /api/register"
    },
    testUser = new
    {
        email = "demo@securecore.dev",
        password = "P@ssw0rd123!"
    }
}))
.WithName("Home")
.WithTags("Info");

// Endpoint protegido — requiere JWT válido
app.MapGet("/api/profile", (HttpContext context) =>
{
    var userId = context.User.FindFirst("sub")?.Value;
    var email = context.User.FindFirst("email")?.Value;
    var ssv = context.User.FindFirst("ssv")?.Value;

    return Results.Ok(new
    {
        message = "¡Acceso autorizado! Tu token JWT es válido.",
        userId,
        email,
        securityStampVersion = ssv,
        tokenExpires = context.User.FindFirst("exp")?.Value
    });
})
.RequireAuthorization()
.WithName("GetProfile")
.WithTags("Profile");

// Endpoint de registro de usuarios
app.MapPost("/api/register", async (
    RegisterRequest request,
    InMemoryUserStore store,
    IPasswordHasher hasher,
    CancellationToken ct) =>
{
    // Verificar si el email ya existe
    var existing = await store.FindByEmailAsync(request.Email.ToLowerInvariant(), ct);
    if (existing is not null)
    {
        return Results.Conflict(new { error = "email_exists", message = "El email ya está registrado." });
    }

    // Crear el usuario
    var user = new UserIdentity
    {
        Id = Guid.NewGuid().ToString(),
        Email = request.Email.ToLowerInvariant(),
        DisplayName = request.DisplayName,
        PasswordHash = hasher.HashPassword(request.Password),
        SecurityStamp = Guid.NewGuid().ToString()
    };

    store.SeedUser(user);

    return Results.Created($"/api/profile", new
    {
        message = "Usuario registrado exitosamente.",
        userId = user.Id,
        email = user.Email
    });
})
.AllowAnonymous()
.WithName("Register")
.WithTags("Registration");

// ─── Paso 7: Pre-cargar usuario de prueba ───
SeedTestData(userStore, app.Services);

app.Run();

// ─── Funciones auxiliares ───

static void SeedTestData(InMemoryUserStore userStore, IServiceProvider services)
{
    using var scope = services.CreateScope();
    var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();

    var testUser = new UserIdentity
    {
        Id = "user-001",
        Email = "demo@securecore.dev",
        DisplayName = "Usuario Demo",
        PasswordHash = hasher.HashPassword("P@ssw0rd123!"),
        SecurityStamp = Guid.NewGuid().ToString()
    };

    userStore.SeedUser(testUser);
}

// ─── DTOs de los endpoints ───
record RegisterRequest(string Email, string Password, string? DisplayName);
