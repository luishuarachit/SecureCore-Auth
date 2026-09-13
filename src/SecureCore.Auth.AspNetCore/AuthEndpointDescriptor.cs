using System.Net.Http;
using Microsoft.AspNetCore.Builder;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Descriptor declarativo de un endpoint del kit HTTP (F7, A-26).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F7): el registro de endpoints se convierte en DATO. Un descriptor describe UNA
/// feature (método, ruta, handler, autorización, filtros y metadatos) sin ejecutar nada; el
/// compositor <c>MapAuthEndpoints</c> lo materializa en el pipeline. Esto respeta:
/// - OCP: una feature nueva es un descriptor nuevo — el compositor no se modifica.
/// - DIP: el compositor depende de esta abstracción, no de handlers concretos.
/// - SRP: el descriptor solo describe; el handler solo traduce; el compositor solo registra.
///
/// El host puede componer su propia superficie seleccionando descriptores, re-ruteando handlers
/// (<c>app.MapPost("/custom", SecureAuthEndpoints.LoginHandler)</c>) o añadiendo sus propios
/// filtros vía <c>Configure</c>.
/// </remarks>
/// <param name="Method">Verbo HTTP del endpoint.</param>
/// <param name="RouteTemplate">Ruta relativa dentro del prefijo del grupo (ej: "/login").</param>
/// <param name="Handler">Delegate del handler (resuelve sus dependencias por DI en tiempo de bind).</param>
/// <param name="RequiresAuthorization">true → <c>RequireAuthorization()</c>; false → <c>AllowAnonymous()</c>.</param>
/// <param name="Configure">Permite añadir filtros, tags u otras convenciones al builder del endpoint.</param>
/// <param name="Name">Nombre del endpoint (para <c>WithName</c> y generación de links).</param>
/// <param name="Description">Descripción OpenAPI (para <c>WithDescription</c>).</param>
public sealed record AuthEndpointDescriptor(
    HttpMethod Method,
    string RouteTemplate,
    Delegate Handler,
    bool RequiresAuthorization,
    Func<IEndpointConventionBuilder, IEndpointConventionBuilder>? Configure = null,
    string? Name = null,
    string? Description = null);
