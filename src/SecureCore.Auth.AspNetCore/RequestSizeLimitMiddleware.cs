using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Middleware que asigna un límite físico (en bytes) al cuerpo de las solicitudes
/// dirigidas a los endpoints de autenticación mapeados con <c>MapSecureAuthEndpoints</c>.
/// </summary>
/// <remarks>
/// DIDÁCTICA: En Minimal APIs los endpoint filters se ejecutan DESPUÉS del binding del
/// cuerpo, por lo que un filter NO puede reducir el límite antes de que Kestrel lea el
/// payload. Este middleware corre ANTES de ese binding: asigna
/// <c>IHttpMaxRequestBodySizeFeature.MaxRequestBodySize</c> y, si la solicitud supera el
/// límite, la lectura del cuerpo por parte del framework lanza BadHttpRequestException,
/// que Kestrel traduce a 413 Payload Too Large.
///
/// Es la protección REAL contra payloads grandes (incluye cuerpos chunked sin
/// Content-Length, que un filter no puede atajar). Debe registrarse SIEMPRE que se use
/// <c>MapSecureAuthEndpoints</c>:
/// <code>
/// app.MapSecureAuthEndpoints("/auth");
/// app.UseSecureAuthRequestSizeLimit("/auth");
/// </code>
///
/// Solo aplica el límite a rutas bajo el prefijo suministrado (por defecto "/auth").
/// El resto de la aplicación conserva el límite global de Kestrel
/// (<c>Kestrel.MaxRequestBodySize</c>).
/// </remarks>
public sealed class RequestSizeLimitMiddleware(
    RequestDelegate next,
    IOptions<SecureAuthOptions> options,
    PathString pathPrefix)
{
    /// <summary>
    /// Procesa la solicitud aplicando el límite de tamaño de cuerpo.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments(pathPrefix, out var remainingPath))
        {
            // DIDÁCTICA (S4): los endpoints WebAuthn (/…/webauthn/*) transportan payloads FIDO2
            // (clientDataJSON + attestationObject/authenticatorData en Base64URL) que superan el
            // límite de 2048 bytes pensado para /login y friends. NO quedan ilimitados (A-29):
            // se les asigna un tope explícito propio (MaxWebAuthnRequestBodySize, 64KB default)
            // para acotar el buffer en memoria ante payloads arbitrarios.
            if (remainingPath.StartsWithSegments("/webauthn", StringComparison.Ordinal))
            {
                var fidoFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
                if (fidoFeature is not null && !fidoFeature.IsReadOnly)
                {
                    fidoFeature.MaxRequestBodySize = options.Value.MaxWebAuthnRequestBodySize;
                }

                await next(context);
                return;
            }

            var feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
            if (feature is not null && !feature.IsReadOnly)
            {
                feature.MaxRequestBodySize = options.Value.MaxAuthRequestBodySize;
            }
        }

        await next(context);
    }
}
