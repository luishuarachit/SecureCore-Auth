using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Configura <c>JwtBearerOptions</c> a partir de <c>IOptions&lt;JwtOptions&gt;</c> (F7, A-26).
/// </summary>
/// <remarks>
/// DIDÁCTICA (F7): la VALIDACIÓN JWT usa ahora la MISMA fuente que la EMISIÓN
/// (<c>JwtTokenService</c> lee <c>IOptions&lt;JwtOptions&gt;</c>). Antes, el Bearer construía los
/// parámetros desde el objeto de la Fluent API (<c>config.Jwt</c>), ignorando appsettings: un host
/// configurado solo por <c>SecureAuth:Jwt</c> emitía con una clave y validaba con otra (o fallaba).
/// Una sola fuente evita la desincronización (DIP: depende de <c>IOptions</c>, no de un concreto).
/// </remarks>
public sealed class ConfigureJwtBearerOptions(
    IOptions<JwtOptions> jwtOptions,
    IOptions<SecureAuthOptions> authOptions) : IConfigureNamedOptions<JwtBearerOptions>
{
    public void Configure(string? name, JwtBearerOptions options)
        => Configure(options);

    public void Configure(JwtBearerOptions options)
    {
        var jwt = jwtOptions.Value;
        var auth = authOptions.Value;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = ServiceCollectionExtensions.CreateIssuerSigningKey(jwt),
            ClockSkew = auth.ClockSkew
        };

        // DIDÁCTICA (A-24): hook OPT-IN de blacklist de access tokens. Con el default
        // NoOpTokenBlacklist el chequeo es no-op; el host que registra su implementación consigue
        // que un jti revocado en /logout falle la autenticación.
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var blacklist = context.HttpContext.RequestServices.GetService<ITokenBlacklist>();
                if (blacklist is null)
                {
                    return;
                }

                var jti = (context.SecurityToken as JwtSecurityToken)?.Id;
                if (string.IsNullOrEmpty(jti))
                {
                    return;
                }

                if (await blacklist.IsBlacklistedAsync(jti, context.HttpContext.RequestAborted))
                {
                    context.Fail("El token de acceso fue revocado.");
                }
            }
        };
    }
}
