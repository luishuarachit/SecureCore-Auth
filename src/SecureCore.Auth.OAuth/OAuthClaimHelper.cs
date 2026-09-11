using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureCore.Auth.OAuth;

/// <summary>
/// Helper para extraer claims de un JwtSecurityToken preservando los tipos cortos originales.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Cuando ValidateToken genera un ClaimsPrincipal, mapea los tipos cortos
/// del JWT ("sub", "email", "name", "picture") a URIs completas de ClaimTypes
/// (ej. "sub" → "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").
///
/// Esto causa que principal.FindFirst("sub") retorne null, porque el claim ya fue
/// renombrado. Los validadores OAuth que usan principal.FindFirst con nombres cortos
/// obtienen valores null, rompiendo ProviderKey, Email, DisplayName y AvatarUrl.
///
/// La solución correcta es leer directamente del JwtSecurityToken, que preserva
/// los tipos originales del JWT emitido por el proveedor OIDC.
///
/// Este helper centraliza la extracción para todos los validadores OAuth,
/// evitando duplicación de código y el riesgo de que futuros validadores
/// cometan el mismo error.
/// </remarks>
public static class OAuthClaimHelper
{
    /// <summary>
    /// Obtiene el valor de un claim del JwtSecurityToken usando el tipo corto original.
    /// </summary>
    /// <param name="jwt">El JWT validado.</param>
    /// <param name="claimType">Tipo corto del claim (ej. "sub", "email", "name").</param>
    /// <returns>El valor del claim, o null si no existe.</returns>
    public static string? GetClaim(JwtSecurityToken jwt, string claimType)
    {
        return jwt.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }

    /// <summary>
    /// Compara dos valores (nonce, state) en TIEMPO CONSTANTE.
    /// </summary>
    /// <remarks>
    /// DIDÁCTICA (auditoría): comparar el nonce con <c>==</c> permite a un atacante medir por
    /// timing cuántos caracteres acertó. FixedTimeEquals mantiene el tiempo independiente del
    /// contenido; la longitud se compara primero (para valores de longitud fija, como nonces
    /// CSPRNG, no revela información útil).
    /// </remarks>
    public static bool FixedTimeEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }

        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);
        return bytesA.Length == bytesB.Length && CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }
}
