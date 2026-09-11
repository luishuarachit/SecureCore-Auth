using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace SecureCore.Auth.AspNetCore;

/// <summary>
/// Filtro de validación basado en DataAnnotations para cuerpos JSON de Minimal APIs.
/// </summary>
/// <remarks>
/// DIDÁCTICA: El <c>RequestDelegateFactory</c> de Minimal APIs NO valida automáticamente
/// las anotaciones de datos de los cuerpos enlazados (la validación solo la disparan
/// <c>[ApiController]</c> en MVC y el binder JSON no consulta <c>[Required]</c>). Este filtro
/// ejecuta <c>Validator.TryValidateObject</c> sobre el argumento enlazado y devuelve un
/// <c>400 ValidationProblem</c> homogéneo (RFC 7807) usando los atributos ya declarados en
/// el DTO como única fuente de verdad del contrato.
/// </remarks>
internal sealed class DataAnnotationsValidationFilter<T> : IEndpointFilter
    where T : class
{
    /// <summary>
    /// Instancia compartida del filtro para el tipo <typeparamref name="T"/>.
    /// </summary>
    public static DataAnnotationsValidationFilter<T> Instance { get; } = new();

    /// <inheritdoc />
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        // DIDÁCTICA: Los endpoint filters se ejecutan DESPUÉS del binding, reciben los
        // argumentos ya enlazados. Localizamos el cuerpo por tipo para no depender del
        // orden de parámetros del handler.
        var request = context.Arguments.OfType<T>().FirstOrDefault();
        if (request is null)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["body"] = ["El cuerpo de la solicitud es inválido."]
            });
        }

        var validationResults = new List<ValidationResult>();
        if (!Validator.TryValidateObject(request, new ValidationContext(request), validationResults, validateAllProperties: true))
        {
            return Results.ValidationProblem(BuildErrors(validationResults));
        }

        return await next(context);
    }

    private static Dictionary<string, string[]> BuildErrors(IEnumerable<ValidationResult> validationResults)
    {
        var errors = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var failure in validationResults)
        {
            var members = failure.MemberNames.ToList();
            if (members.Count == 0)
            {
                members.Add("model");
            }

            foreach (var member in members)
            {
                if (!errors.TryGetValue(member, out var messages))
                {
                    messages = [];
                    errors[member] = messages;
                }

                if (failure.ErrorMessage is { } message)
                {
                    messages.Add(message);
                }
            }
        }

        // DIDÁCTICA: Normalizamos las claves a camelCase ("Origin" -> "origin") para que
        // coincidan con los nombres usados en el JSON del request.
        return errors.ToDictionary(kv => ToCamelCase(kv.Key), kv => kv.Value.ToArray());
    }

    private static string ToCamelCase(string name)
    {
        if (string.IsNullOrEmpty(name) || char.IsLower(name[0]))
        {
            return name;
        }

        return char.ToLowerInvariant(name[0]) + name[1..];
    }
}
