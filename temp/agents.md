# Análisis de Errores en AuthCore

Durante el proceso de estabilización del build general del ecosistema de `textea.me`, se ha detectado que el framework `AuthCore` (integrado como submódulo/symlink) presenta una serie de errores de compilación que impiden la construcción completa de la solución.

A continuación se detalla el diagnóstico y las sugerencias para resolverlos.

## 1. Naturaleza del Problema: Symlink y Rutas Relativas

**Diagnóstico:**
El directorio `AuthCore` dentro de `textea.me` es en realidad un enlace simbólico (symlink) que apunta a un directorio superior:
`AuthCore -> /home/luis/Documentos/Ptoyectos/AuthCore`

Cuando `dotnet build` se ejecuta desde la raíz de `textea.me`, MSBuild evalúa las rutas a través del symlink. Sin embargo, en ciertos contextos (como restauración de paquetes o resolución de referencias de proyectos), MSBuild y el compilador de C# (Roslyn) resuelven la ruta real del symlink. Esto genera una dualidad de rutas:
- `/home/luis/Documentos/Ptoyectos/textea.me/AuthCore/...`
- `/home/luis/Documentos/Ptoyectos/AuthCore/...`

Esta dualidad causa que algunos proyectos dependientes busquen los archivos `.dll` compilados en la ruta del symlink, mientras que el proceso de compilación los deposita en la ruta real (o viceversa), provocando el error recurrente:

> [!WARNING]
> `CSC : error CS0006: No se encontró el archivo de metadatos '/home/luis/Documentos/Ptoyectos/textea.me/AuthCore/src/SecureCore.Auth.OAuth/obj/Debug/net8.0/ref/SecureCore.Auth.OAuth.dll'`

## 2. Dependencias Faltantes en Proyectos Internos

Al intentar compilar proyectos individuales de `AuthCore` de forma aislada, se descubrieron dependencias NuGet faltantes en los archivos `.csproj`.

**Ejemplo: `SecureCore.Auth.OAuth.csproj`**
La compilación falla con los siguientes errores:
- `error CS0234: El tipo o el nombre del espacio de nombres 'Extensions' no existe en el espacio de nombres 'Microsoft'`
- `error CS0246: El nombre del tipo o del espacio de nombres 'IServiceCollection' no se encontró`
- `error CS0246: El nombre del tipo o del espacio de nombres 'IOptions<>' no se encontró`

**Diagnóstico:**
El código fuente utiliza abstracciones de inyección de dependencias y opciones, pero el archivo del proyecto no declara estas referencias.

## Sugerencias de Resolución

Para estabilizar `AuthCore` y permitir que la solución general compile al 100%, se recomiendan las siguientes acciones:

### A. Corregir Dependencias NuGet
Se deben añadir explícitamente los paquetes de extensiones de Microsoft al proyecto que está fallando (`SecureCore.Auth.OAuth.csproj` y posiblemente otros).

```xml
<!-- En SecureCore.Auth.OAuth.csproj -->
<ItemGroup>
  <PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="8.0.0" />
  <PackageReference Include="Microsoft.Extensions.Options" Version="8.0.0" />
</ItemGroup>
```

### B. Gestionar el Symlink Correctamente
Para evitar problemas de resolución de rutas y archivos de metadatos (`CS0006`), existen tres enfoques posibles:

1. **(Recomendado) Compilar AuthCore por separado:**
   En lugar de incluir los proyectos fuente de `AuthCore` en `Textea.slnx`, compila `AuthCore` en su propio repositorio/directorio real (`/home/luis/Documentos/Ptoyectos/AuthCore`) para generar paquetes NuGet (archivos `.nupkg`). Luego, haz que `textea.me` consuma esos paquetes NuGet localmente mediante un origen local (Local NuGet Feed).
   
2. **Reemplazar Symlink por Git Submodule:**
   Si necesitas editar el código en simultáneo, elimina el symlink y utiliza `git submodule add <url-repo-authcore> AuthCore`. Esto garantiza que los archivos existan físicamente dentro del árbol de directorios del proyecto, evitando la confusión de MSBuild con las rutas absolutas.

3. **Propiedades de Directorio:**
   Si se mantiene el symlink, considera crear un archivo `Directory.Build.props` en la raíz de `AuthCore` para forzar que los directorios de salida (`BaseOutputPath` y `BaseIntermediateOutputPath`) se generen en un directorio relativo consistente, independientemente de si se accede vía symlink o vía ruta real.
