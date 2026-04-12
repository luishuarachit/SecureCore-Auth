using System.ComponentModel.DataAnnotations;

namespace SecureCore.Auth.Abstractions.Options;

/// <summary>
/// Opciones de configuración para el hashing de contraseñas con Argon2id.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Argon2id tiene tres parámetros principales que controlan su dificultad:
/// - MemorySize: cuánta RAM usa (en KB). Más memoria = más difícil para GPUs.
/// - Iterations: cuántas veces se repite el cálculo. Más iteraciones = más lento.
/// - Parallelism: cuántos hilos usa. Ajustar según los cores del servidor.
///
/// Los valores por defecto (64 MB, 3 iteraciones, 4 hilos) son los recomendados
/// por OWASP para un equilibrio entre seguridad y rendimiento en 2024.
/// </remarks>
public class Argon2Options
{
    /// <summary>
    /// Sección del archivo de configuración.
    /// </summary>
    public const string SectionName = "SecureAuth:Argon2";

    /// <summary>
    /// Memoria a utilizar en KB. Por defecto: 65536 (64 MB).
    /// </summary>
    [Range(1024, 1048576, ErrorMessage = "La memoria debe estar entre 1 MB y 1 GB.")]
    public int MemorySize { get; set; } = 65536;

    /// <summary>
    /// Número de iteraciones. Por defecto: 3.
    /// </summary>
    [Range(1, 100, ErrorMessage = "El número de iteraciones debe estar entre 1 y 100.")]
    public int Iterations { get; set; } = 3;

    /// <summary>
    /// Grado de paralelismo (hilos). Por defecto: 4.
    /// </summary>
    [Range(1, 64, ErrorMessage = "El paralelismo debe estar entre 1 y 64 hilos.")]
    public int Parallelism { get; set; } = 4;

    /// <summary>
    /// Tamaño del salt en bytes. Por defecto: 16.
    /// </summary>
    [Range(8, 128, ErrorMessage = "El tamaño del salt debe estar entre 8 y 128 bytes.")]
    public int SaltSize { get; set; } = 16;

    /// <summary>
    /// Tamaño del hash resultante en bytes. Por defecto: 32.
    /// </summary>
    [Range(16, 512, ErrorMessage = "El tamaño del hash debe estar entre 16 y 512 bytes.")]
    public int HashSize { get; set; } = 32;
}
