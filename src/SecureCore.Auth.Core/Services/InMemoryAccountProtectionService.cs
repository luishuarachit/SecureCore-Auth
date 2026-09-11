using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Options;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Models;
using SecureCore.Auth.Abstractions.Options;

namespace SecureCore.Auth.Core.Services;

/// <summary>
/// Implementación por defecto de <see cref="IAccountProtectionService"/> en memoria.
/// </summary>
/// <remarks>
/// DIDÁCTICA: Estado por (scope, key) con ventana deslizante y escalamiento por niveles:
///
/// 1. Se acumulan los fallos dentro de <see cref="AccountProtectionOptions.Window"/>.
/// 2. Al alcanzar el máximo del scope se activa un lockout de duración escalonada
///    (1er bloqueo 10 min → 2º 30 min → 3º 1 h → ≥4º 24 h, techo <c>MaxLockDuration</c>).
/// 3. Durante un lockout los fallos se ignoran (no se extiende ni se escala).
/// 4. El lockout decae solo al expirar (revisión perezosa); el nivel se conserva entre
///    ciclos para que los bloqueos consecutivos escalen.
/// 5. Un éxito o un reset limpian el estado del scope.
///
/// LIMITACIÓN (multi-instancia): el estado es in-process. En despliegues distribuidos
/// implemente <see cref="IAccountProtectionService"/> sobre un store compartido (Redis
/// INCR+EXPIRE, SQL, etc.); el contrato no impone el almacén.
///
/// Thread-safety: cada entrada se vuelve atómica lockeando la instancia de entrada.
/// </remarks>
public sealed class InMemoryAccountProtectionService(
    IOptions<AccountProtectionOptions> options,
    TimeProvider? timeProvider = null) : IAccountProtectionService
{
    private readonly AccountProtectionOptions _options = options.Value;
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<(AccountProtectionScope Scope, string Key), ProtectionEntry> _entries = new();

    private DateTimeOffset UtcNow => _clock.GetUtcNow();

    public ValueTask<AccountProtectionResult> CheckAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var entry = GetOrCreate(scope, key);
        var now = UtcNow;

        lock (entry)
        {
            Prune(entry, now);

            if (entry.LockEnd is { } lockEnd && lockEnd > now)
            {
                return ValueTask.FromResult(
                    new AccountProtectionResult(Allowed: false, RemainingAttempts: 0, LockEnd: lockEnd, EscalationLevel: entry.EscalationLevel));
            }

            var remaining = Math.Max(0, _options.GetMaxAttempts(scope) - entry.Failures.Count);
            return ValueTask.FromResult(
                new AccountProtectionResult(Allowed: true, RemainingAttempts: remaining, LockEnd: null, EscalationLevel: entry.EscalationLevel));
        }
    }

    public ValueTask RecordFailureAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var entry = GetOrCreate(scope, key);
        var now = UtcNow;
        var maxAttempts = _options.GetMaxAttempts(scope);

        lock (entry)
        {
            Prune(entry, now);

            // Durante un lockout activo los fallos se ignoran (no extienden ni escalan).
            if (entry.LockEnd is { } lockEnd && lockEnd > now)
            {
                return ValueTask.CompletedTask;
            }

            entry.Failures.Enqueue(now);

            if (entry.Failures.Count < maxAttempts)
            {
                return ValueTask.CompletedTask;
            }

            // Se alcanzó el máximo: escalar un nivel y activar lockout.
            var level = Math.Min(entry.EscalationLevel + 1, _options.EscalationDurations.Count);
            entry.EscalationLevel = level;
            entry.LockEnd = now + _options.GetLockDuration(level);
            entry.Failures.Clear();

            return ValueTask.CompletedTask;
        }
    }

    public ValueTask RecordSuccessAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        _entries.TryRemove((scope, key), out _);
        return ValueTask.CompletedTask;
    }

    public ValueTask ResetAsync(
        AccountProtectionScope scope,
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        _entries.TryRemove((scope, key), out _);
        return ValueTask.CompletedTask;
    }

    public ValueTask ResetAllForUserAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        foreach (var kvp in _entries.ToArray())
        {
            if (kvp.Key.Key == key)
            {
                _entries.TryRemove(kvp.Key, out _);
            }
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask<bool> AnyActiveLockAsync(
        string key,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var now = UtcNow;

        foreach (var kvp in _entries.ToArray())
        {
            if (kvp.Key.Key != key)
            {
                continue;
            }

            lock (kvp.Value)
            {
                Prune(kvp.Value, now);

                if (kvp.Value.LockEnd is { } lockEnd && lockEnd > now)
                {
                    return ValueTask.FromResult(true);
                }
            }
        }

        return ValueTask.FromResult(false);
    }

    private ProtectionEntry GetOrCreate(AccountProtectionScope scope, string key) =>
        _entries.GetOrAdd((scope, key), static _ => new ProtectionEntry());

    /// <summary>
    /// LIMITACIÓN (revisión perezosa): descarta fallos fuera de la ventana y expira lockouts.
    /// </summary>
    private void Prune(ProtectionEntry entry, DateTimeOffset now)
    {
        var cutoff = now - _options.GetWindow();

        while (entry.Failures.Count > 0 && entry.Failures.Peek() < cutoff)
        {
            entry.Failures.Dequeue();
        }

        if (entry.LockEnd is { } lockEnd && lockEnd <= now)
        {
            entry.LockEnd = null;
            entry.Failures.Clear();
        }
    }

    private sealed class ProtectionEntry
    {
        public Queue<DateTimeOffset> Failures { get; } = new();

        public DateTimeOffset? LockEnd { get; set; }

        public int EscalationLevel { get; set; }
    }
}
