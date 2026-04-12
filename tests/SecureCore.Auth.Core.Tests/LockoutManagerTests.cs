using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using SecureCore.Auth.Abstractions;
using SecureCore.Auth.Abstractions.Interfaces;
using SecureCore.Auth.Abstractions.Options;
using SecureCore.Auth.Core.Services;

namespace SecureCore.Auth.Core.Tests;

/// <summary>
/// Tests para LockoutManager — bloqueo exponencial de cuentas.
/// </summary>
public class LockoutManagerTests
{
    private readonly LockoutManager _lockoutManager;
    private readonly IUserStore _userStore;

    public LockoutManagerTests()
    {
        _userStore = Substitute.For<IUserStore>();
        var options = Options.Create(new SecureAuthOptions
        {
            MaxFailedAttempts = 5,
            LockoutDurations =
            [
                TimeSpan.FromMinutes(1),
                TimeSpan.FromMinutes(5),
                TimeSpan.FromMinutes(15)
            ]
        });
        var logger = NullLogger<LockoutManager>.Instance;
        _lockoutManager = new LockoutManager(_userStore, options, logger);
    }

    [Fact]
    public void IsLockedOut_NoLockoutEnd_ReturnsFalse()
    {
        var user = new UserIdentity
        {
            Id = "u1", Email = "a@b.c", SecurityStamp = "s",
            PasswordHash = "h", LockoutEnd = null
        };

        Assert.False(_lockoutManager.IsLockedOut(user));
    }

    [Fact]
    public void IsLockedOut_LockoutInPast_ReturnsFalse()
    {
        var user = new UserIdentity
        {
            Id = "u1", Email = "a@b.c", SecurityStamp = "s",
            PasswordHash = "h",
            LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(-1)
        };

        Assert.False(_lockoutManager.IsLockedOut(user));
    }

    [Fact]
    public void IsLockedOut_LockoutInFuture_ReturnsTrue()
    {
        var user = new UserIdentity
        {
            Id = "u1", Email = "a@b.c", SecurityStamp = "s",
            PasswordHash = "h",
            LockoutEnd = DateTimeOffset.UtcNow.AddMinutes(10)
        };

        Assert.True(_lockoutManager.IsLockedOut(user));
    }

    [Fact]
    public async Task HandleFailedAttemptAsync_BelowThreshold_DoesNotLock()
    {
        // Act — 4 intentos fallidos (umbral es 5)
        await _lockoutManager.HandleFailedAttemptAsync("u1", 4);

        // Assert — no se llamó a SetLockoutEndAsync
        await _userStore.DidNotReceive().SetLockoutEndAsync(
            Arg.Any<string>(), Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task HandleFailedAttemptAsync_AtThreshold_LocksAccount()
    {
        // Act — 5 intentos fallidos (umbral alcanzado)
        await _lockoutManager.HandleFailedAttemptAsync("u1", 5);

        // Assert — se llamó a SetLockoutEndAsync
        await _userStore.Received(1).SetLockoutEndAsync(
            "u1", Arg.Any<DateTimeOffset?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task HandleFailedAttemptAsync_SecondLockout_LongerDuration()
    {
        // Arrange — capturamos los argumentos de todos los llamados
        var capturedLockouts = new List<DateTimeOffset?>();
        _userStore.SetLockoutEndAsync(
                Arg.Any<string>(),
                Arg.Do<DateTimeOffset?>(x => capturedLockouts.Add(x)),
                Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        // Act — primer bloqueo (intento #5) y segundo bloqueo (intento #10)
        await _lockoutManager.HandleFailedAttemptAsync("u1", 5);
        await _lockoutManager.HandleFailedAttemptAsync("u1", 10);

        // Assert — 2 bloqueos capturados, el segundo más largo
        Assert.Equal(2, capturedLockouts.Count);
        Assert.NotNull(capturedLockouts[0]);
        Assert.NotNull(capturedLockouts[1]);
        Assert.True(capturedLockouts[1] > capturedLockouts[0]);
    }
}
