using CupriTor;
using Xunit;

namespace CupriTor.Tests;

public class DialGateTests
{
    [Fact]
    public async Task Unlimited_Gate_Never_Blocks()
    {
        using var gate = new DialGate(0);

        // Acquire far more than any real cap without releasing; none should block, and slots read as unbounded.
        var holders = new List<IDisposable>();
        for (int i = 0; i < 128; i++)
            holders.Add(await gate.AcquireAsync(default));

        Assert.Equal(int.MaxValue, gate.AvailableSlots);
        foreach (IDisposable h in holders) h.Dispose();
    }

    [Fact]
    public async Task Gate_Limits_Concurrent_Holders_To_The_Cap()
    {
        using var gate = new DialGate(2);

        IDisposable a = await gate.AcquireAsync(default);
        IDisposable b = await gate.AcquireAsync(default);
        Assert.Equal(0, gate.AvailableSlots);

        // A third acquire must not complete while the gate is full.
        Task<IDisposable> third = gate.AcquireAsync(default).AsTask();
        Assert.False(third.IsCompleted);

        a.Dispose();                 // free one slot
        IDisposable c = await third; // the waiter now proceeds into the freed slot
        Assert.Equal(0, gate.AvailableSlots);

        b.Dispose();
        c.Dispose();
        Assert.Equal(2, gate.AvailableSlots);
    }

    [Fact]
    public async Task Acquire_Honours_Cancellation_While_Waiting()
    {
        using var gate = new DialGate(1);
        IDisposable a = await gate.AcquireAsync(default);

        using var cts = new CancellationTokenSource();
        Task<IDisposable> pending = gate.AcquireAsync(cts.Token).AsTask();
        Assert.False(pending.IsCompleted);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);

        // The cancelled waiter took no slot; the one held by 'a' is still releasable back into the pool.
        a.Dispose();
        Assert.Equal(1, gate.AvailableSlots);
    }

    [Fact]
    public async Task Double_Dispose_Releases_At_Most_One_Slot()
    {
        using var gate = new DialGate(1);
        IDisposable a = await gate.AcquireAsync(default);

        a.Dispose();
        a.Dispose(); // must not over-release the semaphore

        Assert.Equal(1, gate.AvailableSlots);
    }

    [Fact]
    public void Negative_Limit_Is_Rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new DialGate(-1));
    }
}
