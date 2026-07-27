namespace CupriTor;

/// <summary>
/// A concurrency throttle for outbound dials. At most <c>limit</c> holders may hold a slot at once; further
/// acquirers wait (honouring cancellation) until one is released. A <c>limit</c> of 0 means unlimited — acquiring
/// is then a cheap no-op. Acquire a slot with <see cref="AcquireAsync"/> and dispose the returned handle to release
/// it. Thread-safe; a single instance is shared across all concurrent dials on a client.
/// </summary>
internal sealed class DialGate : IDisposable
{
    private readonly SemaphoreSlim? _sem; // null == unlimited

    public DialGate(int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(limit);
        _sem = limit > 0 ? new SemaphoreSlim(limit, limit) : null;
    }

    /// <summary>Free slots right now (diagnostics/tests); <see cref="int.MaxValue"/> when the gate is unlimited.</summary>
    public int AvailableSlots => _sem?.CurrentCount ?? int.MaxValue;

    /// <summary>
    /// Acquire a slot, waiting if the gate is currently full. Dispose the returned handle to release the slot.
    /// Throws <see cref="OperationCanceledException"/> if <paramref name="ct"/> fires while waiting.
    /// </summary>
    public async ValueTask<IDisposable> AcquireAsync(CancellationToken ct)
    {
        if (_sem is null) return NoopReleaser.Instance;
        await _sem.WaitAsync(ct).ConfigureAwait(false);
        return new Releaser(_sem);
    }

    public void Dispose() => _sem?.Dispose();

    // Releases exactly one slot on the first Dispose; further disposes are ignored (a held slot can't be over-released).
    private sealed class Releaser(SemaphoreSlim sem) : IDisposable
    {
        private SemaphoreSlim? _sem = sem;
        public void Dispose() => Interlocked.Exchange(ref _sem, null)?.Release();
    }

    private sealed class NoopReleaser : IDisposable
    {
        public static readonly NoopReleaser Instance = new();
        public void Dispose() { }
    }
}
