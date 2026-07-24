using CupriTor.Protocol;

namespace CupriTor;

/// <summary>
/// A built, running Tor circuit. Open application streams over it: a directory stream (BEGIN_DIR) to the
/// last hop, or — once onion-service support is wired — a stream to a target. Disposing the circuit tears
/// down its streams and the underlying OR connection.
/// </summary>
public sealed class TorCircuit : IAsyncDisposable
{
    private readonly OrConnection _connection;
    private readonly Circuit _circuit;

    internal TorCircuit(OrConnection connection, Circuit circuit)
    {
        _connection = connection;
        _circuit = circuit;
    }

    /// <summary>Number of hops in the circuit.</summary>
    public int Length => _circuit.HopCount;

    /// <summary>Open a directory stream (BEGIN_DIR) to the last hop and return it as a duplex stream.</summary>
    public async Task<Stream> OpenDirectoryStreamAsync(CancellationToken ct = default) =>
        await _circuit.OpenDirectoryStreamAsync(ct).ConfigureAwait(false);

    /// <summary>Open a stream to <paramref name="target"/> ("host:port") through the last hop.</summary>
    public async Task<Stream> ConnectAsync(string target, CancellationToken ct = default) =>
        await _circuit.ConnectAsync(target, ct).ConfigureAwait(false);

    public async ValueTask DisposeAsync()
    {
        await _circuit.DisposeAsync().ConfigureAwait(false);
        await _connection.DisposeAsync().ConfigureAwait(false);
    }
}
