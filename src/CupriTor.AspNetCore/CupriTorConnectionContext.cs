using System.IO.Pipelines;
using System.Net;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;

namespace CupriTor.AspNetCore;

/// <summary>
/// A Kestrel <see cref="ConnectionContext"/> backed by a single onion stream. No socket, no loopback: Kestrel's
/// HTTP parser reads requests from, and writes responses to, the Tor stream directly.
/// </summary>
internal sealed class CupriTorConnectionContext : ConnectionContext
{
    private readonly Stream _stream;
    private readonly CancellationTokenSource _closed = new();
    private int _disposed;

    public CupriTorConnectionContext(string id, Stream stream, EndPoint localEndPoint)
    {
        _stream = stream;
        Transport = new DuplexStreamPipe(stream);
        ConnectionId = id;
        LocalEndPoint = localEndPoint;
        ConnectionClosed = _closed.Token;
    }

    public override IDuplexPipe Transport { get; set; }
    public override string ConnectionId { get; set; }
    public override IFeatureCollection Features { get; } = new FeatureCollection();
    public override IDictionary<object, object?> Items { get; set; } = new Dictionary<object, object?>();

    public override void Abort(ConnectionAbortedException abortReason)
    {
        // Tear the stream down; Kestrel's read/parse loop observes the close and finishes the connection.
        _ = DisposeAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _closed.Cancel(); } catch { /* nobody listening */ }
        try { Transport.Input.Complete(); } catch { }
        try { Transport.Output.Complete(); } catch { }
        try { await _stream.DisposeAsync().ConfigureAwait(false); } catch { /* best effort → RELAY_END */ }
        _closed.Dispose();
    }
}
