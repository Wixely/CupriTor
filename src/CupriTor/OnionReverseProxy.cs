using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CupriTor;

/// <summary>
/// Helpers that turn an onion service into a reverse proxy: each inbound onion stream is pumped, byte for byte, to
/// a local backend. This is the "sidecar" model — the backend app is unaware of Tor and listens on a normal socket.
/// For a no-loopback, in-process integration (the onion stream fed straight to your web server as a connection),
/// use the CupriTor.AspNetCore transport instead.
/// </summary>
public static class OnionReverseProxy
{
    /// <summary>
    /// Build an <see cref="OnionStreamHandler"/> that dials <paramref name="host"/>:<paramref name="port"/> over TCP
    /// for every inbound onion stream and bridges the two connections until either side closes.
    /// </summary>
    public static OnionStreamHandler ToTcp(string host, int port) => async (stream, _, ct) =>
    {
        using var backend = new TcpClient();
        try
        {
            await backend.ConnectAsync(host, port, ct).ConfigureAwait(false);
            await PumpAsync(stream, backend.GetStream(), ct).ConfigureAwait(false);
        }
        finally
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    };

    /// <summary>Bidirectionally copy between two streams until either direction ends. Does not dispose either stream.</summary>
    public static async Task PumpAsync(Stream a, Stream b, CancellationToken ct)
    {
        try
        {
            await Task.WhenAny(CopyAsync(a, b, ct), CopyAsync(b, a, ct)).ConfigureAwait(false);
        }
        catch { /* connection ended */ }
    }

    private static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[4096];
        int n;
        while ((n = await from.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            await to.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
            await to.FlushAsync(ct).ConfigureAwait(false);
        }
    }
}
