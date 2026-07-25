using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CupriTor;

/// <summary>
/// Handles a single inbound onion stream.
/// </summary>
/// <param name="stream">
/// The accepted duplex stream to the client. The rendezvous circuit has already replied RELAY_CONNECTED, so the
/// stream is ready for reading and writing. The handler <b>owns</b> this stream and must dispose it when finished
/// (disposing sends RELAY_END to the client). This is the raw Tor stream — no loopback socket is involved.
/// </param>
/// <param name="target">
/// The "host:port" the client requested in RELAY_BEGIN. For a single-purpose onion this is typically empty (Tor
/// clients omit the host for a hidden service); use it only if you multiplex several backends behind one address.
/// </param>
/// <param name="cancellationToken">Fired when the service is shutting down.</param>
public delegate Task OnionStreamHandler(Stream stream, string target, CancellationToken cancellationToken);
