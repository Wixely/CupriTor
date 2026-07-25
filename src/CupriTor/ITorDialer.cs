namespace CupriTor;

/// <summary>
/// Dials application streams over Tor. This is the single seam the SOCKS5 server and the HttpClient integration
/// build on, so anything layered on a dialer keeps working unchanged as new destination types (for example
/// clearnet via exit relays) are enabled behind it. <see cref="TorClient"/> is the standard implementation.
/// </summary>
public interface ITorDialer
{
    /// <summary>
    /// Open a duplex <see cref="Stream"/> to <paramref name="host"/>:<paramref name="port"/> over Tor. Disposing
    /// the returned stream tears down the underlying circuit.
    /// </summary>
    Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default);
}
