using System.Net.Http;

namespace CupriTor;

/// <summary>
/// Turns an <see cref="ITorDialer"/> into a standard <see cref="HttpClient"/> / <see cref="SocketsHttpHandler"/>
/// whose connections are made over Tor. Everything HttpClient does — redirects, decompression, cookies, HTTP/1.1,
/// connection pooling, and TLS for <c>https</c> targets — works unchanged; only the transport is a Tor stream
/// instead of a socket. This is the native, in-app way to reach the Tor network from C#.
/// </summary>
public static class TorHttpClientExtensions
{
    /// <summary>
    /// Create a <see cref="SocketsHttpHandler"/> that opens every connection through <paramref name="dialer"/>.
    /// For an <c>https</c> URI the handler runs the TLS handshake over the Tor stream (end-to-end TLS to the
    /// service, on top of Tor's own encryption). The request URI's host and port select the destination — e.g.
    /// <c>GET http://xxxxx.onion/</c> dials <c>xxxxx.onion:80</c>.
    /// </summary>
    public static SocketsHttpHandler CreateTorHttpHandler(this ITorDialer dialer)
    {
        ArgumentNullException.ThrowIfNull(dialer);
        return new SocketsHttpHandler
        {
            UseProxy = false,
            ConnectCallback = async (context, cancellationToken) =>
                await dialer.ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false),
        };
    }

    /// <summary>
    /// Create an <see cref="HttpClient"/> that routes every request over Tor (see <see cref="CreateTorHttpHandler"/>).
    /// The client owns and disposes the handler.
    /// </summary>
    public static HttpClient CreateTorHttpClient(this ITorDialer dialer) =>
        new(CreateTorHttpHandler(dialer), disposeHandler: true);
}
