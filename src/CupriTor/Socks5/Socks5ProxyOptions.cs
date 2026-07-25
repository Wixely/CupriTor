using System.Net;

namespace CupriTor;

/// <summary>Configuration for <see cref="Socks5ProxyServer"/>.</summary>
public sealed class Socks5ProxyOptions
{
    /// <summary>
    /// Address to listen on. Defaults to <c>127.0.0.1:9050</c> — Tor's conventional SOCKS port, loopback-only.
    /// Anyone who can reach the listener can use the tunnel, so keep it on loopback (or firewall it). Use port 0
    /// to bind an ephemeral port (read the actual one from <see cref="Socks5ProxyServer.ListenEndPoint"/>).
    /// </summary>
    public IPEndPoint Bind { get; set; } = new(IPAddress.Loopback, 9050);
}
