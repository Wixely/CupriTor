using System.Net;
using System.Net.Sockets;
using System.Text;
using CupriTor;
using Xunit;

namespace CupriTor.Tests;

public class Socks5ProxyServerTests
{
    [Fact]
    public async Task Connect_By_Domain_Tunnels_Bytes_End_To_End()
    {
        // Backend "onion service": a loopback listener that speaks one HTTP response.
        using var backend = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();
        Task serve = ServeOneAsync(backend, "hi via socks");

        var dialer = new LoopbackDialer((IPEndPoint)backend.LocalEndpoint);
        await using var proxy = new Socks5ProxyServer(dialer, new Socks5ProxyOptions { Bind = new IPEndPoint(IPAddress.Loopback, 0) });
        await proxy.StartAsync();

        using var socks = new TcpClient();
        await socks.ConnectAsync(proxy.ListenEndPoint);
        NetworkStream s = socks.GetStream();

        // Greeting → expect NO-AUTH selected.
        await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var method = new byte[2];
        await s.ReadExactlyAsync(method);
        Assert.Equal(new byte[] { 0x05, 0x00 }, method);

        // CONNECT example.onion:80 (ATYP = domain).
        byte[] name = Encoding.ASCII.GetBytes("example.onion");
        var request = new List<byte> { 0x05, 0x01, 0x00, 0x03, (byte)name.Length };
        request.AddRange(name);
        request.AddRange(new byte[] { 0x00, 80 }); // port 80, big-endian
        await s.WriteAsync(request.ToArray());

        var reply = new byte[10];
        await s.ReadExactlyAsync(reply);
        Assert.Equal(0x05, reply[0]);
        Assert.Equal(0x00, reply[1]); // succeeded

        // Speak HTTP over the tunnel.
        await s.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"));
        string response = await ReadAllAsync(s);

        Assert.Contains("hi via socks", response);
        Assert.Equal("example.onion", dialer.LastHost); // the domain was passed through, not resolved locally
        Assert.Equal(80, dialer.LastPort);
        await serve.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Clearnet_Target_Is_Refused_With_Network_Unreachable()
    {
        // A real TorClient refuses clearnet up front (no bootstrap needed for the refusal).
        await using var tor = new TorClient();
        await using var proxy = new Socks5ProxyServer(tor, new Socks5ProxyOptions { Bind = new IPEndPoint(IPAddress.Loopback, 0) });
        await proxy.StartAsync();

        using var socks = new TcpClient();
        await socks.ConnectAsync(proxy.ListenEndPoint);
        NetworkStream s = socks.GetStream();

        await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00 });
        var method = new byte[2];
        await s.ReadExactlyAsync(method);

        // CONNECT 93.184.216.34:80 (IPv4 literal → clearnet).
        await s.WriteAsync(new byte[] { 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 80 });
        var reply = new byte[10];
        await s.ReadExactlyAsync(reply);

        Assert.Equal(0x05, reply[0]);
        Assert.Equal(0x03, reply[1]); // network unreachable — clearnet/exit not enabled in this build
    }

    private static async Task ServeOneAsync(TcpListener listener, string body)
    {
        using TcpClient conn = await listener.AcceptTcpClientAsync();
        await using NetworkStream s = conn.GetStream();
        var buf = new byte[4096];
        if (await s.ReadAsync(buf) == 0) return;
        byte[] resp = Encoding.ASCII.GetBytes($"HTTP/1.0 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
        await s.WriteAsync(resp);
        await s.FlushAsync();
    }

    private static async Task<string> ReadAllAsync(Stream s)
    {
        using var ms = new MemoryStream();
        var buf = new byte[1024];
        int n;
        while ((n = await s.ReadAsync(buf)) > 0) ms.Write(buf, 0, n);
        return Encoding.ASCII.GetString(ms.ToArray());
    }

    /// <summary>An <see cref="ITorDialer"/> that dials a loopback endpoint — stands in for Tor in the tunnel test.</summary>
    private sealed class LoopbackDialer(IPEndPoint endpoint) : ITorDialer
    {
        public string LastHost { get; private set; } = "";
        public int LastPort { get; private set; }

        public async Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
        {
            LastHost = host;
            LastPort = port;
            var client = new TcpClient();
            await client.ConnectAsync(endpoint, cancellationToken);
            return client.GetStream();
        }
    }
}
