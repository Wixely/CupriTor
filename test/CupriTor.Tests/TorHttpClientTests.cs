using System.Net;
using System.Net.Sockets;
using System.Text;
using CupriTor;
using Xunit;

namespace CupriTor.Tests;

public class TorHttpClientTests
{
    [Fact]
    public async Task Dialer_Rejects_Clearnet_Targets_Until_Exit_Support_Exists()
    {
        await using var client = new TorClient();
        // Onion-to-onion build: clearnet is refused up front (before any bootstrap is even needed).
        NotSupportedException ex = await Assert.ThrowsAsync<NotSupportedException>(
            () => client.ConnectAsync("example.com", 443));
        Assert.Contains("clearnet", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HttpClient_Makes_Requests_Over_The_Dialer()
    {
        // A loopback "service" that speaks one HTTP/1.1 response; a dialer that connects to it stands in for Tor.
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        Task serve = ServeOneAsync(listener, "hello over tor");

        var dialer = new LoopbackDialer(endpoint);
        using HttpClient http = dialer.CreateTorHttpClient();

        string body = await http.GetStringAsync("http://example.onion/path");

        Assert.Equal("hello over tor", body);
        Assert.Equal("example.onion", dialer.LastHost); // the URI's host+port were handed to the dialer, not resolved locally
        Assert.Equal(80, dialer.LastPort);
        await serve.WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task ServeOneAsync(TcpListener listener, string body)
    {
        using TcpClient conn = await listener.AcceptTcpClientAsync();
        await using NetworkStream s = conn.GetStream();
        var buf = new byte[4096];
        if (await s.ReadAsync(buf) == 0) return; // wait for (the start of) the request before replying
        byte[] resp = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n{body}");
        await s.WriteAsync(resp);
        await s.FlushAsync();
    }

    /// <summary>An <see cref="ITorDialer"/> that just dials a loopback endpoint — exercises the HttpClient wiring without Tor.</summary>
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
