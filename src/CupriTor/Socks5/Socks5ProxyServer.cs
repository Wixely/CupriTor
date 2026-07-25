using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CupriTor;

/// <summary>
/// A minimal SOCKS5 (RFC 1928) proxy that tunnels TCP CONNECT requests over Tor via an <see cref="ITorDialer"/>.
/// Point any SOCKS5-aware app at it — <c>curl --socks5-hostname 127.0.0.1:9050</c>, a browser, an SSH
/// <c>ProxyCommand</c>, a bot framework — and its traffic rides CupriTor with no code changes.
/// <para>
/// Onion hostnames are dialed through the rendezvous protocol; clearnet destinations go through a Tor exit relay.
/// (A dialer that declines a destination with <see cref="NotSupportedException"/> is answered "network
/// unreachable".) NO-AUTH and CONNECT only; loopback-bound by default.
/// </para>
/// </summary>
public sealed class Socks5ProxyServer : IAsyncDisposable
{
    private const byte Version = 0x05;
    private const byte CmdConnect = 0x01;
    private const byte MethodNoAuth = 0x00;
    private const byte MethodNone = 0xFF;

    private readonly ITorDialer _dialer;
    private readonly Socks5ProxyOptions _options;
    private readonly Action<string>? _trace;
    private readonly CancellationTokenSource _cts = new();
    private TcpListener? _listener;
    private CancellationTokenSource? _linked;
    private Task? _acceptLoop;

    public Socks5ProxyServer(ITorDialer dialer, Socks5ProxyOptions? options = null, Action<string>? trace = null)
    {
        _dialer = dialer ?? throw new ArgumentNullException(nameof(dialer));
        _options = options ?? new Socks5ProxyOptions();
        _trace = trace;
    }

    /// <summary>The address the proxy is actually listening on (valid after <see cref="StartAsync"/>; reflects the real port when binding to port 0).</summary>
    public IPEndPoint ListenEndPoint { get; private set; } = new(IPAddress.None, 0);

    /// <summary>Bind the listener and begin accepting connections in the background. Returns once listening.</summary>
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_listener is not null) throw new InvalidOperationException("Already started.");
        _listener = new TcpListener(_options.Bind);
        _listener.Start();
        ListenEndPoint = (IPEndPoint)_listener.LocalEndpoint;
        _linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_linked.Token), CancellationToken.None);
        _trace?.Invoke($"SOCKS5 listening on {ListenEndPoint}");
        return Task.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener!.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException) { break; }
            _ = HandleClientAsync(client, ct);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            client.NoDelay = true;
            NetworkStream stream = client.GetStream();
            Stream? upstream = null;
            try
            {
                if (!await NegotiateAsync(stream, ct).ConfigureAwait(false)) return;

                (string host, int port, Socks5Reply parse) = await ReadRequestAsync(stream, ct).ConfigureAwait(false);
                if (parse != Socks5Reply.Succeeded)
                {
                    await ReplyAsync(stream, parse, ct).ConfigureAwait(false);
                    return;
                }

                try
                {
                    upstream = await _dialer.ConnectAsync(host, port, ct).ConfigureAwait(false);
                }
                catch (NotSupportedException)
                {
                    _trace?.Invoke($"dialer declined {host}:{port}");
                    await ReplyAsync(stream, Socks5Reply.NetworkUnreachable, ct).ConfigureAwait(false);
                    return;
                }
                catch (Exception e)
                {
                    _trace?.Invoke($"dial {host}:{port} failed: {e.Message}");
                    await ReplyAsync(stream, Socks5Reply.HostUnreachable, ct).ConfigureAwait(false);
                    return;
                }

                await ReplyAsync(stream, Socks5Reply.Succeeded, ct).ConfigureAwait(false);
                _trace?.Invoke($"tunnel established → {host}:{port}");
                await OnionReverseProxy.PumpAsync(stream, upstream, ct).ConfigureAwait(false);
            }
            catch (Exception) { /* client/link error mid-handshake — just drop the connection */ }
            finally
            {
                if (upstream is not null) await upstream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Method negotiation: accept NO-AUTH (0x00), otherwise reject with 0xFF.</summary>
    private static async Task<bool> NegotiateAsync(NetworkStream stream, CancellationToken ct)
    {
        var head = new byte[2];
        await stream.ReadExactlyAsync(head, ct).ConfigureAwait(false);
        if (head[0] != Version) return false;

        var methods = new byte[head[1]];
        await stream.ReadExactlyAsync(methods, ct).ConfigureAwait(false);

        bool noAuth = Array.IndexOf(methods, MethodNoAuth) >= 0;
        await stream.WriteAsync(new byte[] { Version, noAuth ? MethodNoAuth : MethodNone }, ct).ConfigureAwait(false);
        return noAuth;
    }

    /// <summary>Parse a CONNECT request; returns the target host:port, or a non-success reply code to send back.</summary>
    private static async Task<(string Host, int Port, Socks5Reply Result)> ReadRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        var head = new byte[4]; // VER, CMD, RSV, ATYP
        await stream.ReadExactlyAsync(head, ct).ConfigureAwait(false);
        if (head[0] != Version) return ("", 0, Socks5Reply.GeneralFailure);
        if (head[1] != CmdConnect) return ("", 0, Socks5Reply.CommandNotSupported);

        string host;
        switch (head[3])
        {
            case 0x01: // IPv4 literal (clearnet)
            {
                var addr = new byte[4];
                await stream.ReadExactlyAsync(addr, ct).ConfigureAwait(false);
                host = new IPAddress(addr).ToString();
                break;
            }
            case 0x03: // domain name (.onion, or a clearnet hostname)
            {
                var len = new byte[1];
                await stream.ReadExactlyAsync(len, ct).ConfigureAwait(false);
                var name = new byte[len[0]];
                await stream.ReadExactlyAsync(name, ct).ConfigureAwait(false);
                host = Encoding.ASCII.GetString(name);
                break;
            }
            case 0x04: // IPv6 literal (clearnet)
            {
                var addr = new byte[16];
                await stream.ReadExactlyAsync(addr, ct).ConfigureAwait(false);
                host = new IPAddress(addr).ToString();
                break;
            }
            default:
                return ("", 0, Socks5Reply.AddressTypeNotSupported);
        }

        var port = new byte[2];
        await stream.ReadExactlyAsync(port, ct).ConfigureAwait(false);
        return (host, BinaryPrimitives.ReadUInt16BigEndian(port), Socks5Reply.Succeeded);
    }

    private static Task ReplyAsync(NetworkStream stream, Socks5Reply reply, CancellationToken ct)
    {
        // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0 — clients ignore the bound address for CONNECT.
        byte[] response = { Version, (byte)reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        return stream.WriteAsync(response, ct).AsTask();
    }

    public async Task StopAsync()
    {
        _cts.Cancel();
        _listener?.Stop();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.ConfigureAwait(false); } catch { /* accept loop torn down */ }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _linked?.Dispose();
        _cts.Dispose();
    }

    private enum Socks5Reply : byte
    {
        Succeeded = 0x00,
        GeneralFailure = 0x01,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08,
    }
}
