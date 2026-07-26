using System.Net;
using System.Net.Sockets;
using CupriTor;
using CupriTor.Directory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CupriTor.Host;

/// <summary>
/// The sidecar. Depending on <see cref="OnionHostConfig.Mode"/> it opens a clearnet TCP listener and/or
/// publishes a Tor onion service, proxying every accepted connection to the configured backend app (Kestrel,
/// IIS, or anything on a local port). Independently, it can run an outbound SOCKS5 proxy so any app can reach
/// Tor. All Tor-facing features share one bootstrapped <see cref="TorClient"/>.
/// </summary>
public sealed class OnionHostService : BackgroundService
{
    private readonly OnionHostConfig _config;
    private readonly ILogger<OnionHostService> _log;

    private TorClient? _tor;
    private OnionServiceHost? _onion;
    private TcpListener? _clearnet;
    private readonly SemaphoreSlim _clearnetSlots = new(512); // cap concurrent clearnet front-door connections
    private Socks5ProxyServer? _socks;

    public OnionHostService(OnionHostConfig config, ILogger<OnionHostService> log)
    {
        _config = config;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        (string backendHost, int backendPort) = _config.BackendEndpoint();
        _log.LogInformation("CupriTor host starting — mode {Mode}, backend {Host}:{Port}, socks5 {Socks}",
            _config.Mode, backendHost, backendPort, _config.Socks5.Enabled ? _config.Socks5.Bind : "off");

        // One shared, verified Tor client for every Tor-facing feature (onion publish and/or SOCKS5).
        if (_config.NeedsTor)
        {
            var options = new TorClientOptions
            {
                DirectorySource = _config.DirectorySources.Count > 0
                    ? new HttpDirectorySource(_config.DirectorySources)
                    : new HttpDirectorySource(DefaultDirectorySources),
            };
            _tor = new TorClient(options);
            _log.LogInformation("Bootstrapping Tor (verifying consensus)…");
            await _tor.StartAsync(ct).ConfigureAwait(false);
        }

        if (_config.Mode is BindingMode.ClearnetOnly or BindingMode.Both)
            StartClearnet(backendHost, backendPort, ct);

        if (_config.Mode is BindingMode.TorOnly or BindingMode.Both)
            await StartOnionAsync(backendHost, backendPort, ct).ConfigureAwait(false);

        if (_config.Socks5.Enabled)
            await StartSocks5Async(ct).ConfigureAwait(false);

        try { await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private void StartClearnet(string backendHost, int backendPort, CancellationToken ct)
    {
        (string bindHost, int bindPort) = _config.ClearnetEndpoint();
        IPAddress addr = bindHost is "0.0.0.0" or "*" ? IPAddress.Any : IPAddress.Parse(bindHost);
        _clearnet = new TcpListener(addr, bindPort);
        _clearnet.Start();
        _log.LogInformation("Clearnet front door listening on {Bind} → backend", $"{bindHost}:{bindPort}");

        _ = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _clearnet.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                if (!_clearnetSlots.Wait(0)) { client.Dispose(); continue; } // at capacity — drop the new connection
                _ = ProxyToBackendAsync(client.GetStream(), backendHost, backendPort, disposeClient: client, ct);
            }
        }, ct);
    }

    private async Task StartOnionAsync(string backendHost, int backendPort, CancellationToken ct)
    {
        OnionServiceKey identity = Identity.Load(_config.Onion, _log);

        List<byte[]>? authorized = _config.Onion.AuthorizedClients.Count > 0
            ? _config.Onion.AuthorizedClients.Select(OnionClientAuthorization.ParsePublicKey).ToList()
            : null;
        if (authorized is not null)
            _log.LogInformation("Private onion: {Count} authorized client(s)", authorized.Count);

        // Every inbound onion stream is bridged to the backend app (the library's reverse-proxy helper).
        _log.LogInformation("Publishing onion service ({IntroPoints} intro points)…", _config.Onion.IntroPoints);
        _onion = await _tor!.PublishOnionAsync(identity, backendHost, backendPort, _config.Onion.IntroPoints, authorized, ct).ConfigureAwait(false);
        _log.LogInformation("Onion front door live: http://{Onion}/ → backend {Host}:{Port}", _onion.OnionAddress, backendHost, backendPort);
    }

    private async Task StartSocks5Async(CancellationToken ct)
    {
        (string host, int port) = _config.Socks5Endpoint();
        IPAddress addr = host is "0.0.0.0" or "*" ? IPAddress.Any : IPAddress.Parse(host);
        if (!IPAddress.IsLoopback(addr))
            _log.LogWarning("SOCKS5 proxy bound to NON-LOOPBACK {Bind} — this is an OPEN, UNAUTHENTICATED Tor proxy that anyone who can reach it can use. Bind to 127.0.0.1 unless you truly intend this.", $"{host}:{port}");

        _socks = new Socks5ProxyServer(_tor!, new Socks5ProxyOptions { Bind = new IPEndPoint(addr, port) },
            msg => _log.LogDebug("[socks5] {Message}", msg));
        await _socks.StartAsync(ct).ConfigureAwait(false);
        _log.LogInformation("SOCKS5 proxy listening on {Bind} → Tor (onion + clearnet via exit)", $"{host}:{port}");
    }

    private async Task ProxyToBackendAsync(Stream inbound, string backendHost, int backendPort, IDisposable disposeClient, CancellationToken ct)
    {
        using var _ = disposeClient;
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(backendHost, backendPort, ct).ConfigureAwait(false);
            await OnionReverseProxy.PumpAsync(inbound, tcp.GetStream(), ct).ConfigureAwait(false);
        }
        catch { /* connection ended */ }
        finally { tcp.Dispose(); _clearnetSlots.Release(); }
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        _clearnet?.Stop();
        if (_socks is not null) await _socks.DisposeAsync().ConfigureAwait(false);
        if (_onion is not null) await _onion.DisposeAsync().ConfigureAwait(false);
        if (_tor is not null) await _tor.DisposeAsync().ConfigureAwait(false);
        await base.StopAsync(ct).ConfigureAwait(false);
    }

    private static readonly string[] DefaultDirectorySources =
    {
        "128.31.0.39:9131", "86.59.21.38:80", "45.66.33.45:80", "131.188.40.189:80",
        "193.23.244.244:80", "171.25.193.9:443", "199.58.81.140:80", "204.13.164.118:80",
    };
}
