using System.Net;
using System.Net.Sockets;
using CupriTor;
using CupriTor.Directory;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CupriTor.Host;

/// <summary>
/// The sidecar reverse proxy. Depending on <see cref="OnionHostConfig.Mode"/> it opens a clearnet TCP
/// listener and/or publishes a Tor onion service, and proxies every accepted connection to the configured
/// backend app. Universal: the backend can be Kestrel, IIS, or anything that speaks over a local port.
/// </summary>
public sealed class OnionHostService : BackgroundService
{
    private readonly OnionHostConfig _config;
    private readonly ILogger<OnionHostService> _log;

    private TorClient? _tor;
    private OnionServiceHost? _onion;
    private TcpListener? _clearnet;

    public OnionHostService(OnionHostConfig config, ILogger<OnionHostService> log)
    {
        _config = config;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        (string backendHost, int backendPort) = _config.BackendEndpoint();
        _log.LogInformation("CupriTor host starting — mode {Mode}, backend {Host}:{Port}", _config.Mode, backendHost, backendPort);

        if (_config.Mode is BindingMode.ClearnetOnly or BindingMode.Both)
            StartClearnet(backendHost, backendPort, ct);

        if (_config.Mode is BindingMode.TorOnly or BindingMode.Both)
            await StartOnionAsync(backendHost, backendPort, ct).ConfigureAwait(false);

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
                _ = ProxyToBackendAsync(client.GetStream(), backendHost, backendPort, disposeClient: client, ct);
            }
        }, ct);
    }

    private async Task StartOnionAsync(string backendHost, int backendPort, CancellationToken ct)
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

        OnionServiceKey identity = Identity.Load(_config.Onion, _log);

        List<byte[]>? authorized = _config.Onion.AuthorizedClients.Count > 0
            ? _config.Onion.AuthorizedClients.Select(OnionClientAuthorization.ParsePublicKey).ToList()
            : null;
        if (authorized is not null)
            _log.LogInformation("Private onion: {Count} authorized client(s)", authorized.Count);

        // Every inbound onion stream is bridged to the backend app (the library's reverse-proxy helper).
        _log.LogInformation("Publishing onion service ({IntroPoints} intro points)…", _config.Onion.IntroPoints);
        _onion = await _tor.PublishOnionAsync(identity, backendHost, backendPort, _config.Onion.IntroPoints, authorized, ct).ConfigureAwait(false);
        _log.LogInformation("Onion front door live: http://{Onion}/ → backend {Host}:{Port}", _onion.OnionAddress, backendHost, backendPort);
    }

    private async Task ProxyToBackendAsync(Stream inbound, string backendHost, int backendPort, IDisposable disposeClient, CancellationToken ct)
    {
        using var _ = disposeClient;
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(backendHost, backendPort, ct).ConfigureAwait(false);
            Stream backend = tcp.GetStream();
            await Task.WhenAny(Copy(inbound, backend, ct), Copy(backend, inbound, ct)).ConfigureAwait(false);
        }
        catch { /* connection ended */ }
        finally { tcp.Dispose(); }
    }

    private static async Task Copy(Stream from, Stream to, CancellationToken ct)
    {
        var buffer = new byte[8192];
        int n;
        while ((n = await from.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            await to.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        _clearnet?.Stop();
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
