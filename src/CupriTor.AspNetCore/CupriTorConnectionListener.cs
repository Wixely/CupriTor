using System.Net;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

namespace CupriTor.AspNetCore;

/// <summary>
/// Publishes one onion service and surfaces each inbound Tor stream to Kestrel as a <see cref="ConnectionContext"/>.
/// Publishing runs in the background so binding the server (and any clearnet endpoints) never blocks on Tor
/// bootstrap — <see cref="AcceptAsync"/> simply yields nothing until the descriptor is live.
/// </summary>
internal sealed class CupriTorConnectionListener : IConnectionListener
{
    private readonly CupriTorEndPoint _endpoint;
    private readonly Func<CupriTorOnionOptions, CancellationToken, Task<TorClient>> _torClient;
    private readonly ILogger _log;
    private readonly Channel<ConnectionContext> _accepted =
        Channel.CreateUnbounded<ConnectionContext>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _cts = new();

    private OnionServiceHost? _host;
    private long _connectionCounter;

    public CupriTorConnectionListener(CupriTorEndPoint endpoint, Func<CupriTorOnionOptions, CancellationToken, Task<TorClient>> torClient, ILogger log)
    {
        _endpoint = endpoint;
        _torClient = torClient;
        _log = log;
    }

    public EndPoint EndPoint => _endpoint;

    /// <summary>Begin publishing in the background. Returns immediately.</summary>
    public void Start() => _ = PublishWithRetryAsync(_cts.Token);

    private async Task PublishWithRetryAsync(CancellationToken ct)
    {
        CupriTorOnionOptions opt = _endpoint.Options;
        List<byte[]>? authorized = opt.AuthorizedClients.Count > 0 ? new List<byte[]>(opt.AuthorizedClients) : null;
        int attempt = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                _log.LogInformation("CupriTor onion {Onion}: publishing ({IntroPoints} intro points{Private})…",
                    _endpoint.OnionAddress, opt.IntroPoints, authorized is null ? "" : $", private: {authorized.Count} authorized clients");
                TorClient tor = await _torClient(opt, ct).ConfigureAwait(false);
                _host = await tor.PublishOnionAsync(opt.Identity, EnqueueAsync, opt.IntroPoints, authorized, ct).ConfigureAwait(false);
                _log.LogInformation("CupriTor onion {Onion}: live", _endpoint.OnionAddress);
                return;
            }
            catch (OperationCanceledException) { return; }
            catch (Exception ex)
            {
                var delay = TimeSpan.FromSeconds(Math.Min(60, 5 * ++attempt));
                _log.LogWarning(ex, "CupriTor onion {Onion}: publish failed (attempt {Attempt}); retrying in {Delay}s",
                    _endpoint.OnionAddress, attempt, delay.TotalSeconds);
                try { await Task.Delay(delay, ct).ConfigureAwait(false); } catch { return; }
            }
        }
    }

    /// <summary>The onion accept handler: hand each inbound stream to Kestrel as a connection.</summary>
    private async Task EnqueueAsync(Stream stream, string target, CancellationToken ct)
    {
        string id = "onion-" + Interlocked.Increment(ref _connectionCounter).ToString("x");
        var conn = new CupriTorConnectionContext(id, stream, _endpoint);
        try { await _accepted.Writer.WriteAsync(conn, ct).ConfigureAwait(false); }
        catch { await conn.DisposeAsync().ConfigureAwait(false); } // shutting down → drop it cleanly
    }

    public async ValueTask<ConnectionContext?> AcceptAsync(CancellationToken cancellationToken = default)
    {
        try { return await _accepted.Reader.ReadAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { return null; }
        catch (ChannelClosedException) { return null; }
    }

    public async ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _cts.Cancel();
        _accepted.Writer.TryComplete();
        if (_host is not null) await _host.DisposeAsync().ConfigureAwait(false);
        _host = null;
    }

    public async ValueTask DisposeAsync()
    {
        await UnbindAsync().ConfigureAwait(false);
        _cts.Dispose();
        while (_accepted.Reader.TryRead(out ConnectionContext? conn)) // drain queued-but-unaccepted connections
            await conn.DisposeAsync().ConfigureAwait(false);
    }
}
