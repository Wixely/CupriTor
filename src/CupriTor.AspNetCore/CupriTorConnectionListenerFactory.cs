using System.Net;
using CupriTor.Directory;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;

namespace CupriTor.AspNetCore;

/// <summary>
/// The Kestrel transport that binds <see cref="CupriTorEndPoint"/> endpoints to onion services. It is registered
/// alongside the default socket transport; <see cref="CanBind"/> claims only onion endpoints, so IP endpoints keep
/// binding on sockets (clearnet + onion in one server). Owns a single shared <see cref="TorClient"/> across all
/// onion endpoints, started lazily on first bind.
/// </summary>
internal sealed class CupriTorConnectionListenerFactory : IConnectionListenerFactory, IConnectionListenerFactorySelector, IAsyncDisposable
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly SemaphoreSlim _torGate = new(1, 1);
    private TorClient? _tor;
    private int _disposed;

    public CupriTorConnectionListenerFactory(ILoggerFactory loggerFactory) => _loggerFactory = loggerFactory;

    public bool CanBind(EndPoint endpoint) => endpoint is CupriTorEndPoint;

    public ValueTask<IConnectionListener> BindAsync(EndPoint endpoint, CancellationToken cancellationToken = default)
    {
        if (endpoint is not CupriTorEndPoint onion)
            throw new NotSupportedException($"{nameof(CupriTorConnectionListenerFactory)} only binds {nameof(CupriTorEndPoint)}.");

        var listener = new CupriTorConnectionListener(onion, GetOrStartTorAsync, _loggerFactory.CreateLogger<CupriTorConnectionListener>());
        listener.Start();
        return ValueTask.FromResult<IConnectionListener>(listener);
    }

    private async Task<TorClient> GetOrStartTorAsync(CupriTorOnionOptions options, CancellationToken ct)
    {
        if (_tor is not null) return _tor;
        await _torGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_tor is null)
            {
                var opts = new TorClientOptions
                {
                    DirectorySource = options.DirectorySources.Count > 0
                        ? new HttpDirectorySource(options.DirectorySources.ToArray())
                        : new HttpDirectorySource(DefaultDirectorySources),
                };
                var tor = new TorClient(opts);
                await tor.StartAsync(ct).ConfigureAwait(false);
                _tor = tor;
            }
        }
        finally { _torGate.Release(); }
        return _tor;
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_tor is not null) await _tor.DisposeAsync().ConfigureAwait(false);
        _torGate.Dispose();
    }

    private static readonly string[] DefaultDirectorySources =
    {
        "128.31.0.39:9131", "86.59.21.38:80", "45.66.33.45:80", "131.188.40.189:80",
        "193.23.244.244:80", "171.25.193.9:443", "199.58.81.140:80", "204.13.164.118:80",
    };
}
