using CupriTor.Directory;
using CupriTor.Protocol;
using CupriTor.Transport;

namespace CupriTor;

/// <summary>Configuration for a <see cref="TorClient"/>.</summary>
public sealed class TorClientOptions
{
    /// <summary>
    /// TLS transport used for OR connections. Defaults to the 100%-managed BouncyCastle transport; swap in
    /// <see cref="SslStreamTlsTransport"/> for the OS-backed A/B baseline.
    /// </summary>
    public ITlsTransport Transport { get; set; } = new BouncyCastleTlsTransport();

    /// <summary>Persistence for entry guards and other client state. Defaults to in-memory (non-persistent).</summary>
    public IStateStore StateStore { get; set; } = new InMemoryStateStore();

    /// <summary>
    /// Source of the initial directory documents (consensus, authority keys, microdescriptors). Required
    /// before <see cref="TorClient.StartAsync"/>. Use <see cref="HttpDirectorySource"/> to bootstrap from
    /// directory caches.
    /// </summary>
    public IDirectorySource? DirectorySource { get; set; }

    /// <summary>Per-operation timeout for connects, handshakes, and fetches.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Target number of entry guards to maintain.</summary>
    public int GuardCount { get; set; } = 3;

    /// <summary>Default number of hops for circuits built without an explicit length.</summary>
    public int DefaultCircuitLength { get; set; } = 3;

    /// <summary>
    /// Keep the consensus fresh in the background (re-fetch + re-verify before it expires). Required for any
    /// long-running client or onion service — the consensus is only valid for a few hours. Defaults to true.
    /// </summary>
    public bool AutoRefreshConsensus { get; set; } = true;
}
