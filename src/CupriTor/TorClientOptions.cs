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

    /// <summary>
    /// Persistence for the client's anonymity-critical state. Two opaque byte blobs are written: the entry-guard set
    /// and the layer-2 vanguard set (see <see cref="Vanguards"/>). Both MUST survive restarts — losing them
    /// reselects guards/vanguards on every run, which is a deanonymization risk. Defaults to in-memory
    /// (non-persistent); supply a durable store (<c>FileStateStore</c>, or your own encrypted implementation) for
    /// production. A custom store only needs to persist opaque key→bytes pairs.
    /// </summary>
    public IStateStore StateStore { get; set; } = new InMemoryStateStore();

    /// <summary>
    /// Source of the initial directory documents (consensus, authority keys, microdescriptors). Optional — when
    /// left null, <see cref="TorClient.StartAsync"/> uses <see cref="HttpDirectorySource.CreateDefault"/> (the
    /// built-in directory authorities), so <c>new TorClient()</c> works out of the box. Set it to bootstrap from
    /// your own directory caches.
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

    /// <summary>
    /// When true, only <c>.onion</c> destinations may be dialed; any clearnet/exit dial — a non-onion host, or a
    /// malformed address that isn't recognised as onion — throws <see cref="ClearnetBlockedException"/> instead of
    /// routing through a Tor exit. Set this for an onion-only transport so a bad address can never silently leave Tor
    /// via an exit + remote DNS. Applies to <see cref="TorClient.ConnectAsync"/>/<c>ConnectViaExitAsync</c>, and thus
    /// to the SOCKS5 server and HttpClient integration that dial through them. Default false.
    /// </summary>
    public bool OnionOnly { get; set; }

    /// <summary>
    /// When true, <see cref="TorClient.StartAsync"/> refuses to start with the in-memory default
    /// <see cref="StateStore"/>, which loses entry guards on restart (an anonymity risk). Set this in a long-running
    /// node so ephemeral guards can't ship by accident, and pair it with a persistent store (e.g. <c>FileStateStore</c>).
    /// Default false — a one-time warning is emitted via <see cref="TorClient.StatusChanged"/> instead.
    /// </summary>
    public bool RequirePersistentState { get; set; }

    /// <summary>
    /// Whether to use layer-2 vanguards (guard-spec "vanguards-lite") on onion-service circuits — a small, stable,
    /// slowly-rotating second-hop set that defends against guard-discovery attacks, at the cost of one extra hop per
    /// onion circuit. Defaults to <see cref="VanguardMode.All"/> (client + service, matching Tor). Persisted in the
    /// <see cref="StateStore"/> like the entry guards, so pair it with a persistent store to be effective across restarts.
    /// </summary>
    public VanguardMode Vanguards { get; set; } = VanguardMode.All;

    /// <summary>
    /// How far the local clock may be outside a fetched consensus's validity window and still be accepted. Tor is
    /// time-sensitive; a wrong device clock (common on mobile/embedded/fresh installs) otherwise fails bootstrap.
    /// When the clock is off by more than this, <see cref="TorClient.StartAsync"/> throws a
    /// <see cref="TorClockSkewException"/> (reporting the local and consensus times) instead of an opaque
    /// verification error. Default <see cref="TimeSpan.Zero"/> — strict (accept only within the window) but with the
    /// clear error; raise it (e.g. a couple of hours) to tolerate skew, at the cost of trusting a slightly stale consensus.
    /// </summary>
    public TimeSpan ClockSkewTolerance { get; set; } = TimeSpan.Zero;

    /// <summary>
    /// When true, <see cref="TorClient.StartAsync"/> retries bootstrap with capped exponential backoff (emitting
    /// <see cref="TorPhase.Reconnecting"/>) until it succeeds or the token is cancelled — for daemon-style consumers
    /// that should come up whenever connectivity arrives. Default false: bootstrap fails fast (throws) so errors are
    /// surfaced. Either way, <c>StartAsync</c> is safe to call again after a failure (it is idempotent).
    /// </summary>
    public bool RetryBootstrap { get; set; }
}

/// <summary>Scope of layer-2 vanguard use — see <see cref="TorClientOptions.Vanguards"/>.</summary>
public enum VanguardMode
{
    /// <summary>No vanguards; onion circuits use a random middle (3 hops).</summary>
    Off,
    /// <summary>Vanguards on onion-service (hosting) circuits only; client onion dials stay 3-hop.</summary>
    OnionServiceOnly,
    /// <summary>Vanguards on both client and service onion circuits (Tor's default).</summary>
    All,
}
