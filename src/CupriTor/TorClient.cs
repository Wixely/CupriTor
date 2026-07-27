using CupriTor.Directory;
using CupriTor.OnionService;
using CupriTor.Protocol;

namespace CupriTor;

/// <summary>Public summary of a fetched onion-service descriptor (details needed to connect are kept internal).</summary>
public sealed record OnionDescriptorInfo(int IntroductionPointCount, long RevisionCounter);

/// <summary>Raised when the client cannot bootstrap (fetch or verify a consensus).</summary>
public class TorBootstrapException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// A <see cref="TorBootstrapException"/> raised specifically when the local clock is too far outside the fetched
/// consensus's validity window to trust it — the signatures verify, but the time doesn't. This distinguishes a wrong
/// device clock (common on mobile/embedded/fresh installs) from a genuine signature failure. See
/// <see cref="TorClientOptions.ClockSkewTolerance"/> to allow modest skew.
/// </summary>
public sealed class TorClockSkewException(DateTimeOffset localTime, DateTimeOffset consensusValidAfter, DateTimeOffset consensusValidUntil)
    : TorBootstrapException(
        $"The system clock appears to be wrong: local time {localTime:u} is outside the fetched consensus's validity " +
        $"window [{consensusValidAfter:u} .. {consensusValidUntil:u}]. Tor needs an approximately-correct clock — fix the " +
        $"device clock, or raise TorClientOptions.ClockSkewTolerance to accept the skew.")
{
    /// <summary>The local system time used for verification.</summary>
    public DateTimeOffset LocalTime { get; } = localTime;
    /// <summary>The fetched consensus's valid-after time.</summary>
    public DateTimeOffset ConsensusValidAfter { get; } = consensusValidAfter;
    /// <summary>The fetched consensus's valid-until time.</summary>
    public DateTimeOffset ConsensusValidUntil { get; } = consensusValidUntil;
}

/// <summary>
/// Thrown when a clearnet/exit destination is dialed on a client configured
/// <see cref="TorClientOptions.OnionOnly"/> — so an onion-only transport can never silently leave Tor via an exit.
/// </summary>
public sealed class ClearnetBlockedException(string host)
    : InvalidOperationException($"Clearnet destination '{host}' is blocked: this TorClient is configured OnionOnly.")
{
    /// <summary>The clearnet host that was refused.</summary>
    public string Host { get; } = host;
}

/// <summary>
/// The entry point to CupriTor: bootstraps a verified view of the Tor network from a directory source,
/// maintains entry guards, and builds circuits. Onion-service connect/publish build on top of this.
///
/// Bootstrap fetches the microdescriptor consensus and the directory-authority key certificates, then
/// verifies the consensus is signed by a majority of the hard-coded authorities before trusting it — so a
/// malicious directory cache cannot forge the network view. Circuits then run fully managed crypto end to end.
/// </summary>
public sealed class TorClient : IAsyncDisposable, ITorDialer
{
    private readonly TorClientOptions _options;
    private readonly IRandomSource _random = SecureRandomSource.Instance;
    private readonly CancellationTokenSource _shutdown = new();
    private TorNetwork? _network;
    private Task? _refreshLoop;
    private IDirectorySource? _directorySource; // resolved at StartAsync (options' source, or the built-in default)
    private int _disposed;

    public TorClient(TorClientOptions? options = null)
    {
        _options = options ?? new TorClientOptions();
    }

    // Vanguard scope: service circuits use them under OnionServiceOnly or All; client circuits only under All.
    private bool VanguardsForService => _options.Vanguards is VanguardMode.OnionServiceOnly or VanguardMode.All;
    private bool VanguardsForClient => _options.Vanguards is VanguardMode.All;

    /// <summary>The current verified network view, once bootstrapped (for advanced/service use).</summary>
    internal TorNetwork? Network => _network;

    /// <summary>True once a verified consensus has been loaded and guards are primed.</summary>
    public bool IsBootstrapped => _network is not null;

    /// <summary>The most recent status update (see <see cref="StatusChanged"/>).</summary>
    public TorStatus CurrentStatus { get; private set; } = new(TorPhase.Idle, "Idle", 0);

    /// <summary>
    /// Raised on every phase change during bootstrap and connection — subscribe to drive a progress UI / loading bar.
    /// Handlers should be quick and not throw (exceptions are swallowed so a bad handler can't disrupt Tor operations).
    /// </summary>
    public event EventHandler<TorStatus>? StatusChanged;

    private void Report(TorPhase phase, string message, double progress)
    {
        var status = new TorStatus(phase, message, progress);
        CurrentStatus = status;
        try { StatusChanged?.Invoke(this, status); } catch { /* a faulty handler must not break Tor operations */ }
    }

    /// <summary>
    /// Bootstrap: fetch and verify the consensus, then prime the entry-guard set. Must be called before
    /// building circuits. Requires <see cref="TorClientOptions.DirectorySource"/> to be set.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_network is not null) return; // idempotent: already bootstrapped, and safe to re-call after a prior failure

        // Entry guards must persist across restarts for anonymity; the in-memory default silently loses them.
        if (_options.StateStore is InMemoryStateStore)
        {
            if (_options.RequirePersistentState)
                throw new InvalidOperationException(
                    "RequirePersistentState is set but StateStore is the in-memory default, which loses entry guards on " +
                    "restart (an anonymity risk). Supply a persistent IStateStore (e.g. new FileStateStore(path)).");
            Report(TorPhase.Idle,
                "Warning: entry guards are stored in memory and reset on restart — supply a persistent IStateStore " +
                "(e.g. FileStateStore) for stable guards.", 0.0);
        }

        // No directory source configured? Fall back to the built-in authorities so `new TorClient()` just works.
        IDirectorySource dir = _directorySource = _options.DirectorySource ?? HttpDirectorySource.CreateDefault(_options.Timeout);

        if (!_options.RetryBootstrap)
        {
            await BootstrapAsync(dir, ct).ConfigureAwait(false); // fail-fast (default): throws on failure
            return;
        }

        // Opt-in daemon mode: retry with capped exponential backoff until we bootstrap or the token is cancelled.
        for (int attempt = 0; ; attempt++)
        {
            try { await BootstrapAsync(dir, ct).ConfigureAwait(false); return; }
            catch (OperationCanceledException) { throw; }
            catch (Exception e)
            {
                var wait = TimeSpan.FromSeconds(Math.Min(300, 5 * Math.Pow(2, Math.Min(attempt, 6))));
                Report(TorPhase.Reconnecting, $"Bootstrap failed ({e.Message}); retrying in {wait.TotalSeconds:F0}s…", 0.0);
                await Task.Delay(wait, ct).ConfigureAwait(false);
            }
        }
    }

    // One bootstrap attempt: fetch + verify the consensus, prime guards/vanguards, warm the cache, swap to the
    // over-circuit directory source, and start the refresh loop. Reports Failed and rethrows if it can't complete.
    private async Task BootstrapAsync(IDirectorySource dir, CancellationToken ct)
    {
        try
        {
            Consensus consensus = await FetchVerifiedConsensusAsync(dir, DateTimeOffset.UtcNow, reportProgress: true, ct).ConfigureAwait(false);
            Report(TorPhase.LoadingGuards, "Priming entry guards…", 0.85);
            var guards = new EntryGuardManager(_options.StateStore, _random, _options.GuardCount);
            VanguardManager? vanguards = _options.Vanguards != VanguardMode.Off
                ? new VanguardManager(_options.StateStore, _random)
                : null;
            var network = new TorNetwork(consensus, guards, dir, _options.Transport, _random, _options.Timeout, vanguards);
            _network = network;

            // Download every relay's microdescriptor now (over the clearnet bootstrap source) so later circuit builds
            // hit the cache instead of fetching per-hop descriptors over the directory channel — which is what leaks
            // each circuit's relay selection to an on-path observer. Best-effort: misses fall back to lazy per-build fetch.
            Report(TorPhase.LoadingGuards, "Fetching relay descriptors…", 0.9);
            try { await network.WarmMicrodescriptorCacheAsync(dir, ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { /* best-effort warm */ }

            // From now on, fetch directory documents over Tor circuits (BEGIN_DIR), so consensus refreshes stop
            // signalling "Tor user" to an on-path observer. Build-time microdescriptor resolution stays cache-first.
            _directorySource = new CircuitDirectorySource(network, dir);

            if (_options.AutoRefreshConsensus)
                _refreshLoop ??= Task.Run(() => RefreshConsensusLoopAsync(_shutdown.Token));

            Report(TorPhase.Bootstrapped, "Connected to the Tor network.", 1.0);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            Report(TorPhase.Failed, $"Bootstrap failed: {e.Message}", CurrentStatus.Progress);
            throw;
        }
    }

    /// <summary>Fetch the microdescriptor consensus and authority keys, and verify the consensus against the hard-coded authorities.</summary>
    private async Task<Consensus> FetchVerifiedConsensusAsync(IDirectorySource dir, DateTimeOffset now, bool reportProgress, CancellationToken ct)
    {
        if (reportProgress) Report(TorPhase.FetchingConsensus, "Fetching the network consensus…", 0.15);
        string consensusText, keysText;
        try
        {
            consensusText = await dir.FetchConsensusAsync(ct).ConfigureAwait(false);
            keysText = await dir.FetchAuthorityKeysAsync(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new TorBootstrapException("Failed to fetch directory documents.", e);
        }

        if (reportProgress) Report(TorPhase.VerifyingConsensus, "Verifying authority signatures…", 0.6);
        if (!Consensus.TryParse(consensusText, out Consensus? consensus) || consensus is null)
            throw new TorBootstrapException("Could not parse the consensus.");

        var certs = new List<AuthorityKeyCertificate>();
        foreach (string block in SplitCertificates(keysText))
            if (AuthorityKeyCertificate.TryParse(block, out AuthorityKeyCertificate cert))
                certs.Add(cert);

        if (!ConsensusVerifier.Verify(consensus, certs, DirectoryAuthorities.DefaultFingerprints, now, out int validSignatures))
        {
            // Distinguish a genuine signature failure from a local clock outside the consensus's validity window:
            // re-verify as of the consensus's own valid-after (when the authorities signed it). If the signatures are
            // sound then, only the clock is wrong — report that clearly, honouring ClockSkewTolerance.
            if (ConsensusVerifier.Verify(consensus, certs, DirectoryAuthorities.DefaultFingerprints, consensus.ValidAfter, out _))
            {
                TimeSpan tol = _options.ClockSkewTolerance;
                if (now < consensus.ValidAfter - tol || now >= consensus.ValidUntil + tol)
                    throw new TorClockSkewException(now, consensus.ValidAfter, consensus.ValidUntil);
                // else: skew is within the configured tolerance — accept this consensus.
            }
            else
            {
                throw new TorBootstrapException($"Consensus signature verification failed ({validSignatures} valid signatures).");
            }
        }

        return consensus;
    }

    /// <summary>
    /// Keep the consensus fresh for a long-running client/service: re-fetch + re-verify shortly before the
    /// current one expires (the consensus is only valid ~3h), and swap it in atomically. Retries with backoff.
    /// </summary>
    private async Task RefreshConsensusLoopAsync(CancellationToken ct)
    {
        bool degraded = false; // whether a Reconnecting episode was reported (so we only signal on transitions)
        while (!ct.IsCancellationRequested)
        {
            TorNetwork? network = _network;
            DateTimeOffset validUntil = network?.Consensus.ValidUntil ?? DateTimeOffset.UtcNow.AddHours(1);
            // Refresh in the last quarter of the validity window (with a floor/ceiling), matching tor's cadence.
            DateTimeOffset now = DateTimeOffset.UtcNow;
            TimeSpan wait = validUntil - now - TimeSpan.FromMinutes(45);
            if (wait < TimeSpan.FromMinutes(5)) wait = TimeSpan.FromMinutes(5);
            if (wait > TimeSpan.FromHours(2)) wait = TimeSpan.FromHours(2);
            if (degraded && wait > TimeSpan.FromSeconds(60)) wait = TimeSpan.FromSeconds(60); // poll faster while reconnecting

            try { await Task.Delay(wait, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            for (int attempt = 0; attempt < 5 && !ct.IsCancellationRequested; attempt++)
            {
                try
                {
                    Consensus fresh = await FetchVerifiedConsensusAsync(_directorySource!, DateTimeOffset.UtcNow, reportProgress: false, ct).ConfigureAwait(false);
                    _network?.UpdateConsensus(fresh);
                    // Re-warm the microdescriptor cache for the new consensus over a circuit (private), so builds keep
                    // hitting the cache and newly-listed relays aren't fetched over clearnet on first use.
                    if (_network is not null)
                        try { await _network.WarmMicrodescriptorCacheAsync(_directorySource!, ct).ConfigureAwait(false); }
                        catch (Exception e) when (e is not OperationCanceledException) { /* best-effort re-warm */ }
                    if (degraded) { degraded = false; Report(TorPhase.Bootstrapped, "Reconnected to the Tor network.", 1.0); }
                    break;
                }
                catch (OperationCanceledException) { return; }
                catch (Exception e)
                {
                    if (!degraded) { degraded = true; Report(TorPhase.Reconnecting, $"Lost connectivity to the Tor network; reconnecting… ({e.Message})", CurrentStatus.Progress); }
                    try { await Task.Delay(TimeSpan.FromMinutes(2 * (attempt + 1)), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { return; }
                }
            }
        }
    }

    /// <summary>Build a circuit of the given length (defaults to <see cref="TorClientOptions.DefaultCircuitLength"/>).</summary>
    public async Task<TorCircuit> BuildCircuitAsync(int? length = null, CancellationToken ct = default)
    {
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before building circuits.");
        int hops = length ?? _options.DefaultCircuitLength;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout);

        (OrConnection conn, Circuit circuit) = await network.BuildCircuitAsync(hops, DateTimeOffset.UtcNow, timeout.Token).ConfigureAwait(false);
        return new TorCircuit(conn, circuit);
    }

    /// <summary>
    /// Look up a v3 onion service: derive its blinded key, fetch the descriptor from a responsible HSDir
    /// over a circuit, verify it, and decrypt it to the introduction points. Returns a summary; this is the
    /// descriptor stage of connecting to an onion (the introduce/rendezvous stage builds on it).
    /// </summary>
    public async Task<OnionDescriptorInfo> LookupOnionAsync(string onion, CancellationToken ct = default)
    {
        if (!OnionAddress.TryParse(onion, out OnionAddress address))
            throw new InvalidOnionAddressException(onion);
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before onion lookups.");

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout);

        var client = new HsDescriptorClient(network, useVanguards: VanguardsForClient);
        OnionDescriptorResult result = await client.FetchAsync(address, timeout.Token).ConfigureAwait(false);
        return new OnionDescriptorInfo(result.IntroductionPoints.Count, result.RevisionCounter);
    }

    /// <summary>
    /// Connect to a v3 onion service and return a duplex <see cref="Stream"/> to the given virtual port:
    /// fetch the descriptor, establish a rendezvous point, INTRODUCE1 to an introduction point, complete
    /// the hs-ntor rendezvous, and open an application stream. Disposing the stream tears down the circuit.
    /// </summary>
    public Task<Stream> ConnectToOnionAsync(string onion, int port, CancellationToken ct = default) =>
        ConnectToOnionAsync(onion, port, _options.Timeout, ct);

    /// <summary>
    /// As <see cref="ConnectToOnionAsync(string,int,CancellationToken)"/>, but with an explicit per-call
    /// <paramref name="timeout"/> that overrides <see cref="TorClientOptions.Timeout"/> — convenient for a racing
    /// dialer that abandons slow dials. Throws <see cref="InvalidOnionAddressException"/> on a malformed address.
    /// </summary>
    public async Task<Stream> ConnectToOnionAsync(string onion, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        // Validate the (possibly untrusted) address first, so a malformed one is rejected regardless of client state.
        if (!OnionAddress.TryParse(onion, out OnionAddress address))
            throw new InvalidOnionAddressException(onion);
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before connecting.");

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        Report(TorPhase.BuildingCircuit, $"Connecting to onion service {onion}…", 0.3);
        var connector = new OnionConnector(network, useVanguards: VanguardsForClient);
        Stream stream = await connector.ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
        Report(TorPhase.Connected, $"Connected to {onion}.", 1.0);
        return stream;
    }

    /// <summary>
    /// Dial <paramref name="host"/>:<paramref name="port"/> over Tor and return a duplex <see cref="Stream"/>
    /// (implements <see cref="ITorDialer"/>). Onion hosts (<c>*.onion</c>) connect via the rendezvous protocol
    /// (see <see cref="ConnectToOnionAsync"/>); any other host connects to the clearnet through a Tor exit relay
    /// (see <see cref="ConnectViaExitAsync"/>). The SOCKS5 server and the HttpClient integration both dial through
    /// here, so both reach onion and clearnet destinations alike.
    /// </summary>
    public Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default) =>
        ConnectAsync(host, port, _options.Timeout, cancellationToken);

    /// <summary>
    /// As <see cref="ConnectAsync(string,int,CancellationToken)"/>, with an explicit per-call <paramref name="timeout"/>.
    /// If <see cref="TorClientOptions.OnionOnly"/> is set, a non-onion host throws <see cref="ClearnetBlockedException"/>
    /// rather than routing through a Tor exit.
    /// </summary>
    public async Task<Stream> ConnectAsync(string host, int port, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        if (host.EndsWith(".onion", StringComparison.OrdinalIgnoreCase))
            return await ConnectToOnionAsync(host, port, timeout, cancellationToken).ConfigureAwait(false);
        if (_options.OnionOnly)
            throw new ClearnetBlockedException(host);
        return await ConnectViaExitAsync(host, port, timeout, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Connect to a clearnet <paramref name="host"/>:<paramref name="port"/> through a Tor exit relay and return a
    /// duplex <see cref="Stream"/>. Builds a 3-hop circuit whose exit permits the port, then RELAY_BEGINs to the
    /// target — the exit performs the DNS resolution, so no local lookup leaks. Retries on a fresh exit if one
    /// refuses the address (exit policy / resolve failure). Disposing the stream tears the circuit down.
    /// </summary>
    public Task<Stream> ConnectViaExitAsync(string host, int port, CancellationToken ct = default) =>
        ConnectViaExitAsync(host, port, _options.Timeout, ct);

    /// <summary>As <see cref="ConnectViaExitAsync(string,int,CancellationToken)"/>, with an explicit per-attempt
    /// <paramref name="timeout"/>. Throws <see cref="ClearnetBlockedException"/> if the client is <c>OnionOnly</c>.</summary>
    public async Task<Stream> ConnectViaExitAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        if (_options.OnionOnly) throw new ClearnetBlockedException(host);
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before connecting.");
        // An IPv6-literal destination must exit over IPv6, so select an exit whose IPv6 ("p6") policy permits the port.
        bool ipv6 = System.Net.IPAddress.TryParse(host, out System.Net.IPAddress? ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        const int maxAttempts = 3;
        Exception? last = null;

        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);

            Report(TorPhase.BuildingCircuit, $"Building an exit circuit to {host}:{port}…", 0.3);
            OrConnection conn;
            Circuit circuit;
            try { (conn, circuit) = await network.BuildExitCircuitAsync(port, middleCount: 1, DateTimeOffset.UtcNow, cts.Token, ipv6).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { last = e; continue; }

            try
            {
                Report(TorPhase.Connecting, $"Opening a stream to {host}:{port} via the exit…", 0.7);
                TorStream stream = await circuit.ConnectAsync($"{host}:{port}", RelayBeginFlags.IPv6Okay, cts.Token).ConfigureAwait(false);
                Report(TorPhase.Connected, $"Connected to {host}:{port}.", 1.0);
                return new CircuitOwningStream(stream, circuit, conn);
            }
            catch (StreamRejectedException e) when (IsRetryableExitFailure(e.Reason))
            {
                last = e;
                await conn.DisposeAsync().ConfigureAwait(false); // the address is unreachable via this exit — try another
            }
            catch
            {
                await conn.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        throw new IOException($"Could not connect to {host}:{port} via a Tor exit after {maxAttempts} attempts.", last);
    }

    // Exit-side failures worth retrying on a different exit; target-side ones (connection refused/reset) are not.
    private static bool IsRetryableExitFailure(RelayEndReason? reason) => reason is
        RelayEndReason.ExitPolicy or RelayEndReason.ResolveFailed or RelayEndReason.Misc or RelayEndReason.Internal or
        RelayEndReason.NoRoute or RelayEndReason.Timeout or RelayEndReason.ResourceLimit or RelayEndReason.Hibernating;

    /// <summary>
    /// Host a v3 onion service for the given <paramref name="identity"/> (create one with
    /// <see cref="OnionServiceKey.CreateRandom"/>, restore with <see cref="OnionServiceKey.FromTorSecretKey"/>,
    /// or import a vanity key): establish introduction points, publish the descriptor, and hand each inbound stream
    /// (already RELAY_CONNECTED) to <paramref name="onAccept"/>, which owns it. This is the low-level primitive —
    /// feed the stream straight to a web server (no loopback) or bridge it wherever you like. Returns the .onion
    /// address once published; runs until <paramref name="ct"/> is cancelled or the host is disposed.
    /// </summary>
    public async Task<OnionServiceHost> PublishOnionAsync(OnionServiceKey identity, OnionStreamHandler onAccept, int introPoints = 3, IReadOnlyList<byte[]>? authorizedClients = null, CancellationToken ct = default)
    {
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before publishing.");
        var service = new HsService(network, introPoints, authorizedClients: authorizedClients, useVanguards: VanguardsForService);
        return await service.StartAsync(identity, onAccept, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Convenience overload: host <paramref name="identity"/> as a reverse proxy that bridges every inbound onion
    /// stream to a local TCP backend at <paramref name="backendHost"/>:<paramref name="backendPort"/>. The backend
    /// app is unaware of Tor. For a no-loopback, in-process integration use CupriTor.AspNetCore instead.
    /// </summary>
    public Task<OnionServiceHost> PublishOnionAsync(OnionServiceKey identity, string backendHost, int backendPort, int introPoints = 3, IReadOnlyList<byte[]>? authorizedClients = null, CancellationToken ct = default) =>
        PublishOnionAsync(identity, OnionReverseProxy.ToTcp(backendHost, backendPort), introPoints, authorizedClients, ct);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _shutdown.Cancel();
        if (_refreshLoop is not null)
        {
            try { await _refreshLoop.ConfigureAwait(false); } catch { /* shutdown */ }
        }
        _shutdown.Dispose();
    }

    private static IEnumerable<string> SplitCertificates(string text)
    {
        const string marker = "dir-key-certificate-version";
        int idx = text.IndexOf(marker, StringComparison.Ordinal);
        while (idx >= 0)
        {
            int next = text.IndexOf(marker, idx + marker.Length, StringComparison.Ordinal);
            yield return next < 0 ? text[idx..] : text[idx..next];
            idx = next;
        }
    }
}
