using CupriTor.Directory;
using CupriTor.OnionService;
using CupriTor.Protocol;

namespace CupriTor;

/// <summary>Public summary of a fetched onion-service descriptor (details needed to connect are kept internal).</summary>
public sealed record OnionDescriptorInfo(int IntroductionPointCount, long RevisionCounter);

/// <summary>Raised when the client cannot bootstrap (fetch or verify a consensus).</summary>
public sealed class TorBootstrapException(string message, Exception? inner = null) : Exception(message, inner);

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
        // No directory source configured? Fall back to the built-in authorities so `new TorClient()` just works.
        IDirectorySource dir = _directorySource = _options.DirectorySource ?? HttpDirectorySource.CreateDefault(_options.Timeout);

        try
        {
            Consensus consensus = await FetchVerifiedConsensusAsync(dir, DateTimeOffset.UtcNow, reportProgress: true, ct).ConfigureAwait(false);
            Report(TorPhase.LoadingGuards, "Priming entry guards…", 0.85);
            var guards = new EntryGuardManager(_options.StateStore, _random, _options.GuardCount);
            _network = new TorNetwork(consensus, guards, dir, _options.Transport, _random, _options.Timeout);

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
            throw new TorBootstrapException($"Consensus signature verification failed ({validSignatures} valid signatures).");

        return consensus;
    }

    /// <summary>
    /// Keep the consensus fresh for a long-running client/service: re-fetch + re-verify shortly before the
    /// current one expires (the consensus is only valid ~3h), and swap it in atomically. Retries with backoff.
    /// </summary>
    private async Task RefreshConsensusLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TorNetwork? network = _network;
            DateTimeOffset validUntil = network?.Consensus.ValidUntil ?? DateTimeOffset.UtcNow.AddHours(1);
            // Refresh in the last quarter of the validity window (with a floor/ceiling), matching tor's cadence.
            DateTimeOffset now = DateTimeOffset.UtcNow;
            TimeSpan wait = validUntil - now - TimeSpan.FromMinutes(45);
            if (wait < TimeSpan.FromMinutes(5)) wait = TimeSpan.FromMinutes(5);
            if (wait > TimeSpan.FromHours(2)) wait = TimeSpan.FromHours(2);

            try { await Task.Delay(wait, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            for (int attempt = 0; attempt < 5 && !ct.IsCancellationRequested; attempt++)
            {
                try
                {
                    Consensus fresh = await FetchVerifiedConsensusAsync(_directorySource!, DateTimeOffset.UtcNow, reportProgress: false, ct).ConfigureAwait(false);
                    _network?.UpdateConsensus(fresh);
                    break;
                }
                catch (OperationCanceledException) { return; }
                catch
                {
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
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before onion lookups.");
        if (!OnionAddress.TryParse(onion, out OnionAddress address))
            throw new ArgumentException($"Not a valid v3 .onion address: {onion}", nameof(onion));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout);

        var client = new HsDescriptorClient(network);
        OnionDescriptorResult result = await client.FetchAsync(address, timeout.Token).ConfigureAwait(false);
        return new OnionDescriptorInfo(result.IntroductionPoints.Count, result.RevisionCounter);
    }

    /// <summary>
    /// Connect to a v3 onion service and return a duplex <see cref="Stream"/> to the given virtual port:
    /// fetch the descriptor, establish a rendezvous point, INTRODUCE1 to an introduction point, complete
    /// the hs-ntor rendezvous, and open an application stream. Disposing the stream tears down the circuit.
    /// </summary>
    public async Task<Stream> ConnectToOnionAsync(string onion, int port, CancellationToken ct = default)
    {
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before connecting.");
        if (!OnionAddress.TryParse(onion, out OnionAddress address))
            throw new ArgumentException($"Not a valid v3 .onion address: {onion}", nameof(onion));

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.Timeout);

        Report(TorPhase.BuildingCircuit, $"Connecting to onion service {onion}…", 0.3);
        var connector = new OnionConnector(network);
        Stream stream = await connector.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
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
    public async Task<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        return host.EndsWith(".onion", StringComparison.OrdinalIgnoreCase)
            ? await ConnectToOnionAsync(host, port, cancellationToken).ConfigureAwait(false)
            : await ConnectViaExitAsync(host, port, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Connect to a clearnet <paramref name="host"/>:<paramref name="port"/> through a Tor exit relay and return a
    /// duplex <see cref="Stream"/>. Builds a 3-hop circuit whose exit permits the port, then RELAY_BEGINs to the
    /// target — the exit performs the DNS resolution, so no local lookup leaks. Retries on a fresh exit if one
    /// refuses the address (exit policy / resolve failure). Disposing the stream tears the circuit down.
    /// </summary>
    public async Task<Stream> ConnectViaExitAsync(string host, int port, CancellationToken ct = default)
    {
        TorNetwork network = _network ?? throw new InvalidOperationException("Call StartAsync before connecting.");
        const int maxAttempts = 3;
        Exception? last = null;

        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(_options.Timeout);

            Report(TorPhase.BuildingCircuit, $"Building an exit circuit to {host}:{port}…", 0.3);
            OrConnection conn;
            Circuit circuit;
            try { (conn, circuit) = await network.BuildExitCircuitAsync(port, middleCount: 1, DateTimeOffset.UtcNow, timeout.Token).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { last = e; continue; }

            try
            {
                Report(TorPhase.Connecting, $"Opening a stream to {host}:{port} via the exit…", 0.7);
                TorStream stream = await circuit.ConnectAsync($"{host}:{port}", RelayBeginFlags.IPv6Okay, timeout.Token).ConfigureAwait(false);
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
        var service = new HsService(network, introPoints, authorizedClients: authorizedClients);
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
