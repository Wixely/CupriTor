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
public sealed class TorClient : IAsyncDisposable
{
    private readonly TorClientOptions _options;
    private readonly IRandomSource _random = SecureRandomSource.Instance;
    private TorNetwork? _network;

    public TorClient(TorClientOptions? options = null)
    {
        _options = options ?? new TorClientOptions();
    }

    /// <summary>True once a verified consensus has been loaded and guards are primed.</summary>
    public bool IsBootstrapped => _network is not null;

    /// <summary>
    /// Bootstrap: fetch and verify the consensus, then prime the entry-guard set. Must be called before
    /// building circuits. Requires <see cref="TorClientOptions.DirectorySource"/> to be set.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_options.DirectorySource is null)
            throw new TorBootstrapException("TorClientOptions.DirectorySource must be set before StartAsync.");

        DateTimeOffset now = DateTimeOffset.UtcNow;

        string consensusText;
        string keysText;
        try
        {
            consensusText = await _options.DirectorySource.FetchConsensusAsync(ct).ConfigureAwait(false);
            keysText = await _options.DirectorySource.FetchAuthorityKeysAsync(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new TorBootstrapException("Failed to fetch directory documents.", e);
        }

        if (!Consensus.TryParse(consensusText, out Consensus? consensus) || consensus is null)
            throw new TorBootstrapException("Could not parse the consensus.");

        var certs = new List<AuthorityKeyCertificate>();
        foreach (string block in SplitCertificates(keysText))
            if (AuthorityKeyCertificate.TryParse(block, out AuthorityKeyCertificate cert))
                certs.Add(cert);

        if (!ConsensusVerifier.Verify(consensus, certs, DirectoryAuthorities.DefaultFingerprints, now, out int validSignatures))
            throw new TorBootstrapException($"Consensus signature verification failed ({validSignatures} valid signatures).");

        var guards = new EntryGuardManager(_options.StateStore, _random, _options.GuardCount);
        _network = new TorNetwork(consensus, guards, _options.DirectorySource, _options.Transport, _random, _options.Timeout);
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

        var connector = new OnionConnector(network);
        return await connector.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

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
