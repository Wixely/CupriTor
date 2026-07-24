using System.Security.Cryptography;
using System.Text;
using CupriTor.Directory;
using CupriTor.Transport;

namespace CupriTor.Protocol;

/// <summary>
/// The client's operational view of the network: a verified microdescriptor consensus, the entry-guard
/// set, and the machinery to resolve per-hop ntor keys and build circuits. Owns circuit-id allocation.
/// This is the internal engine behind the public <c>TorClient</c>.
/// </summary>
internal sealed class TorNetwork
{
    private readonly IDirectorySource _dir;
    private readonly ITlsTransport _transport;
    private readonly IRandomSource _random;
    private readonly TimeSpan _timeout;
    private uint _circIdCounter;

    public Consensus Consensus { get; }
    public EntryGuardManager Guards { get; }

    public TorNetwork(Consensus consensus, EntryGuardManager guards, IDirectorySource dir,
        ITlsTransport transport, IRandomSource random, TimeSpan timeout)
    {
        Consensus = consensus;
        Guards = guards;
        _dir = dir;
        _transport = transport;
        _random = random;
        _timeout = timeout;
    }

    /// <summary>
    /// Build a circuit of <paramref name="length"/> hops (entry guard + middles), establish the OR
    /// connection to the guard, run the ntor + EXTEND2 chain, and start the receive loop. The returned
    /// connection must be disposed together with the circuit.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitAsync(int length, DateTimeOffset now, CancellationToken ct)
    {
        if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));
        (GuardEntry guard, RouterStatusEntry[] path) = SelectPath(length - 1, forcedFinalHop: null, now);
        return BuildOverPathAsync(guard, path, now, ct);
    }

    /// <summary>
    /// Build a circuit whose final hop is a specific relay (e.g. a chosen HSDir or introduction point),
    /// with an entry guard and <paramref name="middleCount"/> random middles before it.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitToAsync(RouterStatusEntry finalHop, int middleCount, DateTimeOffset now, CancellationToken ct)
    {
        (GuardEntry guard, RouterStatusEntry[] path) = SelectPath(middleCount, forcedFinalHop: finalHop, now);
        return BuildOverPathAsync(guard, path, now, ct);
    }

    /// <summary>Select the entry guard (hop 0), <paramref name="middleCount"/> random middles, and an optional forced final hop.</summary>
    private (GuardEntry Guard, RouterStatusEntry[] Path) SelectPath(int middleCount, RouterStatusEntry? forcedFinalHop, DateTimeOffset now)
    {
        var selection = Guards.SelectGuard(Consensus.Routers, now)
            ?? throw new InvalidOperationException("No usable entry guard is available from the current consensus.");

        var perHop = new List<IReadOnlyCollection<string>>();
        for (int i = 0; i < middleCount; i++) perHop.Add(new[] { "Fast" });

        if (!PathSelector.TryExtendPath(Consensus.Routers, new[] { selection.Router }, perHop, _random, out RouterStatusEntry[] selected))
            throw new InvalidOperationException("Could not select a circuit path from the consensus.");

        if (forcedFinalHop is null) return (selection.Guard, selected);

        var withFinal = new RouterStatusEntry[selected.Length + 1];
        selected.CopyTo(withFinal, 0);
        withFinal[^1] = forcedFinalHop;
        return (selection.Guard, withFinal);
    }

    private async Task<(OrConnection Connection, Circuit Circuit)> BuildOverPathAsync(GuardEntry guard, RouterStatusEntry[] path, DateTimeOffset now, CancellationToken ct)
    {
        Dictionary<string, Microdescriptor> mds = await ResolveMicrodescriptorsAsync(path, ct).ConfigureAwait(false);

        RelayHopInfo HopFor(RouterStatusEntry r)
        {
            Microdescriptor md = mds[Convert.ToHexString(r.RsaIdentityDigest)];
            return new RelayHopInfo(r.Address, (ushort)r.OrPort, r.RsaIdentityDigest, md.NtorOnionKey, md.Ed25519Identity);
        }

        RelayHopInfo hop0 = HopFor(path[0]);
        OrConnection conn = await OrConnection.EstablishAsync(
            _transport, path[0].Address.ToString(), path[0].OrPort, now,
            expectedEd25519Identity: hop0.Ed25519Identity, peerAddress: path[0].Address, ct: ct).ConfigureAwait(false);

        try
        {
            Circuit circuit = conn.CreateCircuit(NextCircuitId());
            await circuit.CreateFirstHopAsync(hop0, ct).ConfigureAwait(false);
            for (int i = 1; i < path.Length; i++)
                await circuit.ExtendAsync(HopFor(path[i]), ct).ConfigureAwait(false);

            Guards.MarkSuccess(guard, now);
            circuit.Start();
            return (conn, circuit);
        }
        catch
        {
            Guards.MarkFailure(guard, now);
            await conn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Fetch and digest-match the microdescriptors for the given routers (ntor keys + ed25519 ids).</summary>
    private async Task<Dictionary<string, Microdescriptor>> ResolveMicrodescriptorsAsync(IReadOnlyList<RouterStatusEntry> routers, CancellationToken ct)
    {
        var byDigest = new Dictionary<string, RouterStatusEntry>(StringComparer.Ordinal);
        var digests = new List<string>();
        foreach (RouterStatusEntry r in routers)
        {
            if (r.MicrodescriptorSha256 is null)
                throw new InvalidOperationException($"Router {r.Nickname} has no microdescriptor digest.");
            byDigest[Convert.ToHexString(r.MicrodescriptorSha256)] = r;
            digests.Add(Convert.ToBase64String(r.MicrodescriptorSha256).TrimEnd('='));
        }

        string text = await _dir.FetchMicrodescriptorsAsync(digests, ct).ConfigureAwait(false);

        var result = new Dictionary<string, Microdescriptor>(StringComparer.Ordinal);
        foreach (string block in SplitMicrodescriptorBlocks(text))
        {
            byte[] digest = SHA256.HashData(Encoding.ASCII.GetBytes(block));
            if (byDigest.TryGetValue(Convert.ToHexString(digest), out RouterStatusEntry? router) &&
                Microdescriptor.TryParse(block, out Microdescriptor md) && md.NtorOnionKey.Length == 32)
            {
                result[Convert.ToHexString(router.RsaIdentityDigest)] = md;
            }
        }

        foreach (RouterStatusEntry r in routers)
            if (!result.ContainsKey(Convert.ToHexString(r.RsaIdentityDigest)))
                throw new InvalidOperationException($"Could not resolve a microdescriptor (ntor key) for {r.Nickname}.");

        return result;
    }

    /// <summary>
    /// Resolve the ed25519 identities of the currently-listed HSDir relays (needed to compute the hash
    /// ring). Best-effort and batched: HSDirs whose microdescriptor cannot be fetched are omitted.
    /// </summary>
    public async Task<(List<RouterStatusEntry> HsDirs, Dictionary<string, byte[]> Ed25519ById)> ResolveHsDirsAsync(CancellationToken ct)
    {
        var hsdirs = Consensus.Routers
            .Where(r => r.Flags.Contains("HSDir") && r.Flags.Contains("Running") && r.Flags.Contains("Valid") && r.MicrodescriptorSha256 is not null)
            .ToList();

        Dictionary<string, Microdescriptor> mds = await FetchMicrodescriptorsLenientAsync(hsdirs, ct).ConfigureAwait(false);

        var ed = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var withEd = new List<RouterStatusEntry>();
        foreach (RouterStatusEntry r in hsdirs)
        {
            string id = Convert.ToHexString(r.RsaIdentityDigest);
            if (mds.TryGetValue(id, out Microdescriptor? md) && md.Ed25519Identity is { Length: 32 })
            {
                ed[id] = md.Ed25519Identity;
                withEd.Add(r);
            }
        }
        return (withEd, ed);
    }

    /// <summary>Batch-fetch microdescriptors, digest-matched, tolerating relays whose descriptor is unavailable.</summary>
    private async Task<Dictionary<string, Microdescriptor>> FetchMicrodescriptorsLenientAsync(IReadOnlyList<RouterStatusEntry> routers, CancellationToken ct)
    {
        var byDigest = new Dictionary<string, RouterStatusEntry>(StringComparer.Ordinal);
        foreach (RouterStatusEntry r in routers)
            if (r.MicrodescriptorSha256 is not null)
                byDigest[Convert.ToHexString(r.MicrodescriptorSha256)] = r;

        var result = new Dictionary<string, Microdescriptor>(StringComparer.Ordinal);
        const int batchSize = 90;
        for (int start = 0; start < routers.Count; start += batchSize)
        {
            var slice = routers.Skip(start).Take(batchSize).Where(r => r.MicrodescriptorSha256 is not null).ToList();
            if (slice.Count == 0) continue;

            var digests = slice.Select(r => Convert.ToBase64String(r.MicrodescriptorSha256!).TrimEnd('=')).ToList();
            string text;
            try { text = await _dir.FetchMicrodescriptorsAsync(digests, ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { continue; }

            foreach (string block in SplitMicrodescriptorBlocks(text))
            {
                byte[] digest = SHA256.HashData(Encoding.ASCII.GetBytes(block));
                if (byDigest.TryGetValue(Convert.ToHexString(digest), out RouterStatusEntry? router) &&
                    Microdescriptor.TryParse(block, out Microdescriptor md))
                {
                    result[Convert.ToHexString(router.RsaIdentityDigest)] = md;
                }
            }
        }
        return result;
    }

    // Split concatenated microdescriptors into exact blocks (each starts at an "onion-key" line).
    private static IEnumerable<string> SplitMicrodescriptorBlocks(string text)
    {
        var starts = new List<int>();
        int i = text.IndexOf("onion-key", StringComparison.Ordinal);
        while (i >= 0)
        {
            if (i == 0 || text[i - 1] == '\n') starts.Add(i);
            i = text.IndexOf("onion-key", i + 9, StringComparison.Ordinal);
        }
        for (int k = 0; k < starts.Count; k++)
        {
            int end = k + 1 < starts.Count ? starts[k + 1] : text.Length;
            yield return text[starts[k]..end];
        }
    }

    private uint NextCircuitId()
    {
        // Client-originated circuit ids set the high bit (tor-spec §5.1).
        uint id = Interlocked.Increment(ref _circIdCounter);
        return 0x80000000u | id;
    }
}
