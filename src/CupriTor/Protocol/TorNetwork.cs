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
    private volatile Consensus _consensus;

    /// <summary>The current verified consensus. Swapped atomically by <see cref="UpdateConsensus"/> on refresh.</summary>
    public Consensus Consensus => _consensus;
    public EntryGuardManager Guards { get; }

    /// <summary>The directory source used for fetching documents (consensus refresh, microdescriptors).</summary>
    public IDirectorySource DirectorySource => _dir;

    public TorNetwork(Consensus consensus, EntryGuardManager guards, IDirectorySource dir,
        ITlsTransport transport, IRandomSource random, TimeSpan timeout)
    {
        _consensus = consensus;
        Guards = guards;
        _dir = dir;
        _transport = transport;
        _random = random;
        _timeout = timeout;
    }

    /// <summary>Atomically replace the consensus (after a fresh fetch + verification). New circuits/rings use it immediately.</summary>
    public void UpdateConsensus(Consensus consensus) => _consensus = consensus;

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

    /// <summary>
    /// Build an exit circuit (entry guard + <paramref name="middleCount"/> middles + an exit relay) whose exit
    /// permits <paramref name="port"/>. Exit candidates are Exit-flagged, Fast, Running, Valid and not BadExit,
    /// kept distinct (relay + /16) from the earlier hops; each candidate's microdescriptor exit-policy summary is
    /// checked against the port before it is chosen (the summary lives only in the microdescriptor, not the consensus).
    /// </summary>
    public async Task<(OrConnection Connection, Circuit Circuit)> BuildExitCircuitAsync(int port, int middleCount, DateTimeOffset now, CancellationToken ct)
    {
        const int maxExitProbes = 8;

        // Entry guard + middles first, so the exit can be policy-checked and kept distinct from them.
        var selection = Guards.SelectGuard(Consensus.Routers, now)
            ?? throw new InvalidOperationException("No usable entry guard is available from the current consensus.");
        var perHop = new List<IReadOnlyCollection<string>>();
        for (int i = 0; i < middleCount; i++) perHop.Add(new[] { "Fast" });
        if (!PathSelector.TryExtendPath(Consensus.Routers, new[] { selection.Router }, perHop, _random, out RouterStatusEntry[] guardAndMiddles))
            throw new InvalidOperationException("Could not select a guard + middle path from the consensus.");

        var candidates = Consensus.Routers.Where(r =>
            r.Flags.Contains("Exit") && !r.Flags.Contains("BadExit") &&
            r.Flags.Contains("Fast") && r.Flags.Contains("Running") && r.Flags.Contains("Valid") &&
            r.MicrodescriptorSha256 is not null &&
            !guardAndMiddles.Contains(r) && !SharesSubnet(r, guardAndMiddles)).ToList();
        if (candidates.Count == 0)
            throw new InvalidOperationException("No exit relays are available in the current consensus.");

        Exception? last = null;
        for (int probe = 0; probe < maxExitProbes && candidates.Count > 0; probe++)
        {
            RouterStatusEntry exit = PathSelector.PickWeighted(candidates, _random);
            candidates.Remove(exit);

            Microdescriptor md;
            try { md = await ResolveMicrodescriptorAsync(exit, ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { last = e; continue; }

            if (!md.ExitPolicyIPv4.Allows(port)) continue;

            var path = new RouterStatusEntry[guardAndMiddles.Length + 1];
            guardAndMiddles.CopyTo(path, 0);
            path[^1] = exit;
            return await BuildOverPathAsync(selection.Guard, path, now, ct).ConfigureAwait(false);
        }

        throw new InvalidOperationException(
            $"No exit relay permitting port {port} was found after probing up to {maxExitProbes} candidates.", last);
    }

    private static bool SharesSubnet(RouterStatusEntry r, IReadOnlyList<RouterStatusEntry> others)
    {
        foreach (RouterStatusEntry o in others)
            if (PathSelector.SameSlash16(r.Address, o.Address)) return true;
        return false;
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

    /// <summary>
    /// Build a circuit that ends at the introduction point described by <paramref name="introSpecifiers"/> +
    /// <paramref name="introNtorKey"/> (from a decrypted descriptor): an entry guard, <paramref name="middleCount"/>
    /// middles, then an EXTEND2 to the intro point using its raw link specifiers.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitToIntroAsync(
        IReadOnlyList<LinkSpecifier> introSpecifiers, byte[] introNtorKey, int middleCount, DateTimeOffset now, CancellationToken ct)
    {
        (GuardEntry guard, RouterStatusEntry[] path) = SelectPath(middleCount, forcedFinalHop: null, now);
        return BuildOverPathAsync(guard, path, now, ct, circuit => circuit.ExtendToAsync(introSpecifiers, introNtorKey, ct));
    }

    /// <summary>Pick a random relay carrying the required flags (bandwidth-weighted), e.g. a rendezvous point.</summary>
    public RouterStatusEntry? SelectRelay(IReadOnlyCollection<string> requiredFlags)
    {
        var perHop = new IReadOnlyCollection<string>[] { requiredFlags };
        return PathSelector.TrySelect(Consensus.Routers, perHop, _random, out RouterStatusEntry[] path) ? path[0] : null;
    }

    /// <summary>Resolve a single relay's microdescriptor (ntor onion key + ed25519 identity).</summary>
    public async Task<Microdescriptor> ResolveMicrodescriptorAsync(RouterStatusEntry relay, CancellationToken ct)
    {
        Dictionary<string, Microdescriptor> mds = await ResolveMicrodescriptorsAsync(new[] { relay }, ct).ConfigureAwait(false);
        return mds[Convert.ToHexString(relay.RsaIdentityDigest)];
    }

    private async Task<(OrConnection Connection, Circuit Circuit)> BuildOverPathAsync(
        GuardEntry guard, RouterStatusEntry[] path, DateTimeOffset now, CancellationToken ct, Func<Circuit, Task>? beforeStart = null)
    {
        Dictionary<string, Microdescriptor> mds = await ResolveMicrodescriptorsAsync(path, ct).ConfigureAwait(false);

        RelayHopInfo HopFor(RouterStatusEntry r)
        {
            Microdescriptor md = mds[Convert.ToHexString(r.RsaIdentityDigest)];
            return new RelayHopInfo(r.Address, (ushort)r.OrPort, r.RsaIdentityDigest, md.NtorOnionKey, md.Ed25519Identity);
        }

        RelayHopInfo hop0 = HopFor(path[0]);

        // A failure to reach or handshake the guard is the guard's fault; a failure at a later hop is not.
        OrConnection conn;
        Circuit circuit;
        try
        {
            conn = await OrConnection.EstablishAsync(
                _transport, path[0].Address.ToString(), path[0].OrPort, now,
                expectedEd25519Identity: hop0.Ed25519Identity, peerAddress: path[0].Address, ct: ct).ConfigureAwait(false);
            circuit = conn.CreateCircuit(NextCircuitId());
            await circuit.CreateFirstHopAsync(hop0, ct).ConfigureAwait(false);
        }
        catch
        {
            Guards.MarkFailure(guard, now);
            throw;
        }

        // The guard connection is up; the guard is good regardless of what happens at later hops.
        Guards.MarkSuccess(guard, now);
        try
        {
            for (int i = 1; i < path.Length; i++)
                await circuit.ExtendAsync(HopFor(path[i]), ct).ConfigureAwait(false);

            if (beforeStart is not null) await beforeStart(circuit).ConfigureAwait(false);

            circuit.Start();
            return (conn, circuit);
        }
        catch
        {
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
