using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CupriTor.Directory;
using CupriTor.Transport;

namespace CupriTor.Protocol;

/// <summary>Signals that a selected path has two hops in the same declared relay family; the caller should reselect.</summary>
internal sealed class FamilyConflictException(string message) : Exception(message);

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
    private readonly VanguardManager? _vanguards; // layer-2 vanguards for onion circuits (null when disabled)
    private uint _circIdCounter;
    private volatile Consensus _consensus;

    // Microdescriptors are content-addressed by their SHA-256 digest, so a cached entry can never be stale:
    // a changed descriptor yields a new digest (a cache miss). This both stops re-fetching a relay's ntor key
    // over the (clearnet) directory channel on every circuit build and speeds up high-fan-out dialing.
    private readonly ConcurrentDictionary<string, Microdescriptor> _microdescCache = new(StringComparer.Ordinal);

    /// <summary>The current verified consensus. Swapped atomically by <see cref="UpdateConsensus"/> on refresh.</summary>
    public Consensus Consensus => _consensus;
    public EntryGuardManager Guards { get; }

    /// <summary>The directory source used for fetching documents (consensus refresh, microdescriptors).</summary>
    public IDirectorySource DirectorySource => _dir;

    public TorNetwork(Consensus consensus, EntryGuardManager guards, IDirectorySource dir,
        ITlsTransport transport, IRandomSource random, TimeSpan timeout, VanguardManager? vanguards = null)
    {
        _consensus = consensus;
        Guards = guards;
        _dir = dir;
        _transport = transport;
        _random = random;
        _timeout = timeout;
        _vanguards = vanguards;
    }

    /// <summary>Atomically replace the consensus (after a fresh fetch + verification). New circuits/rings use it immediately.</summary>
    public void UpdateConsensus(Consensus consensus)
    {
        _consensus = consensus;

        // Prune cached microdescriptors no longer referenced by the new consensus, keeping the cache bounded to
        // roughly the network size. Content-addressed, so dropping a still-live entry only costs a re-fetch.
        var live = new HashSet<string>(StringComparer.Ordinal);
        foreach (RouterStatusEntry r in consensus.Routers)
            if (r.MicrodescriptorSha256 is not null) live.Add(Convert.ToHexString(r.MicrodescriptorSha256));
        foreach (string key in _microdescCache.Keys)
            if (!live.Contains(key)) _microdescCache.TryRemove(key, out _);
    }

    /// <summary>
    /// Build a circuit of <paramref name="length"/> hops (entry guard + middles), establish the OR
    /// connection to the guard, run the ntor + EXTEND2 chain, and start the receive loop. The returned
    /// connection must be disposed together with the circuit.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitAsync(int length, DateTimeOffset now, CancellationToken ct)
    {
        if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));
        return SelectAndBuildAsync(length - 1, forcedFinalHop: null, now, ct);
    }

    /// <summary>
    /// Build a circuit whose final hop is a specific relay (e.g. a chosen HSDir or introduction point),
    /// with an entry guard and <paramref name="middleCount"/> random middles before it.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitToAsync(RouterStatusEntry finalHop, int middleCount, DateTimeOffset now, CancellationToken ct, bool vanguards = false) =>
        SelectAndBuildAsync(middleCount, forcedFinalHop: finalHop, now, ct, vanguards: vanguards);

    /// <summary>Select a path and build it, reselecting up to a few times if the path is rejected for a family conflict.</summary>
    private async Task<(OrConnection Connection, Circuit Circuit)> SelectAndBuildAsync(
        int middleCount, RouterStatusEntry? forcedFinalHop, DateTimeOffset now, CancellationToken ct, Func<Circuit, Task>? beforeStart = null, bool vanguards = false)
    {
        for (int attempt = 0; ; attempt++)
        {
            (GuardEntry guard, RouterStatusEntry[] path) = SelectPath(middleCount, forcedFinalHop, now, vanguards);
            try { return await BuildOverPathAsync(guard, path, now, ct, beforeStart).ConfigureAwait(false); }
            catch (FamilyConflictException) when (attempt < 3) { /* reselect and retry */ }
        }
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
        IReadOnlyList<RouterStatusEntry> routers = Consensus.Routers; // snapshot: one consensus for the whole selection

        // Entry guard + middles first, so the exit can be policy-checked and kept distinct from them.
        var selection = Guards.SelectGuard(routers, now)
            ?? throw new InvalidOperationException("No usable entry guard is available from the current consensus.");
        var perHop = new List<IReadOnlyCollection<string>>();
        for (int i = 0; i < middleCount; i++) perHop.Add(new[] { "Fast" });
        if (!PathSelector.TryExtendPath(routers, new[] { selection.Router }, perHop, _random, out RouterStatusEntry[] guardAndMiddles))
            throw new InvalidOperationException("Could not select a guard + middle path from the consensus.");

        var candidates = routers.Where(r =>
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
            try { return await BuildOverPathAsync(selection.Guard, path, now, ct).ConfigureAwait(false); }
            catch (FamilyConflictException e) { last = e; continue; } // this exit shares a family with an earlier hop — try another
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

    /// <summary>Reject a path that has two hops in the same declared family (mutual — each must list the other).</summary>
    private static void EnsureFamilyDistinct(RouterStatusEntry[] path, IReadOnlyDictionary<string, Microdescriptor> mds)
    {
        for (int i = 0; i < path.Length; i++)
        {
            Microdescriptor mdI = mds[Convert.ToHexString(path[i].RsaIdentityDigest)];
            for (int j = i + 1; j < path.Length; j++)
            {
                Microdescriptor mdJ = mds[Convert.ToHexString(path[j].RsaIdentityDigest)];
                if (InSameFamily(path[i], mdI, path[j], mdJ))
                    throw new FamilyConflictException($"Hops {path[i].Nickname} and {path[j].Nickname} are in the same family.");
            }
        }
    }

    /// <summary>Two relays are family iff EACH lists the other in its "family" line (path-spec: mutual).</summary>
    internal static bool InSameFamily(RouterStatusEntry a, Microdescriptor mdA, RouterStatusEntry b, Microdescriptor mdB) =>
        FamilyLists(mdA.Family, b) && FamilyLists(mdB.Family, a);

    private static bool FamilyLists(IReadOnlySet<string> family, RouterStatusEntry r) =>
        family.Count != 0 &&
        (family.Contains("$" + Convert.ToHexString(r.RsaIdentityDigest)) || family.Contains(r.Nickname.ToLowerInvariant()));

    /// <summary>
    /// Select the entry guard (hop 0), an optional layer-2 vanguard (hop 1, when <paramref name="vanguards"/> is set
    /// and a vanguard set is configured), <paramref name="middleCount"/> random middles, and an optional forced final hop.
    /// </summary>
    private (GuardEntry Guard, RouterStatusEntry[] Path) SelectPath(int middleCount, RouterStatusEntry? forcedFinalHop, DateTimeOffset now, bool vanguards)
    {
        IReadOnlyList<RouterStatusEntry> routers = Consensus.Routers; // snapshot: one consensus for the whole selection
        var selection = Guards.SelectGuard(routers, now)
            ?? throw new InvalidOperationException("No usable entry guard is available from the current consensus.");

        // Fixed leading hops: the guard, plus a layer-2 vanguard when enabled (guard-discovery defense for onion
        // circuits). If no vanguard is available, fall back to a normal middle rather than failing the build.
        var head = new List<RouterStatusEntry> { selection.Router };
        if (vanguards && _vanguards is not null)
        {
            RouterStatusEntry? layer2 = _vanguards.SelectLayer2(routers, selection.Router, now);
            if (layer2 is not null) head.Add(layer2);
        }
        int headLen = head.Count;

        var perHop = new List<IReadOnlyCollection<string>>();
        for (int i = 0; i < middleCount; i++) perHop.Add(new[] { "Fast" });

        if (forcedFinalHop is null)
        {
            if (!PathSelector.TryExtendPath(routers, head.ToArray(), perHop, _random, out RouterStatusEntry[] selected))
                throw new InvalidOperationException("Could not select a circuit path from the consensus.");
            return (selection.Guard, selected); // [guard, (vanguard), middle…]
        }

        // Forced final hop (HSDir / intro / rendezvous): choose middles distinct (relay + /16 + family) from the
        // guard, the vanguard, and the final hop — the exit path already does this.
        var headWithFinal = new List<RouterStatusEntry>(head) { forcedFinalHop };
        if (!PathSelector.TryExtendPath(routers, headWithFinal.ToArray(), perHop, _random, out RouterStatusEntry[] extended))
            throw new InvalidOperationException("Could not select a circuit path from the consensus.");

        // extended = [head…, finalHop, middle0, middle1, …] → reorder to [head…, middle0, …, finalHop].
        var path = new RouterStatusEntry[extended.Length];
        for (int i = 0; i < headLen; i++) path[i] = head[i];
        for (int i = 0; i < middleCount; i++) path[headLen + i] = extended[headLen + 1 + i];
        path[^1] = forcedFinalHop;
        return (selection.Guard, path);
    }

    /// <summary>
    /// Build a circuit that ends at the introduction point described by <paramref name="introSpecifiers"/> +
    /// <paramref name="introNtorKey"/> (from a decrypted descriptor): an entry guard, <paramref name="middleCount"/>
    /// middles, then an EXTEND2 to the intro point using its raw link specifiers.
    /// </summary>
    public Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitToIntroAsync(
        IReadOnlyList<LinkSpecifier> introSpecifiers, byte[] introNtorKey, int middleCount, DateTimeOffset now, CancellationToken ct, bool vanguards = false)
    {
        return SelectAndBuildAsync(middleCount, forcedFinalHop: null, now, ct, circuit => circuit.ExtendToAsync(introSpecifiers, introNtorKey, ct), vanguards);
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
        EnsureFamilyDistinct(path, mds); // now that we have each hop's family list, reject same-family paths (→ reselect)

        RelayHopInfo HopFor(RouterStatusEntry r)
        {
            Microdescriptor md = mds[Convert.ToHexString(r.RsaIdentityDigest)];
            return new RelayHopInfo(r.Address, (ushort)r.OrPort, r.RsaIdentityDigest, md.NtorOnionKey, md.Ed25519Identity);
        }

        RelayHopInfo hop0 = HopFor(path[0]);

        // A failure to reach or handshake the guard is the guard's fault; a failure at a later hop is not.
        OrConnection? established = null;
        Circuit circuit;
        try
        {
            established = await OrConnection.EstablishAsync(
                _transport, path[0].Address.ToString(), path[0].OrPort, now,
                expectedEd25519Identity: hop0.Ed25519Identity, peerAddress: path[0].Address, ct: ct).ConfigureAwait(false);
            circuit = established.CreateCircuit(NextCircuitId());
            await circuit.CreateFirstHopAsync(hop0, ct).ConfigureAwait(false);
        }
        catch
        {
            Guards.MarkFailure(guard, now);
            // Don't leak the guard connection if it came up but the first hop was cancelled/failed mid-handshake.
            if (established is not null) await established.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        // The guard connection is up; the guard is good regardless of what happens at later hops.
        OrConnection conn = established!; // non-null past the catch above (which rethrows on any failure)
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

    /// <summary>Resolve the microdescriptors (ntor keys + ed25519 ids) for the given routers, serving cache hits and
    /// fetching only the misses. Every router must resolve (throws otherwise).</summary>
    private Task<Dictionary<string, Microdescriptor>> ResolveMicrodescriptorsAsync(IReadOnlyList<RouterStatusEntry> routers, CancellationToken ct) =>
        FetchMicrodescriptorsCachedAsync(routers, lenient: false, ct);

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
    private Task<Dictionary<string, Microdescriptor>> FetchMicrodescriptorsLenientAsync(IReadOnlyList<RouterStatusEntry> routers, CancellationToken ct) =>
        FetchMicrodescriptorsCachedAsync(routers, lenient: true, ct);

    /// <summary>
    /// Resolve microdescriptors for <paramref name="routers"/>, serving from the content-addressed cache and
    /// fetching only cache misses (batched) over the directory source; fetched descriptors are then cached by
    /// digest. When <paramref name="lenient"/> is true, relays without a digest or whose descriptor can't be
    /// fetched/parsed are omitted; otherwise every router must resolve (throws if any does not).
    /// </summary>
    private async Task<Dictionary<string, Microdescriptor>> FetchMicrodescriptorsCachedAsync(IReadOnlyList<RouterStatusEntry> routers, bool lenient, CancellationToken ct, IDirectorySource? source = null)
    {
        IDirectorySource dir = source ?? _dir;
        var result = new Dictionary<string, Microdescriptor>(StringComparer.Ordinal); // hex(rsa id) → md
        var need = new List<RouterStatusEntry>();
        var byMdDigest = new Dictionary<string, RouterStatusEntry>(StringComparer.Ordinal); // hex(md digest) → router (misses)

        foreach (RouterStatusEntry r in routers)
        {
            if (r.MicrodescriptorSha256 is null)
            {
                if (lenient) continue;
                throw new InvalidOperationException($"Router {r.Nickname} has no microdescriptor digest.");
            }
            string mdHex = Convert.ToHexString(r.MicrodescriptorSha256);
            if (_microdescCache.TryGetValue(mdHex, out Microdescriptor? cached))
                result[Convert.ToHexString(r.RsaIdentityDigest)] = cached;
            else { need.Add(r); byMdDigest[mdHex] = r; }
        }

        const int batchSize = 90;
        for (int start = 0; start < need.Count; start += batchSize)
        {
            var slice = need.Skip(start).Take(batchSize).ToList();
            var digests = slice.Select(r => Convert.ToBase64String(r.MicrodescriptorSha256!).TrimEnd('=')).ToList();

            string text;
            try { text = await dir.FetchMicrodescriptorsAsync(digests, ct).ConfigureAwait(false); }
            catch (Exception e) when (lenient && e is not OperationCanceledException) { continue; }

            foreach (string block in SplitMicrodescriptorBlocks(text))
            {
                byte[] digest = SHA256.HashData(Encoding.ASCII.GetBytes(block));
                string mdHex = Convert.ToHexString(digest);
                if (byMdDigest.TryGetValue(mdHex, out RouterStatusEntry? router) &&
                    Microdescriptor.TryParse(block, out Microdescriptor md) &&
                    (lenient || md.NtorOnionKey.Length == 32))
                {
                    _microdescCache[mdHex] = md; // content-addressed → safe to cache (pruned on consensus update)
                    result[Convert.ToHexString(router.RsaIdentityDigest)] = md;
                }
            }
        }

        if (!lenient)
            foreach (RouterStatusEntry r in routers)
                if (!result.ContainsKey(Convert.ToHexString(r.RsaIdentityDigest)))
                    throw new InvalidOperationException($"Could not resolve a microdescriptor (ntor key) for {r.Nickname}.");

        return result;
    }

    /// <summary>
    /// Download every currently-listed relay's microdescriptor into the cache (best-effort) using
    /// <paramref name="source"/>. Doing this "download-all" at bootstrap over the clearnet source means later
    /// circuit builds hit the cache (no per-build directory fetch) AND an observer of the bootstrap can't tell
    /// which relays are selected; doing it over a circuit source refreshes the cache for a new consensus privately.
    /// </summary>
    public Task WarmMicrodescriptorCacheAsync(IDirectorySource source, CancellationToken ct)
    {
        var routers = Consensus.Routers.Where(r => r.MicrodescriptorSha256 is not null).ToList();
        return FetchMicrodescriptorsCachedAsync(routers, lenient: true, ct, source);
    }

    /// <summary>
    /// Fetch a directory document over a Tor circuit: build a 3-hop circuit to a V2Dir directory cache, open a
    /// BEGIN_DIR stream, GET <paramref name="path"/>, and return the (HTTP-stripped) body. The circuit's hops are
    /// resolved from the microdescriptor cache, so this does not re-enter directory resolution. Used for consensus
    /// refreshes so directory traffic stops signalling "Tor user" to an on-path observer after bootstrap.
    /// </summary>
    public async Task<string> DirectoryGetOverCircuitAsync(string path, CancellationToken ct)
    {
        RouterStatusEntry relay = SelectRelay(new[] { "V2Dir", "Fast", "Running", "Valid" })
            ?? throw new InvalidOperationException("No V2Dir directory cache is available in the consensus.");

        (OrConnection conn, Circuit circuit) = await BuildCircuitToAsync(relay, middleCount: 1, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await using (conn)
        {
            await using Stream stream = await circuit.OpenDirectoryStreamAsync(ct).ConfigureAwait(false);
            await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET {path} HTTP/1.0\r\n\r\n"), ct).ConfigureAwait(false);

            using var buf = new MemoryStream();
            var chunk = new byte[8192];
            const int maxBytes = 48 * 1024 * 1024; // cap: a hostile cache mustn't OOM us
            int n;
            while ((n = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
            {
                buf.Write(chunk, 0, n);
                if (buf.Length > maxBytes) throw new InvalidOperationException("Directory response exceeded the size cap.");
            }
            return ParseHttpBody(buf.ToArray());
        }
    }

    // Strip the HTTP status line + headers (up to the first blank line) and return the body; throw on non-200.
    internal static string ParseHttpBody(byte[] response)
    {
        ReadOnlySpan<byte> data = response;
        int headerEnd = data.IndexOf("\r\n\r\n"u8);
        if (headerEnd < 0) throw new InvalidOperationException("Malformed directory HTTP response (no header terminator).");
        ReadOnlySpan<byte> header = data[..headerEnd];
        int lineEnd = header.IndexOf((byte)'\n');
        string statusLine = Encoding.ASCII.GetString(lineEnd >= 0 ? header[..lineEnd] : header).Trim();
        if (!statusLine.Contains("200", StringComparison.Ordinal))
            throw new InvalidOperationException($"Directory fetch returned '{statusLine}'.");
        return Encoding.UTF8.GetString(data[(headerEnd + 4)..]);
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
