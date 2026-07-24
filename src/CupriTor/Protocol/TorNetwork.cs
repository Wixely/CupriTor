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
    public async Task<(OrConnection Connection, Circuit Circuit)> BuildCircuitAsync(int length, DateTimeOffset now, CancellationToken ct)
    {
        if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));

        var guard = Guards.SelectGuard(Consensus.Routers, now)
            ?? throw new InvalidOperationException("No usable entry guard is available from the current consensus.");

        // The guard is hop 0; select the remaining middles with /16 + family diversity against it.
        var perHop = new List<IReadOnlyCollection<string>>();
        for (int i = 1; i < length; i++) perHop.Add(new[] { "Fast" });

        if (!PathSelector.TryExtendPath(Consensus.Routers, new[] { guard.Router }, perHop, _random, out RouterStatusEntry[] path))
            throw new InvalidOperationException("Could not select a circuit path from the consensus.");

        Dictionary<string, Microdescriptor> mds = await ResolveMicrodescriptorsAsync(path, ct).ConfigureAwait(false);

        RelayHopInfo GuardHop(RouterStatusEntry r)
        {
            Microdescriptor md = mds[Convert.ToHexString(r.RsaIdentityDigest)];
            return new RelayHopInfo(r.Address, (ushort)r.OrPort, r.RsaIdentityDigest, md.NtorOnionKey, md.Ed25519Identity);
        }

        RelayHopInfo hop0 = GuardHop(path[0]);
        OrConnection conn = await OrConnection.EstablishAsync(
            _transport, path[0].Address.ToString(), path[0].OrPort, now,
            expectedEd25519Identity: hop0.Ed25519Identity, peerAddress: path[0].Address, ct: ct).ConfigureAwait(false);

        try
        {
            Circuit circuit = conn.CreateCircuit(NextCircuitId());
            await circuit.CreateFirstHopAsync(hop0, ct).ConfigureAwait(false);
            for (int i = 1; i < path.Length; i++)
                await circuit.ExtendAsync(GuardHop(path[i]), ct).ConfigureAwait(false);

            Guards.MarkSuccess(guard.Guard, now);
            circuit.Start();
            return (conn, circuit);
        }
        catch
        {
            Guards.MarkFailure(guard.Guard, now);
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
