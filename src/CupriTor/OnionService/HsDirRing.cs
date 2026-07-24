using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace CupriTor.OnionService;

/// <summary>
/// The v3 HSDir hash ring (rend-spec-v3 §2.2.3): positions each HSDir on a ring by a per-period index,
/// and selects the relays responsible for a service's descriptor as the ones immediately following the
/// service's per-replica index around the ring.
/// </summary>
internal static class HsDirRing
{
    public const int DefaultReplicas = 2;      // hsdir_n_replicas
    public const int DefaultSpreadStore = 4;   // hsdir_spread_store
    public const int DefaultSpreadFetch = 3;   // hsdir_spread_fetch

    private static readonly byte[] NodeIdxPrefix = Encoding.ASCII.GetBytes("node-idx");
    private static readonly byte[] StoreAtIdxPrefix = Encoding.ASCII.GetBytes("store-at-idx");

    /// <summary>A relay's ring position: SHA3-256("node-idx" ‖ ed25519_id ‖ SRV ‖ INT_8(period) ‖ INT_8(len)).</summary>
    public static byte[] NodeIndex(ReadOnlySpan<byte> ed25519Id, ReadOnlySpan<byte> sharedRandom, long periodNumber, int periodLength)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(NodeIdxPrefix, 0, NodeIdxPrefix.Length);
        Fixed32(sha3, ed25519Id);
        Fixed32(sha3, sharedRandom);
        Int8(sha3, periodNumber);
        Int8(sha3, periodLength);
        return Final(sha3);
    }

    /// <summary>A service's per-replica position: SHA3-256("store-at-idx" ‖ blindedKey ‖ INT_8(replica) ‖ INT_8(len) ‖ INT_8(period)).</summary>
    public static byte[] HsIndex(ReadOnlySpan<byte> blindedKey, int replica, long periodNumber, int periodLength)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(StoreAtIdxPrefix, 0, StoreAtIdxPrefix.Length);
        Fixed32(sha3, blindedKey);
        Int8(sha3, replica);
        Int8(sha3, periodLength);
        Int8(sha3, periodNumber);
        return Final(sha3);
    }

    /// <summary>
    /// The relays responsible for the service this period: for each replica, the <paramref name="spread"/>
    /// relays whose node index immediately follows the replica's hs index around the ring (wrapping),
    /// unioned and de-duplicated.
    /// </summary>
    public static List<TNode> Responsible<TNode>(
        IReadOnlyList<TNode> hsDirs,
        Func<TNode, byte[]> ed25519IdOf,
        ReadOnlySpan<byte> blindedKey,
        ReadOnlySpan<byte> sharedRandom,
        long periodNumber,
        int periodLength,
        int replicas = DefaultReplicas,
        int spread = DefaultSpreadStore)
    {
        var ranked = new List<(byte[] Index, TNode Node)>(hsDirs.Count);
        foreach (TNode node in hsDirs)
            ranked.Add((NodeIndex(ed25519IdOf(node), sharedRandom, periodNumber, periodLength), node));
        ranked.Sort((x, y) => Compare(x.Index, y.Index));

        var chosen = new List<TNode>();
        var seen = new HashSet<int>();
        if (ranked.Count == 0) return chosen;

        for (int replica = 1; replica <= replicas; replica++)
        {
            byte[] hsIndex = HsIndex(blindedKey, replica, periodNumber, periodLength);
            int start = FirstIndexAfter(ranked, hsIndex);
            for (int i = 0, added = 0; i < ranked.Count && added < spread; i++)
            {
                int pos = (start + i) % ranked.Count;
                if (seen.Add(pos)) { chosen.Add(ranked[pos].Node); added++; }
                else added++; // a slot already taken by another replica still counts toward this replica's spread
            }
        }
        return chosen;
    }

    // First position whose index is strictly greater than target (wrapping to 0 if none).
    private static int FirstIndexAfter<TNode>(List<(byte[] Index, TNode Node)> ranked, byte[] target)
    {
        int lo = 0, hi = ranked.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (Compare(ranked[mid].Index, target) > 0) hi = mid;
            else lo = mid + 1;
        }
        return lo % ranked.Count;
    }

    private static int Compare(byte[] a, byte[] b)
    {
        for (int i = 0; i < a.Length && i < b.Length; i++)
        {
            int d = a[i] - b[i];
            if (d != 0) return d;
        }
        return a.Length - b.Length;
    }

    private static void Fixed32(Sha3Digest sha3, ReadOnlySpan<byte> value)
    {
        Span<byte> buf = stackalloc byte[32];
        value.Slice(0, 32).CopyTo(buf);
        sha3.BlockUpdate(buf);
    }

    private static void Int8(Sha3Digest sha3, long value)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        sha3.BlockUpdate(buf);
    }

    private static byte[] Final(Sha3Digest sha3)
    {
        var result = new byte[32];
        sha3.DoFinal(result, 0);
        return result;
    }
}
