using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

public class HsDirRingTests
{
    private static byte[] Fill(byte v) { var b = new byte[32]; Array.Fill(b, v); return b; }

    private static List<byte[]> SyntheticHsDirs(int n)
    {
        var list = new List<byte[]>(n);
        for (int i = 0; i < n; i++)
        {
            var id = new byte[32];
            id[0] = (byte)i;
            id[1] = (byte)(i * 7 + 3);
            id[31] = (byte)(i * 13);
            list.Add(id);
        }
        return list;
    }

    [Fact]
    public void Indices_Are_Deterministic()
    {
        byte[] srv = Fill(0x5a), blinded = Fill(0xb1);
        Assert.Equal(HsDirRing.NodeIndex(Fill(1), srv, 500, 1440), HsDirRing.NodeIndex(Fill(1), srv, 500, 1440));
        Assert.NotEqual(HsDirRing.NodeIndex(Fill(1), srv, 500, 1440), HsDirRing.NodeIndex(Fill(2), srv, 500, 1440));
        Assert.Equal(HsDirRing.HsIndex(blinded, 1, 500, 1440), HsDirRing.HsIndex(blinded, 1, 500, 1440));
        Assert.NotEqual(HsDirRing.HsIndex(blinded, 1, 500, 1440), HsDirRing.HsIndex(blinded, 2, 500, 1440));
    }

    [Fact]
    public void Responsible_Selection_Matches_Ring_Walk()
    {
        var dirs = SyntheticHsDirs(50);
        byte[] srv = Fill(0x5a), blinded = Fill(0xb1);
        long tp = 500; int len = 1440, replicas = 2, spread = 4;

        List<byte[]> chosen = HsDirRing.Responsible(dirs, id => id, blinded, srv, tp, len, replicas, spread);

        // Independently recompute: rank nodes by index, then walk `spread` from each replica's hs index.
        var ranked = dirs.Select(id => (idx: HsDirRing.NodeIndex(id, srv, tp, len), id))
                         .OrderBy(x => x.idx, ByteArrayComparer.Instance).ToList();

        var expected = new List<byte[]>();
        var seenPos = new HashSet<int>();
        for (int replica = 1; replica <= replicas; replica++)
        {
            byte[] hs = HsDirRing.HsIndex(blinded, replica, tp, len);
            int start = ranked.FindIndex(x => ByteArrayComparer.Instance.Compare(x.idx, hs) > 0);
            if (start < 0) start = 0;
            for (int i = 0, added = 0; added < spread; i++)
            {
                int pos = (start + i) % ranked.Count;
                if (seenPos.Add(pos)) expected.Add(ranked[pos].id);
                added++;
            }
        }

        Assert.Equal(expected.Count, chosen.Count);
        for (int i = 0; i < expected.Count; i++)
            Assert.Equal(expected[i], chosen[i]);
        Assert.Equal(chosen.Count, chosen.Distinct(ByteArrayComparer.Instance).Count()); // no duplicates
    }

    [Fact]
    public void Responsible_Count_Is_Bounded_By_Replicas_Times_Spread()
    {
        var dirs = SyntheticHsDirs(100);
        List<byte[]> chosen = HsDirRing.Responsible(dirs, id => id, Fill(7), Fill(9), 123, 1440, replicas: 2, spread: 4);
        Assert.True(chosen.Count <= 2 * 4);
        Assert.True(chosen.Count > 0);
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>, IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? a, byte[]? b)
        {
            for (int i = 0; i < a!.Length && i < b!.Length; i++) { int d = a[i] - b[i]; if (d != 0) return d; }
            return a.Length - b!.Length;
        }
        public bool Equals(byte[]? a, byte[]? b) => a!.AsSpan().SequenceEqual(b);
        public int GetHashCode(byte[] a) => BitConverter.ToInt32(a, 0);
    }
}
