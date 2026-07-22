using System.Net;
using CupriTor.Directory;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class EntryGuardTests
{
    private sealed class SeededRandom(int seed) : IRandomSource
    {
        private readonly Random _r = new(seed);
        public ulong NextBelow(ulong exclusiveMax)
        {
            ulong v = (ulong)(_r.NextDouble() * exclusiveMax);
            return v >= exclusiveMax ? exclusiveMax - 1 : v;
        }
    }

    private static readonly DateTimeOffset Now = new(2026, 7, 22, 8, 0, 0, TimeSpan.Zero);

    private static RouterStatusEntry Guard(byte id, string ip, long bw = 1000)
    {
        var idBytes = new byte[20];
        Array.Fill(idBytes, id);
        var r = new RouterStatusEntry
        {
            Nickname = $"G{id}",
            RsaIdentityDigest = idBytes,
            Address = IPAddress.Parse(ip),
            OrPort = 9001,
            Bandwidth = bw,
        };
        foreach (string f in new[] { "Guard", "Running", "Valid", "Fast", "Stable" }) r.Flags.Add(f);
        return r;
    }

    private static List<RouterStatusEntry> Candidates() => new()
    {
        Guard(1, "10.1.0.1"),
        Guard(2, "10.2.0.1"),
        Guard(3, "10.3.0.1"),
        Guard(4, "10.4.0.1"),
    };

    [Fact]
    public void Samples_And_Persists_Across_Restart()
    {
        var store = new InMemoryStateStore();
        List<RouterStatusEntry> routers = Candidates();

        var m1 = new EntryGuardManager(store, new SeededRandom(1), targetCount: 2);
        var sel1 = m1.SelectGuard(routers, Now);
        Assert.NotNull(sel1);
        Assert.Equal(2, m1.Guards.Count);
        List<string> fps = m1.Guards.Select(g => g.Fingerprint).ToList();

        // A fresh manager (different RNG) over the same store loads the persisted guards.
        var m2 = new EntryGuardManager(store, new SeededRandom(999), targetCount: 2);
        Assert.Equal(fps, m2.Guards.Select(g => g.Fingerprint).ToList());
        var sel2 = m2.SelectGuard(routers, Now);
        Assert.Equal(sel1!.Value.Guard.Fingerprint, sel2!.Value.Guard.Fingerprint);
    }

    [Fact]
    public void Failure_Switches_Guard_Then_Recovers_After_Backoff()
    {
        var store = new InMemoryStateStore();
        List<RouterStatusEntry> routers = Candidates();
        var m = new EntryGuardManager(store, new SeededRandom(2), targetCount: 2);

        string first = m.SelectGuard(routers, Now)!.Value.Guard.Fingerprint;
        m.MarkFailure(m.Guards.First(g => g.Fingerprint == first), Now);

        string afterFailure = m.SelectGuard(routers, Now)!.Value.Guard.Fingerprint;
        Assert.NotEqual(first, afterFailure); // switched to a backup

        // After the retry backoff, the original guard is preferred again.
        DateTimeOffset later = Now + TimeSpan.FromMinutes(11);
        string recovered = m.SelectGuard(routers, later)!.Value.Guard.Fingerprint;
        Assert.Equal(first, recovered);
    }

    [Fact]
    public void Guards_Are_In_Distinct_Subnets()
    {
        var store = new InMemoryStateStore();
        var routers = new List<RouterStatusEntry>
        {
            Guard(1, "10.1.0.1"),
            Guard(2, "10.1.0.2"), // same /16 as guard 1
            Guard(3, "10.2.0.1"),
        };
        var m = new EntryGuardManager(store, new SeededRandom(5), targetCount: 2);
        m.SelectGuard(routers, Now);

        var subnets = m.Guards
            .Select(g => string.Join('.', IPAddress.Parse(g.Address).GetAddressBytes()[..2]))
            .ToList();
        Assert.Equal(subnets.Count, subnets.Distinct().Count());
    }

    [Fact]
    public void Skips_Guard_That_Left_The_Consensus()
    {
        var store = new InMemoryStateStore();
        List<RouterStatusEntry> routers = Candidates();
        var m = new EntryGuardManager(store, new SeededRandom(7), targetCount: 2);

        var selected = m.SelectGuard(routers, Now)!.Value;
        // Remove the selected guard from the consensus.
        List<RouterStatusEntry> reduced = routers.Where(r => Convert.ToHexString(r.RsaIdentityDigest) != selected.Guard.Fingerprint).ToList();

        var next = m.SelectGuard(reduced, Now);
        Assert.NotNull(next);
        Assert.NotEqual(selected.Guard.Fingerprint, next!.Value.Guard.Fingerprint);
    }
}
