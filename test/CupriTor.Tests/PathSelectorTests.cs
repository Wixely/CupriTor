using System.Net;
using CupriTor.Directory;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class PathSelectorTests
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

    private static RouterStatusEntry Relay(string nick, string ip, long bw, params string[] flags)
    {
        var r = new RouterStatusEntry { Nickname = nick, Address = IPAddress.Parse(ip), OrPort = 9001, Bandwidth = bw };
        foreach (string f in flags) r.Flags.Add(f);
        return r;
    }

    private static readonly IReadOnlyList<IReadOnlyCollection<string>> ThreeHop = new[]
    {
        new[] { "Guard", "Fast", "Stable" },
        new[] { "Fast" },
        new[] { "Fast", "Stable" },
    };

    [Fact]
    public void Selects_Distinct_Path_Honouring_Flags_And_Subnets()
    {
        var routers = new List<RouterStatusEntry>
        {
            Relay("G1", "10.1.0.1", 1000, "Running", "Valid", "Guard", "Fast", "Stable"),
            Relay("G2", "10.2.0.1", 1000, "Running", "Valid", "Guard", "Fast", "Stable"),
            Relay("M1", "10.3.0.1", 1000, "Running", "Valid", "Fast", "Stable"),
            Relay("M2", "10.4.0.1", 1000, "Running", "Valid", "Fast", "Stable"),
        };

        Assert.True(PathSelector.TrySelect(routers, ThreeHop, new SeededRandom(1), out var path));
        Assert.Equal(3, path.Length);
        Assert.Equal(3, path.Distinct().Count());
        Assert.Contains("Guard", path[0].Flags);          // entry is a guard
        Assert.All(path, r => Assert.Contains("Running", r.Flags));
        // Distinct /16 subnets.
        var slash16 = path.Select(r => string.Join('.', r.Address.GetAddressBytes()[..2])).ToList();
        Assert.Equal(3, slash16.Distinct().Count());
    }

    [Fact]
    public void Fails_When_Not_Enough_Distinct_Subnets()
    {
        // Three candidates but all in the same /16 -> only one can be placed.
        var routers = new List<RouterStatusEntry>
        {
            Relay("G1", "10.1.0.1", 1000, "Running", "Valid", "Guard", "Fast", "Stable"),
            Relay("M1", "10.1.0.2", 1000, "Running", "Valid", "Fast", "Stable"),
            Relay("M2", "10.1.0.3", 1000, "Running", "Valid", "Fast", "Stable"),
        };
        Assert.False(PathSelector.TrySelect(routers, ThreeHop, new SeededRandom(1), out _));
    }

    [Fact]
    public void Respects_Family_Constraint()
    {
        var g = Relay("G1", "10.1.0.1", 1000, "Running", "Valid", "Guard", "Fast", "Stable");
        var mSameFamily = Relay("M1", "10.2.0.1", 1000, "Running", "Valid", "Fast", "Stable");
        var mOk = Relay("M2", "10.3.0.1", 1000, "Running", "Valid", "Fast", "Stable");
        var mOk2 = Relay("M3", "10.4.0.1", 1000, "Running", "Valid", "Fast", "Stable");

        var families = new Dictionary<RouterStatusEntry, IReadOnlySet<string>>
        {
            [g] = new HashSet<string> { "famA" },
            [mSameFamily] = new HashSet<string> { "famA" },   // same family as the guard
            [mOk] = new HashSet<string> { "famB" },
            [mOk2] = new HashSet<string> { "famC" },
        };
        IReadOnlySet<string> Fam(RouterStatusEntry r) => families.TryGetValue(r, out var s) ? s : new HashSet<string>();

        var routers = new List<RouterStatusEntry> { g, mSameFamily, mOk, mOk2 };
        Assert.True(PathSelector.TrySelect(routers, ThreeHop, new SeededRandom(3), out var path, Fam));
        Assert.DoesNotContain(mSameFamily, path); // excluded: shares "famA" with the chosen guard
    }

    [Fact]
    public void Selection_Is_Bandwidth_Weighted()
    {
        var routers = new List<RouterStatusEntry>
        {
            Relay("Heavy", "10.1.0.1", 1000, "Running", "Valid", "Guard"),
            Relay("Light", "10.2.0.1", 1, "Running", "Valid", "Guard"),
        };
        var oneHop = new[] { (IReadOnlyCollection<string>)new[] { "Guard" } };

        int heavy = 0;
        var rng = new SeededRandom(42);
        for (int i = 0; i < 1000; i++)
        {
            Assert.True(PathSelector.TrySelect(routers, oneHop, rng, out var path));
            if (path[0].Nickname == "Heavy") heavy++;
        }
        Assert.True(heavy > 900, $"expected the high-bandwidth relay to dominate, got {heavy}/1000");
    }
}
