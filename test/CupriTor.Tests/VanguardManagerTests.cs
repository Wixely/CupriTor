using System.Net;
using CupriTor.Directory;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class VanguardManagerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);

    private static RouterStatusEntry Relay(int i, params string[] flags)
    {
        var id = new byte[20];
        id[0] = (byte)i;
        id[1] = (byte)(i >> 8);
        var r = new RouterStatusEntry
        {
            Nickname = $"relay{i}",
            RsaIdentityDigest = id,
            Address = IPAddress.Parse($"10.{i}.0.1"), // distinct /16 per i
            OrPort = 9001,
            Bandwidth = 1000,
        };
        foreach (string f in flags) r.Flags.Add(f);
        return r;
    }

    private static readonly string[] MiddleFlags = { "Fast", "Stable", "Running", "Valid" };

    [Fact]
    public void SelectLayer2_Builds_A_Distinct_Set_With_Bounded_Lifetimes()
    {
        var routers = Enumerable.Range(0, 30).Select(i => Relay(i, MiddleFlags)).ToList();
        var guard = Relay(200, "Fast", "Stable", "Running", "Valid", "Guard");
        var vg = new VanguardManager(new InMemoryStateStore(), SecureRandomSource.Instance);

        RouterStatusEntry? l2 = vg.SelectLayer2(routers, guard, Now);

        Assert.NotNull(l2);
        Assert.Equal(4, vg.Vanguards.Count); // spec default NUM_LAYER2_GUARDS
        Assert.Equal(4, vg.Vanguards.Select(v => v.Fingerprint).Distinct().Count());

        string guardFp = Convert.ToHexString(guard.RsaIdentityDigest);
        Assert.DoesNotContain(guardFp, vg.Vanguards.Select(v => v.Fingerprint));
        Assert.NotEqual(guardFp, Convert.ToHexString(l2!.RsaIdentityDigest));

        // Lifetime = max(X,X), X ~ uniform[1,12] days — every vanguard expires within those bounds.
        Assert.All(vg.Vanguards, v => Assert.InRange(v.ExpiresAt - Now, TimeSpan.FromDays(1), TimeSpan.FromDays(12)));
    }

    [Fact]
    public void Vanguards_Persist_Across_Instances()
    {
        var routers = Enumerable.Range(0, 30).Select(i => Relay(i, MiddleFlags)).ToList();
        var guard = Relay(200, MiddleFlags);
        var store = new InMemoryStateStore();

        var first = new VanguardManager(store, SecureRandomSource.Instance);
        first.SelectLayer2(routers, guard, Now);
        string[] chosen = first.Vanguards.Select(v => v.Fingerprint).OrderBy(x => x).ToArray();

        // A fresh manager over the same store reuses the persisted set (rotating each run would defeat the point).
        var restored = new VanguardManager(store, SecureRandomSource.Instance);
        Assert.Equal(chosen, restored.Vanguards.Select(v => v.Fingerprint).OrderBy(x => x).ToArray());
    }

    [Fact]
    public void Guard_Is_Never_Selected_As_A_Vanguard()
    {
        var guard = Relay(5, "Fast", "Stable", "Running", "Valid", "Guard");
        var routers = Enumerable.Range(0, 30).Select(i => Relay(i, MiddleFlags)).ToList(); // includes relay 5
        var vg = new VanguardManager(new InMemoryStateStore(), SecureRandomSource.Instance);

        vg.SelectLayer2(routers, guard, Now);

        Assert.DoesNotContain(Convert.ToHexString(guard.RsaIdentityDigest), vg.Vanguards.Select(v => v.Fingerprint));
    }

    [Fact]
    public void SelectLayer2_Returns_Null_When_No_Suitable_Relays()
    {
        // Relays without Fast/Stable aren't usable as vanguards.
        var routers = Enumerable.Range(0, 5).Select(i => Relay(i, "Running", "Valid")).ToList();
        var guard = Relay(200, MiddleFlags);
        var vg = new VanguardManager(new InMemoryStateStore(), SecureRandomSource.Instance);

        Assert.Null(vg.SelectLayer2(routers, guard, Now));
        Assert.Empty(vg.Vanguards);
    }
}
