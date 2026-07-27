using System.Globalization;
using System.Net;
using System.Text;
using CupriTor.Directory;

namespace CupriTor.Protocol;

/// <summary>A persisted layer-2 vanguard: the relay's identity fingerprint, last-known address, and expiry.</summary>
internal sealed class Layer2Vanguard
{
    public required string Fingerprint { get; init; } // hex of the 20-byte RSA identity digest
    public required string Address { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }

    public bool IsExpired(DateTimeOffset now) => now >= ExpiresAt;
}

/// <summary>
/// Maintains the layer-2 vanguard set (guard-spec / prop-333 "vanguards-lite"): a small, slowly-rotating set of
/// second-hop relays used for onion-service circuits, so an adversary who can induce many circuits can't enumerate
/// random middles to work back toward the entry guard (guard-discovery defense). Per the spec: 4 vanguards, each
/// with a <c>max(X, X)</c> lifetime where X is uniform in [1, 12] days (≈1 week average); a vanguard is replaced
/// when it leaves the consensus or loses the Fast/Stable flags. Persisted across restarts via an
/// <see cref="IStateStore"/>, exactly like the entry guards — losing the set each run would defeat the point.
/// </summary>
internal sealed class VanguardManager
{
    private const string StoreKey = "layer2-vanguards";
    private static readonly TimeSpan MinLifetime = TimeSpan.FromDays(1);
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(12);

    private readonly IStateStore _store;
    private readonly IRandomSource _random;
    private readonly int _targetCount;
    private readonly List<Layer2Vanguard> _vanguards;
    private readonly object _lock = new(); // circuit builds run concurrently; serialize all set access

    public VanguardManager(IStateStore store, IRandomSource random, int targetCount = 4)
    {
        _store = store;
        _random = random;
        _targetCount = Math.Clamp(targetCount, 1, 19); // spec caps guard-hs-l2-number at 19
        _vanguards = Load(store);
    }

    /// <summary>The current layer-2 vanguard fingerprints (for tests/diagnostics).</summary>
    public IReadOnlyList<Layer2Vanguard> Vanguards => _vanguards;

    /// <summary>
    /// Refresh the set from the current consensus and return a random usable layer-2 relay to use as the second hop
    /// of an onion circuit, kept distinct (relay + /16) from <paramref name="guard"/>. Returns null if none is
    /// available (the caller should fall back to a normal middle).
    /// </summary>
    public RouterStatusEntry? SelectLayer2(IReadOnlyList<RouterStatusEntry> routers, RouterStatusEntry guard, DateTimeOffset now)
    {
        // Vanguards must be usable as middles: Fast + Stable + Running + Valid (path selection wants those flags).
        var listed = routers
            .Where(r => r.Flags.Contains("Fast") && r.Flags.Contains("Stable") && r.Flags.Contains("Running") && r.Flags.Contains("Valid"))
            .ToDictionary(r => Convert.ToHexString(r.RsaIdentityDigest));

        string guardFp = Convert.ToHexString(guard.RsaIdentityDigest);

        lock (_lock)
        {
            Refresh(listed, guard, guardFp, now);

            var usable = new List<RouterStatusEntry>();
            foreach (Layer2Vanguard v in _vanguards)
                if (!v.IsExpired(now) && listed.TryGetValue(v.Fingerprint, out RouterStatusEntry? r)
                    && v.Fingerprint != guardFp && !PathSelector.SameSlash16(r.Address, guard.Address))
                    usable.Add(r);

            if (usable.Count == 0) return null;
            return usable[(int)_random.NextBelow((ulong)usable.Count)];
        }
    }

    // Drop expired / unlisted / flag-losing vanguards (and any that now collide with the guard), then top the set
    // back up to the target count from the consensus — bandwidth-weighted, distinct relay + /16 from the guard and
    // the existing vanguards. Persists if the set changed.
    private void Refresh(Dictionary<string, RouterStatusEntry> listed, RouterStatusEntry guard, string guardFp, DateTimeOffset now)
    {
        bool changed = _vanguards.RemoveAll(v =>
            v.IsExpired(now) || !listed.ContainsKey(v.Fingerprint) || v.Fingerprint == guardFp) > 0;

        var have = _vanguards.Select(v => v.Fingerprint).ToHashSet();
        while (_vanguards.Count < _targetCount)
        {
            var available = listed.Values.Where(r =>
            {
                string fp = Convert.ToHexString(r.RsaIdentityDigest);
                return fp != guardFp && !have.Contains(fp)
                    && !PathSelector.SameSlash16(r.Address, guard.Address)
                    && !ConflictsVanguardSubnet(r, listed);
            }).ToList();
            if (available.Count == 0) break;

            RouterStatusEntry picked = PathSelector.PickWeighted(available, _random);
            _vanguards.Add(new Layer2Vanguard
            {
                Fingerprint = Convert.ToHexString(picked.RsaIdentityDigest),
                Address = picked.Address.ToString(),
                ExpiresAt = now + RandomLifetime(),
            });
            have.Add(Convert.ToHexString(picked.RsaIdentityDigest));
            changed = true;
        }

        if (changed) Persist();
    }

    private bool ConflictsVanguardSubnet(RouterStatusEntry candidate, Dictionary<string, RouterStatusEntry> listed)
    {
        foreach (Layer2Vanguard v in _vanguards)
            if (listed.TryGetValue(v.Fingerprint, out RouterStatusEntry? r) && PathSelector.SameSlash16(candidate.Address, r.Address))
                return true;
        return false;
    }

    // Lifetime = max(X, X), X ~ uniform[MinLifetime, MaxLifetime] (prop 333 §"Rotation period analysis").
    private TimeSpan RandomLifetime()
    {
        long span = (long)(MaxLifetime - MinLifetime).TotalSeconds;
        long a = (long)_random.NextBelow((ulong)span + 1);
        long b = (long)_random.NextBelow((ulong)span + 1);
        return MinLifetime + TimeSpan.FromSeconds(Math.Max(a, b));
    }

    private void Persist()
    {
        var sb = new StringBuilder();
        foreach (Layer2Vanguard v in _vanguards)
            sb.Append(v.Fingerprint).Append(',').Append(v.Address).Append(',').Append(v.ExpiresAt.ToUnixTimeSeconds()).Append('\n');
        _store.Write(StoreKey, Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static List<Layer2Vanguard> Load(IStateStore store)
    {
        var list = new List<Layer2Vanguard>();
        byte[]? data = store.Read(StoreKey);
        if (data is null) return list;

        foreach (string line in Encoding.UTF8.GetString(data).Split('\n'))
        {
            if (line.Length == 0) continue;
            string[] p = line.Split(',');
            if (p.Length != 3) continue;
            if (!long.TryParse(p[2], CultureInfo.InvariantCulture, out long exp)) continue;
            list.Add(new Layer2Vanguard { Fingerprint = p[0], Address = p[1], ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(exp) });
        }
        return list;
    }
}
