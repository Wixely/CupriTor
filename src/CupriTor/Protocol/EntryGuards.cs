using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using CupriTor.Directory;

namespace CupriTor.Protocol;

/// <summary>Persistence for small pieces of client state (guards, caches). Keys are opaque strings.</summary>
public interface IStateStore
{
    byte[]? Read(string key);
    void Write(string key, byte[] data);
}

/// <summary>An in-memory <see cref="IStateStore"/> (default/testing; not persistent across process restarts).</summary>
public sealed class InMemoryStateStore : IStateStore
{
    private readonly Dictionary<string, byte[]> _data = new();
    public byte[]? Read(string key) => _data.TryGetValue(key, out byte[]? v) ? v : null;
    public void Write(string key, byte[] data) => _data[key] = data;
}

/// <summary>A persisted entry guard: the relay's identity fingerprint and last-known address plus reachability state.</summary>
internal sealed class GuardEntry
{
    public required string Fingerprint { get; init; }   // hex of the 20-byte RSA identity digest
    public required string Address { get; set; }
    public DateTimeOffset AddedAt { get; set; }
    public bool Reachable { get; set; } = true;
    public DateTimeOffset? RetryAfter { get; set; }

    public bool IsUsable(DateTimeOffset now) => Reachable || RetryAfter is null || now >= RetryAfter;
}

/// <summary>
/// Manages the client's entry guards (guard-spec / prop-271, pragmatic subset): a small persisted set
/// of stable entry relays, sampled bandwidth-weighted from the consensus with /16 diversity, tracked
/// up/down with retry backoff, and reused across restarts via an <see cref="IStateStore"/>. Guards are
/// anonymity-critical: they are kept stable rather than reselected per circuit.
/// </summary>
internal sealed class EntryGuardManager
{
    private const string StoreKey = "entry-guards";
    private static readonly TimeSpan RetryBackoff = TimeSpan.FromMinutes(10);

    private readonly IStateStore _store;
    private readonly IRandomSource _random;
    private readonly int _targetCount;
    private readonly List<GuardEntry> _guards;
    private readonly object _lock = new(); // circuit builds run concurrently; all guard-set access is serialized

    public EntryGuardManager(IStateStore store, IRandomSource random, int targetCount = 3)
    {
        _store = store;
        _random = random;
        _targetCount = targetCount;
        _guards = Load(store);
    }

    public IReadOnlyList<GuardEntry> Guards => _guards;

    /// <summary>
    /// Ensure the guard set is populated from the current consensus and return a usable, currently-listed
    /// guard with its router entry (for dialing), or null if none is available right now.
    /// </summary>
    public (GuardEntry Guard, RouterStatusEntry Router)? SelectGuard(IReadOnlyList<RouterStatusEntry> routers, DateTimeOffset now)
    {
        var listed = routers
            .Where(r => r.Flags.Contains("Guard") && r.Flags.Contains("Running") && r.Flags.Contains("Valid"))
            .ToDictionary(r => Convert.ToHexString(r.RsaIdentityDigest));

        lock (_lock)
        {
            TopUp(listed.Values.ToList(), now);

            foreach (GuardEntry g in _guards)
            {
                if (!g.IsUsable(now)) continue;
                if (listed.TryGetValue(g.Fingerprint, out RouterStatusEntry? router))
                    return (g, router);
            }
            return null;
        }
    }

    public void MarkSuccess(GuardEntry guard, DateTimeOffset now)
    {
        lock (_lock)
        {
            guard.Reachable = true;
            guard.RetryAfter = null;
            Persist();
        }
    }

    public void MarkFailure(GuardEntry guard, DateTimeOffset now)
    {
        lock (_lock)
        {
            guard.Reachable = false;
            guard.RetryAfter = now + RetryBackoff;
            Persist();
        }
    }

    private void TopUp(List<RouterStatusEntry> candidates, DateTimeOffset now)
    {
        bool changed = false;
        var have = _guards.Select(g => g.Fingerprint).ToHashSet();

        while (_guards.Count < _targetCount)
        {
            var available = candidates
                .Where(c => !have.Contains(Convert.ToHexString(c.RsaIdentityDigest)) && !ConflictsGuardSubnet(c))
                .ToList();
            if (available.Count == 0) break;

            RouterStatusEntry picked = WeightedChoice(available);
            var entry = new GuardEntry
            {
                Fingerprint = Convert.ToHexString(picked.RsaIdentityDigest),
                Address = picked.Address.ToString(),
                AddedAt = now,
            };
            _guards.Add(entry);
            have.Add(entry.Fingerprint);
            changed = true;
        }

        if (changed) Persist();
    }

    private bool ConflictsGuardSubnet(RouterStatusEntry candidate)
    {
        foreach (GuardEntry g in _guards)
            if (IPAddress.TryParse(g.Address, out IPAddress? addr) && SameSlash16(candidate.Address, addr))
                return true;
        return false;
    }

    private RouterStatusEntry WeightedChoice(List<RouterStatusEntry> candidates)
    {
        ulong total = 0;
        foreach (RouterStatusEntry c in candidates) total += (ulong)Math.Max(c.Bandwidth, 1);
        ulong pick = _random.NextBelow(total);
        ulong acc = 0;
        foreach (RouterStatusEntry c in candidates)
        {
            acc += (ulong)Math.Max(c.Bandwidth, 1);
            if (pick < acc) return c;
        }
        return candidates[^1];
    }

    private static bool SameSlash16(IPAddress a, IPAddress b)
    {
        if (a.AddressFamily != AddressFamily.InterNetwork || b.AddressFamily != AddressFamily.InterNetwork)
            return false;
        byte[] x = a.GetAddressBytes(), y = b.GetAddressBytes();
        return x[0] == y[0] && x[1] == y[1];
    }

    private void Persist()
    {
        var sb = new StringBuilder();
        foreach (GuardEntry g in _guards)
        {
            sb.Append(g.Fingerprint).Append(',')
              .Append(g.Address).Append(',')
              .Append(g.AddedAt.ToUnixTimeSeconds()).Append(',')
              .Append(g.Reachable ? '1' : '0').Append(',')
              .Append(g.RetryAfter?.ToUnixTimeSeconds() ?? -1).Append('\n');
        }
        _store.Write(StoreKey, Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static List<GuardEntry> Load(IStateStore store)
    {
        var list = new List<GuardEntry>();
        byte[]? data = store.Read(StoreKey);
        if (data is null) return list;

        foreach (string line in Encoding.UTF8.GetString(data).Split('\n'))
        {
            if (line.Length == 0) continue;
            string[] p = line.Split(',');
            if (p.Length != 5) continue;
            if (!long.TryParse(p[2], CultureInfo.InvariantCulture, out long added)) continue;
            if (!long.TryParse(p[4], CultureInfo.InvariantCulture, out long retry)) continue;
            list.Add(new GuardEntry
            {
                Fingerprint = p[0],
                Address = p[1],
                AddedAt = DateTimeOffset.FromUnixTimeSeconds(added),
                Reachable = p[3] == "1",
                RetryAfter = retry < 0 ? null : DateTimeOffset.FromUnixTimeSeconds(retry),
            });
        }
        return list;
    }
}
