using System.Net;
using System.Net.Sockets;
using CupriTor.Directory;

namespace CupriTor.Protocol;

/// <summary>
/// Bandwidth-weighted circuit path selection (path-spec) honouring the anonymity constraints: every
/// relay must be Running and Valid, each hop's required flags must be present (e.g. Guard for the
/// entry), and no two hops may share a /16 subnet. Relay-<b>family</b> distinctness is enforced by
/// <see cref="TorNetwork"/> <i>after</i> selection (it needs each hop's microdescriptor family list, which
/// isn't available at selection time), reselecting on a conflict. Exit selection also layers on top of this.
/// </summary>
internal static class PathSelector
{
    private static readonly string[] BaseFlags = { "Running", "Valid" };

    /// <summary>
    /// Select one distinct relay per hop. <paramref name="requiredFlagsPerHop"/> gives the flags each
    /// position needs on top of the base flags. <paramref name="family"/>, if supplied, maps a relay to
    /// its family identifiers for the distinct-family constraint. Returns false if any hop has no candidate.
    /// </summary>
    public static bool TrySelect(
        IReadOnlyList<RouterStatusEntry> routers,
        IReadOnlyList<IReadOnlyCollection<string>> requiredFlagsPerHop,
        IRandomSource random,
        out RouterStatusEntry[] path,
        Func<RouterStatusEntry, IReadOnlySet<string>>? family = null) =>
        TryExtendPath(routers, Array.Empty<RouterStatusEntry>(), requiredFlagsPerHop, random, out path, family);

    /// <summary>
    /// Select the remaining hops of a path whose first hops are already chosen (e.g. a fixed entry guard),
    /// honouring the same distinct-relay, /16 and family constraints against the pre-chosen hops. The
    /// returned path is <paramref name="prechosen"/> followed by one relay per entry in
    /// <paramref name="requiredFlagsPerHop"/>.
    /// </summary>
    public static bool TryExtendPath(
        IReadOnlyList<RouterStatusEntry> routers,
        IReadOnlyList<RouterStatusEntry> prechosen,
        IReadOnlyList<IReadOnlyCollection<string>> requiredFlagsPerHop,
        IRandomSource random,
        out RouterStatusEntry[] path,
        Func<RouterStatusEntry, IReadOnlySet<string>>? family = null)
    {
        var chosen = new List<RouterStatusEntry>(prechosen.Count + requiredFlagsPerHop.Count);
        chosen.AddRange(prechosen);

        foreach (IReadOnlyCollection<string> required in requiredFlagsPerHop)
        {
            var candidates = new List<RouterStatusEntry>();
            foreach (RouterStatusEntry r in routers)
            {
                if (!HasFlags(r, BaseFlags) || !HasFlags(r, required)) continue;
                if (chosen.Contains(r)) continue;
                if (ConflictsSubnet(r, chosen)) continue;
                if (family is not null && ConflictsFamily(r, chosen, family)) continue;
                candidates.Add(r);
            }

            if (candidates.Count == 0)
            {
                path = Array.Empty<RouterStatusEntry>();
                return false;
            }

            chosen.Add(PickWeighted(candidates, random));
        }

        path = chosen.ToArray();
        return true;
    }

    private static bool HasFlags(RouterStatusEntry r, IEnumerable<string> flags)
    {
        foreach (string f in flags)
            if (!r.Flags.Contains(f)) return false;
        return true;
    }

    private static bool ConflictsSubnet(RouterStatusEntry r, List<RouterStatusEntry> chosen)
    {
        foreach (RouterStatusEntry c in chosen)
            if (SameSlash16(r.Address, c.Address)) return true;
        return false;
    }

    internal static bool SameSlash16(IPAddress a, IPAddress b)
    {
        if (a.AddressFamily != AddressFamily.InterNetwork || b.AddressFamily != AddressFamily.InterNetwork)
            return false;
        byte[] x = a.GetAddressBytes(), y = b.GetAddressBytes();
        return x[0] == y[0] && x[1] == y[1];
    }

    private static bool ConflictsFamily(RouterStatusEntry r, List<RouterStatusEntry> chosen,
        Func<RouterStatusEntry, IReadOnlySet<string>> family)
    {
        IReadOnlySet<string> fr = family(r);
        if (fr.Count == 0) return false;
        foreach (RouterStatusEntry c in chosen)
            if (family(c).Overlaps(fr)) return true;
        return false;
    }

    internal static RouterStatusEntry PickWeighted(IReadOnlyList<RouterStatusEntry> candidates, IRandomSource random)
    {
        ulong total = 0;
        foreach (RouterStatusEntry c in candidates) total += Weight(c);

        ulong pick = random.NextBelow(total);
        ulong acc = 0;
        foreach (RouterStatusEntry c in candidates)
        {
            acc += Weight(c);
            if (pick < acc) return c;
        }
        return candidates[^1];
    }

    private static ulong Weight(RouterStatusEntry r) => (ulong)Math.Max(r.Bandwidth, 1);
}
