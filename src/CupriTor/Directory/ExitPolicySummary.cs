using System.Globalization;

namespace CupriTor.Directory;

/// <summary>
/// A relay's exit-policy summary (dir-spec, the microdescriptor "p"/"p6" line): a verb ("accept" or "reject")
/// and a port list. <c>accept</c> lists the permitted ports (all others denied); <c>reject</c> lists the denied
/// ports (all others permitted). This is a port-only summary "for most addresses" — the exit may still reject a
/// specific IP at connect time (surfaced as RELAY_END). A relay that publishes no summary rejects everything.
/// </summary>
internal sealed class ExitPolicySummary
{
    private readonly bool _accept;
    private readonly (int Lo, int Hi)[] _ranges;

    private ExitPolicySummary(bool accept, (int Lo, int Hi)[] ranges)
    {
        _accept = accept;
        _ranges = ranges;
    }

    /// <summary>Rejects every port — the default when a relay publishes no exit-policy summary.</summary>
    public static ExitPolicySummary RejectAll { get; } = new(accept: true, Array.Empty<(int, int)>());

    /// <summary>True if this exit permits connections to <paramref name="port"/>.</summary>
    public bool Allows(int port)
    {
        bool listed = false;
        foreach ((int lo, int hi) in _ranges)
            if (port >= lo && port <= hi) { listed = true; break; }
        return _accept ? listed : !listed;
    }

    /// <summary>Parse a summary from its verb ("accept"/"reject") and PortList ("80,443,600-700").</summary>
    public static ExitPolicySummary Parse(string verb, string portList)
    {
        bool accept = verb switch
        {
            "accept" => true,
            "reject" => false,
            _ => throw new FormatException($"Exit policy verb must be 'accept' or 'reject', got '{verb}'."),
        };

        var ranges = new List<(int, int)>();
        foreach (string part in portList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int dash = part.IndexOf('-');
            if (dash < 0)
            {
                int p = int.Parse(part, CultureInfo.InvariantCulture);
                ranges.Add((p, p));
            }
            else
            {
                int lo = int.Parse(part[..dash], CultureInfo.InvariantCulture);
                int hi = int.Parse(part[(dash + 1)..], CultureInfo.InvariantCulture);
                ranges.Add((Math.Min(lo, hi), Math.Max(lo, hi)));
            }
        }
        return new ExitPolicySummary(accept, ranges.ToArray());
    }
}
