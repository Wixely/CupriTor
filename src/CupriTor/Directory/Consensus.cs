using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace CupriTor.Directory;

/// <summary>A relay's entry in a microdesc-flavour consensus (dir-spec §3.4.1).</summary>
internal sealed class RouterStatusEntry
{
    public string Nickname { get; set; } = "";
    public byte[] RsaIdentityDigest { get; set; } = Array.Empty<byte>(); // 20-byte SHA-1 fingerprint
    public DateTimeOffset Published { get; set; }
    public IPAddress Address { get; set; } = IPAddress.None;
    public int OrPort { get; set; }
    public int DirPort { get; set; }
    public List<IPEndPoint> ExtraOrAddresses { get; } = new();
    public HashSet<string> Flags { get; } = new(StringComparer.Ordinal);
    public string? Version { get; set; }
    public long Bandwidth { get; set; } = -1;
    public byte[]? MicrodescriptorSha256 { get; set; } // the "m" line digest
}

/// <summary>An authority signature line from a consensus footer.</summary>
internal sealed record DirectorySignature(
    string Algorithm,
    byte[] IdentityFingerprint,
    byte[] SigningKeyDigest,
    byte[] Signature);

/// <summary>
/// A parsed microdesc-flavour network-status consensus (dir-spec §3.4.1). Parsing is structural and
/// strict; authority-signature verification against the directory authorities is a separate step
/// that consumes <see cref="SignedBody"/> and <see cref="Signatures"/>.
/// </summary>
internal sealed class Consensus
{
    private const int MinConsensusMethod = 26; // reject ancient-format consensuses; current network is 30+

    public int ConsensusMethod { get; private set; }
    public DateTimeOffset ValidAfter { get; private set; }
    public DateTimeOffset FreshUntil { get; private set; }
    public DateTimeOffset ValidUntil { get; private set; }
    public HashSet<string> KnownFlags { get; } = new(StringComparer.Ordinal);
    public byte[]? SharedRandomCurrentValue { get; private set; }
    public byte[]? SharedRandomPreviousValue { get; private set; }
    public List<RouterStatusEntry> Routers { get; } = new();
    public List<DirectorySignature> Signatures { get; } = new();

    /// <summary>The exact bytes the authority signatures cover (start of document through "directory-signature ").</summary>
    public byte[] SignedBody { get; private set; } = Array.Empty<byte>();

    public byte[] SignedBodySha1 => SHA1.HashData(SignedBody);
    public byte[] SignedBodySha256 => SHA256.HashData(SignedBody);

    public bool IsValidAt(DateTimeOffset now) => now >= ValidAfter && now < ValidUntil;

    public static bool TryParse(string text, out Consensus consensus)
    {
        consensus = null!;
        try
        {
            consensus = ParseInternal(text);
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException or OverflowException or IndexOutOfRangeException or ArgumentException)
        {
            consensus = null!;
            return false;
        }
    }

    private static Consensus ParseInternal(string text)
    {
        var c = new Consensus();
        c.SignedBody = ExtractSignedBody(text);
        List<DirectoryItem> items = DirectoryReader.Parse(text);

        RouterStatusEntry? current = null;
        void Flush() { if (current is not null) { c.Routers.Add(current); current = null; } }

        foreach (DirectoryItem item in items)
        {
            string[] a = item.Arguments;
            switch (item.Keyword)
            {
                case "network-status-version":
                    if (a.Length < 2 || a[0] != "3" || a[1] != "microdesc")
                        throw new DirectoryParseException("Not a version-3 microdesc consensus.");
                    break;
                case "vote-status":
                    if (a.Length < 1 || a[0] != "consensus")
                        throw new DirectoryParseException("Document is not a consensus.");
                    break;
                case "consensus-method":
                    if (a.Length < 1) throw new DirectoryParseException("consensus-method has no argument.");
                    c.ConsensusMethod = int.Parse(a[0], CultureInfo.InvariantCulture);
                    break;
                case "valid-after":
                    c.ValidAfter = ParseTime(a);
                    break;
                case "fresh-until":
                    c.FreshUntil = ParseTime(a);
                    break;
                case "valid-until":
                    c.ValidUntil = ParseTime(a);
                    break;
                case "known-flags":
                    foreach (string f in a) c.KnownFlags.Add(f);
                    break;
                case "shared-rand-current-value":
                    if (a.Length >= 2) c.SharedRandomCurrentValue = DirectoryReader.Base64(a[1]);
                    break;
                case "shared-rand-previous-value":
                    if (a.Length >= 2) c.SharedRandomPreviousValue = DirectoryReader.Base64(a[1]);
                    break;
                case "r":
                    Flush();
                    current = ParseRouterLine(a);
                    break;
                case "a":
                    if (current is not null && a.Length >= 1) current.ExtraOrAddresses.Add(IPEndPoint.Parse(a[0]));
                    break;
                case "s":
                    if (current is not null) foreach (string f in a) current.Flags.Add(f);
                    break;
                case "v":
                    if (current is not null) current.Version = string.Join(' ', a);
                    break;
                case "w":
                    if (current is not null) current.Bandwidth = ParseBandwidth(a);
                    break;
                case "m":
                    if (current is not null && a.Length >= 1) current.MicrodescriptorSha256 = DirectoryReader.Base64(a[0]);
                    break;
                case "directory-footer":
                    Flush();
                    break;
                case "directory-signature":
                    c.Signatures.Add(ParseSignature(item));
                    break;
            }
        }
        Flush();

        if (c.ValidAfter == default || c.ValidUntil == default)
            throw new DirectoryParseException("Consensus is missing validity times.");
        if (c.ConsensusMethod < MinConsensusMethod)
            throw new DirectoryParseException($"Consensus method {c.ConsensusMethod} is below the minimum supported ({MinConsensusMethod}).");
        return c;
    }

    private static RouterStatusEntry ParseRouterLine(string[] a)
    {
        // r nickname base64-identity published-date published-time IP ORPort DirPort
        if (a.Length < 7)
            throw new DirectoryParseException("Malformed 'r' line.");
        return new RouterStatusEntry
        {
            Nickname = a[0],
            RsaIdentityDigest = DirectoryReader.Base64(a[1]),
            Published = ParseTime(new[] { a[2], a[3] }),
            Address = IPAddress.Parse(a[4]),
            OrPort = int.Parse(a[5], CultureInfo.InvariantCulture),
            DirPort = int.Parse(a[6], CultureInfo.InvariantCulture),
        };
    }

    private static long ParseBandwidth(string[] a)
    {
        foreach (string kv in a)
        {
            if (kv.StartsWith("Bandwidth=", StringComparison.Ordinal))
                return long.Parse(kv.AsSpan("Bandwidth=".Length), CultureInfo.InvariantCulture);
        }
        return -1;
    }

    private static DirectorySignature ParseSignature(DirectoryItem item)
    {
        string[] a = item.Arguments;
        string algorithm;
        byte[] identity, signingKey;
        if (a.Length >= 3)
        {
            algorithm = a[0];
            identity = Convert.FromHexString(a[1]);
            signingKey = Convert.FromHexString(a[2]);
        }
        else if (a.Length == 2)
        {
            algorithm = "sha1";
            identity = Convert.FromHexString(a[0]);
            signingKey = Convert.FromHexString(a[1]);
        }
        else
        {
            throw new DirectoryParseException("Malformed 'directory-signature' line.");
        }

        return new DirectorySignature(algorithm, identity, signingKey,
            item.ObjectData ?? throw new DirectoryParseException("directory-signature has no signature object."));
    }

    private static DateTimeOffset ParseTime(string[] a)
    {
        if (a.Length < 2) throw new DirectoryParseException("Malformed timestamp.");
        return DateTimeOffset.ParseExact($"{a[0]} {a[1]}", "yyyy-MM-dd HH:mm:ss",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    }

    private static byte[] ExtractSignedBody(string text)
    {
        const string token = "directory-signature ";
        int idx = text.IndexOf("\n" + token, StringComparison.Ordinal);
        if (idx < 0)
            throw new DirectoryParseException("Consensus has no directory-signature.");
        int end = idx + 1 + token.Length; // include the newline offset (+1) and the token itself
        return Encoding.ASCII.GetBytes(text.Substring(0, end));
    }
}
