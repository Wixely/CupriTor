using System.Security.Cryptography;

namespace CupriTor.Directory;

/// <summary>
/// A Tor microdescriptor (dir-spec §3.10): the per-relay data referenced by a microdesc-flavour
/// consensus. Carries the relay's ntor onion key and Ed25519 identity — the latter is what the link
/// handshake validates against.
/// </summary>
internal sealed class Microdescriptor
{
    public byte[]? RsaOnionKeyDer { get; private init; }
    public byte[] NtorOnionKey { get; private init; } = Array.Empty<byte>();
    public byte[]? Ed25519Identity { get; private init; }

    /// <summary>The relay's IPv4 exit-policy summary (the "p" line). Rejects everything when the line is absent.</summary>
    public ExitPolicySummary ExitPolicyIPv4 { get; private init; } = ExitPolicySummary.RejectAll;

    /// <summary>The relay's IPv6 exit-policy summary (the "p6" line). Rejects everything when the line is absent.</summary>
    public ExitPolicySummary ExitPolicyIPv6 { get; private init; } = ExitPolicySummary.RejectAll;

    private static readonly IReadOnlySet<string> EmptyFamily = new HashSet<string>();

    /// <summary>
    /// The relay's declared family (the "family" line), normalized for matching: "$UPPERCASEHEX" for identity
    /// fingerprints (any "=name"/"~name" suffix stripped) and lowercase for nicknames. Empty when no line is present.
    /// </summary>
    public IReadOnlySet<string> Family { get; private init; } = EmptyFamily;

    /// <summary>Normalize a family token to its canonical match form: "$UPPERHEX" fingerprint or a lowercase nickname.</summary>
    internal static string NormalizeFamilyToken(string token)
    {
        if (token.StartsWith('$'))
        {
            string hex = token[1..];
            int sep = hex.IndexOfAny(new[] { '=', '~' }); // "$HEX=name" / "$HEX~name"
            if (sep >= 0) hex = hex[..sep];
            return "$" + hex.ToUpperInvariant();
        }
        return token.ToLowerInvariant();
    }

    /// <summary>SHA-256 of the microdescriptor's exact bytes — the digest a consensus "m" line references.</summary>
    public static byte[] ComputeDigest(ReadOnlySpan<byte> microdescriptorBytes) => SHA256.HashData(microdescriptorBytes);

    public static bool TryParse(string text, out Microdescriptor microdescriptor)
    {
        microdescriptor = null!;
        try
        {
            List<DirectoryItem> items = DirectoryReader.Parse(text);

            byte[]? rsaOnion = null;
            byte[]? ntor = null;
            byte[]? ed = null;
            ExitPolicySummary policy = ExitPolicySummary.RejectAll;
            ExitPolicySummary policyV6 = ExitPolicySummary.RejectAll;
            HashSet<string>? family = null;

            foreach (DirectoryItem item in items)
            {
                switch (item.Keyword)
                {
                    case "family":
                        family ??= new HashSet<string>();
                        foreach (string tok in item.Arguments) family.Add(NormalizeFamilyToken(tok));
                        break;
                    case "onion-key":
                        rsaOnion = item.ObjectData;
                        break;
                    case "ntor-onion-key":
                        if (item.Arguments.Length < 1) return false;
                        ntor = DirectoryReader.Base64(item.Arguments[0]);
                        break;
                    case "id":
                        if (item.Arguments.Length >= 2 && item.Arguments[0] == "ed25519")
                            ed = DirectoryReader.Base64(item.Arguments[1]);
                        break;
                    case "p": // IPv4 exit-policy summary
                        if (item.Arguments.Length >= 2)
                            policy = ExitPolicySummary.Parse(item.Arguments[0], item.Arguments[1]);
                        break;
                    case "p6": // IPv6 exit-policy summary
                        if (item.Arguments.Length >= 2)
                            policyV6 = ExitPolicySummary.Parse(item.Arguments[0], item.Arguments[1]);
                        break;
                }
            }

            if (ntor is not { Length: 32 }) return false;
            if (ed is not null && ed.Length != 32) return false;

            microdescriptor = new Microdescriptor
            {
                RsaOnionKeyDer = rsaOnion,
                NtorOnionKey = ntor,
                Ed25519Identity = ed,
                ExitPolicyIPv4 = policy,
                ExitPolicyIPv6 = policyV6,
                Family = family ?? EmptyFamily,
            };
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException or OverflowException or IndexOutOfRangeException or ArgumentException)
        {
            return false;
        }
    }
}
