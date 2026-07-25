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

            foreach (DirectoryItem item in items)
            {
                switch (item.Keyword)
                {
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
            };
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException)
        {
            return false;
        }
    }
}
