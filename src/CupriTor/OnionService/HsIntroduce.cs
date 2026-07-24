using System.Security.Cryptography;
using CupriTor.Protocol;

namespace CupriTor.OnionService;

/// <summary>The decrypted contents of an INTRODUCE1/INTRODUCE2 cell: what the service needs to reach the rendezvous point.</summary>
internal sealed record IntroduceRequest(byte[] ClientPublic, byte[] RendezvousCookie, byte[] RendezvousNtorKey, List<LinkSpecifier> RendezvousLinkSpecifiers);

/// <summary>
/// INTRODUCE1 body construction and parsing (rend-spec-v3 §3.3): the ed25519-auth-key header followed by
/// the hs-ntor ENCRYPTED blob = CLIENT_PK ‖ AES-256-CTR(ENC_KEY, plaintext) ‖ MAC(MAC_KEY, cell-minus-MAC).
/// The plaintext carries the rendezvous cookie, the rendezvous point's ntor key, and its link specifiers.
/// Both directions live here so the client build path is cross-checked by the service open path in tests
/// (and reused by the future service side).
/// </summary>
internal static class HsIntroduce
{
    private const int MacLength = 32;
    private const int ClientPkLength = 32;

    /// <summary>Client: build an INTRODUCE1 payload for the given hs-ntor state and rendezvous point.</summary>
    public static byte[] Build(HsNtor.ClientState hs, byte[] authKey, byte[] cookie, byte[] rendezvousNtorKey, byte[] rendezvousLinkSpecifiers)
    {
        var plaintext = new List<byte>();
        plaintext.AddRange(cookie);                 // RENDEZVOUS_COOKIE (20)
        plaintext.Add(0);                            // N_EXTENSIONS = 0
        plaintext.Add(0x01);                         // ONION_KEY_TYPE = ntor
        plaintext.Add(0x00); plaintext.Add(0x20);    // ONION_KEY_LEN = 32
        plaintext.AddRange(rendezvousNtorKey);       // RP ntor onion key (32)
        plaintext.AddRange(rendezvousLinkSpecifiers);// NSPEC ‖ RP link specifiers
        byte[] encData = plaintext.ToArray();
        new AesCtrKeystream(hs.IntroEncryptKey).XorInPlace(encData);

        byte[] encrypted = Concat(hs.ClientPublic, encData, new byte[MacLength]); // MAC filled in below
        byte[] cell = HsCells.BuildIntroduce(authKey, encrypted);

        // MAC covers the whole cell up to (not including) the trailing MAC field.
        byte[] mac = HsNtor.Mac256(hs.IntroMacKey, cell[..^MacLength]);
        mac.CopyTo(cell, cell.Length - MacLength);
        return cell;
    }

    /// <summary>
    /// Service: parse and decrypt an INTRODUCE1/INTRODUCE2 cell with the intro point's private encryption
    /// key, verifying the hs-ntor MAC. Returns false on malformed input or MAC failure.
    /// </summary>
    public static bool TryOpen(byte[] cell, byte[] introEncPrivate, byte[] introEncPublic, byte[] subcredential, out IntroduceRequest request)
    {
        request = null!;
        if (!HsCells.TryParseIntroduce(cell, out byte[] authKey, out byte[] encrypted)) return false;
        if (encrypted.Length < ClientPkLength + MacLength) return false;

        byte[] clientPublic = encrypted[..ClientPkLength];
        byte[] receivedMac = encrypted[^MacLength..];
        byte[] encData = encrypted[ClientPkLength..^MacLength];

        (byte[] EncKey, byte[] MacKey)? keys = HsNtor.ServiceIntroduce(introEncPrivate, introEncPublic, authKey, subcredential, clientPublic);
        if (keys is null) return false;

        byte[] expectedMac = HsNtor.Mac256(keys.Value.MacKey, cell[..^MacLength]);
        if (!CryptographicOperations.FixedTimeEquals(expectedMac, receivedMac)) return false;

        byte[] plaintext = (byte[])encData.Clone();
        new AesCtrKeystream(keys.Value.EncKey).XorInPlace(plaintext);

        if (!TryParsePlaintext(plaintext, out byte[] cookie, out byte[] rpNtorKey, out List<LinkSpecifier> rpSpecs)) return false;
        request = new IntroduceRequest(clientPublic, cookie, rpNtorKey, rpSpecs);
        return true;
    }

    private static bool TryParsePlaintext(ReadOnlySpan<byte> plaintext, out byte[] cookie, out byte[] rpNtorKey, out List<LinkSpecifier> rpSpecs)
    {
        cookie = Array.Empty<byte>();
        rpNtorKey = Array.Empty<byte>();
        rpSpecs = new List<LinkSpecifier>();

        int pos = 0;
        if (plaintext.Length < 20 + 1 + 1 + 2 + 32) return false;
        cookie = plaintext.Slice(0, 20).ToArray();
        pos += 20;

        int extensions = plaintext[pos++];
        for (int i = 0; i < extensions; i++)
        {
            if (pos + 2 > plaintext.Length) return false;
            int extLen = plaintext[pos + 1];
            pos += 2 + extLen;
        }
        if (pos + 4 + 32 > plaintext.Length) return false;

        if (plaintext[pos++] != 0x01) return false;        // ONION_KEY_TYPE = ntor
        int keyLen = (plaintext[pos] << 8) | plaintext[pos + 1];
        pos += 2;
        if (keyLen != 32 || pos + 32 > plaintext.Length) return false;
        rpNtorKey = plaintext.Slice(pos, 32).ToArray();
        pos += 32;

        return LinkSpecifier.TryParseList(plaintext.Slice(pos), out rpSpecs);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts) total += p.Length;
        var result = new byte[total];
        int pos = 0;
        foreach (byte[] p in parts) { p.CopyTo(result, pos); pos += p.Length; }
        return result;
    }
}
