using System.Text;
using CupriCurve;

namespace CupriTor.OnionService;

/// <summary>
/// The ESTABLISH_INTRO cell (rend-spec-v3 §3.1), sent by a service over a circuit to a relay to make it an
/// introduction point. Body: AUTH_KEY_TYPE(1)=ed25519 ‖ AUTH_KEY_LEN(2) ‖ AUTH_KEY(32) ‖ N_EXTENSIONS(1) ‖
/// HANDSHAKE_AUTH(32) ‖ SIG_LEN(2) ‖ SIG(64). The HANDSHAKE_AUTH MAC is keyed by the circuit's KH; the
/// Ed25519 signature (by the intro auth key) covers the "Tor establish-intro cell v1" prefix plus everything
/// through HANDSHAKE_AUTH.
/// </summary>
internal static class HsEstablishIntro
{
    private const byte AuthKeyTypeEd25519 = 0x02;
    private static readonly byte[] SigPrefix = Encoding.ASCII.GetBytes("Tor establish-intro cell v1");

    /// <summary>Build a signed ESTABLISH_INTRO cell for <paramref name="authKeyPublic"/>, MACed with the circuit's KH.</summary>
    public static byte[] Build(ReadOnlySpan<byte> authKeyPublic, Ed25519ExpandedKey authKeySigner, ReadOnlySpan<byte> kh)
    {
        // Region the MAC covers: AUTH_KEY_TYPE ‖ AUTH_KEY_LEN ‖ AUTH_KEY ‖ N_EXTENSIONS (everything before HANDSHAKE_AUTH).
        var pre = new List<byte>(1 + 2 + 32 + 1) { AuthKeyTypeEd25519, 0x00, 0x20 };
        pre.AddRange(authKeyPublic.ToArray());
        pre.Add(0x00); // N_EXTENSIONS = 0
        byte[] preArr = pre.ToArray();

        // HANDSHAKE_AUTH = crypto_mac_sha3_256(key = KH[20], msg = preArr).
        byte[] handshakeAuth = HsNtor.Mac256(kh.ToArray(), preArr);

        // SIG covers the prefix string ‖ (preArr ‖ HANDSHAKE_AUTH); it does NOT cover SIG_LEN/SIG.
        byte[] signedRegion = Concat(preArr, handshakeAuth);
        byte[] toSign = Concat(SigPrefix, signedRegion);
        var sig = new byte[Ed25519.SignatureSize];
        Ed25519.SignWithExpandedKey(authKeySigner, authKeyPublic, toSign, sig);

        var cell = new byte[preArr.Length + 32 + 2 + 64];
        int pos = 0;
        preArr.CopyTo(cell, pos); pos += preArr.Length;
        handshakeAuth.CopyTo(cell, pos); pos += 32;
        cell[pos++] = 0x00; cell[pos++] = 0x40; // SIG_LEN = 64
        sig.CopyTo(cell, pos);
        return cell;
    }

    /// <summary>
    /// Parse an INTRO_ESTABLISHED cell body. Any well-formed body (empty, or an extension list) means the intro
    /// point accepted us — tor's parser simply reads and discards the extensions.
    /// </summary>
    public static bool ParseEstablished(ReadOnlySpan<byte> body)
    {
        if (body.Length == 0) return true;
        int n = body[0];
        int pos = 1;
        for (int i = 0; i < n; i++)
        {
            if (pos + 2 > body.Length) return false;
            int len = body[pos + 1];
            pos += 2 + len;
            if (pos > body.Length) return false;
        }
        return true;
    }

    internal static byte[] SigPrefixBytes => SigPrefix;

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }
}
