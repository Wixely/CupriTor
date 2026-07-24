using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriTor.OnionService;

/// <summary>
/// The hs-ntor handshake (rend-spec-v3 §3.3.2): the client↔service authenticated key exchange carried
/// through the introduction point. The client derives INTRODUCE1 encryption keys from the intro point's
/// Curve25519 encryption key; the service and client then derive the shared rendezvous NTOR_KEY_SEED and
/// an authentication tag. Curve25519 via BouncyCastle; SHA3-256 MAC and SHAKE-256 KDF.
/// </summary>
internal static class HsNtor
{
    private const string ProtoId = "tor-hs-ntor-curve25519-sha3-256-1";
    private static readonly byte[] THsEnc = Ascii(ProtoId + ":hs_key_extract");
    private static readonly byte[] THsVerify = Ascii(ProtoId + ":hs_verify");
    private static readonly byte[] THsMac = Ascii(ProtoId + ":hs_mac");
    private static readonly byte[] MHsExpand = Ascii(ProtoId + ":hs_key_expand");
    private static readonly byte[] ProtoIdBytes = Ascii(ProtoId);
    private static readonly byte[] ServerStr = Ascii("Server");

    private const int KeyLen = 32;   // AES-256 / Curve25519
    private const int MacKeyLen = 32;

    /// <summary>Client-side state carried from INTRODUCE1 to RENDEZVOUS2.</summary>
    internal sealed class ClientState
    {
        public required X25519PrivateKeyParameters Ephemeral { get; init; } // x
        public required byte[] ClientPublic { get; init; }                  // X
        public required byte[] IntroEncKey { get; init; }                   // B
        public required byte[] AuthKey { get; init; }                       // AUTH_KEY
        public required byte[] IntroEncryptKey { get; init; }               // ENC_KEY for INTRODUCE1
        public required byte[] IntroMacKey { get; init; }                   // MAC_KEY for INTRODUCE1
    }

    /// <summary>Client builds an ephemeral key and the INTRODUCE1 encryption keys.</summary>
    public static ClientState ClientIntroduce(byte[] introEncKey, byte[] authKey, byte[] subcredential, SecureRandom? random = null)
    {
        var x = new X25519PrivateKeyParameters(random ?? new SecureRandom());
        byte[] clientPub = x.GeneratePublicKey().GetEncoded();

        byte[] bx = Agree(x, introEncKey) ?? throw new InvalidOperationException("intro DH failed");
        byte[] introSecret = Concat(bx, authKey, clientPub, introEncKey, ProtoIdBytes);
        (byte[] enc, byte[] mac) = IntroKeys(introSecret, subcredential);

        return new ClientState
        {
            Ephemeral = x,
            ClientPublic = clientPub,
            IntroEncKey = introEncKey,
            AuthKey = authKey,
            IntroEncryptKey = enc,
            IntroMacKey = mac,
        };
    }

    /// <summary>Service recovers the INTRODUCE1 encryption keys from the client's public key.</summary>
    public static (byte[] EncKey, byte[] MacKey)? ServiceIntroduce(byte[] introEncPrivate, byte[] introEncKey, byte[] authKey, byte[] subcredential, byte[] clientPublic)
    {
        byte[]? xb = AgreeRaw(introEncPrivate, clientPublic);
        if (xb is null) return null;
        byte[] introSecret = Concat(xb, authKey, clientPublic, introEncKey, ProtoIdBytes);
        return IntroKeys(introSecret, subcredential);
    }

    /// <summary>Service completes the handshake: generates Y and returns the shared NTOR_KEY_SEED + auth tag.</summary>
    public static (byte[] ServicePublic, byte[] NtorKeySeed, byte[] Auth)? ServiceRendezvous(
        byte[] introEncPrivate, byte[] introEncKey, byte[] authKey, byte[] clientPublic, SecureRandom? random = null)
    {
        var y = new X25519PrivateKeyParameters(random ?? new SecureRandom());
        byte[] servicePub = y.GeneratePublicKey().GetEncoded();

        byte[]? xy = Agree(y, clientPublic);
        byte[]? xb = AgreeRaw(introEncPrivate, clientPublic);
        if (xy is null || xb is null) return null;

        byte[] rendSecret = Concat(xy, xb, authKey, introEncKey, clientPublic, servicePub, ProtoIdBytes);
        // MAC key is the secret input; the message is the t-string (tor's crypto_mac_sha3_256 order).
        byte[] ntorKeySeed = Mac256(rendSecret, THsEnc);
        byte[] verify = Mac256(rendSecret, THsVerify);
        byte[] auth = Mac256(Concat(verify, authKey, introEncKey, servicePub, clientPublic, ProtoIdBytes, ServerStr), THsMac);
        return (servicePub, ntorKeySeed, auth);
    }

    /// <summary>Client completes the handshake from RENDEZVOUS2, verifying the auth tag. Returns null on failure.</summary>
    public static byte[]? ClientRendezvous(ClientState state, byte[] servicePublic, byte[] receivedAuth)
    {
        byte[]? yx = Agree(state.Ephemeral, servicePublic);
        byte[]? bx = Agree(state.Ephemeral, state.IntroEncKey);
        if (yx is null || bx is null) return null;

        byte[] rendSecret = Concat(yx, bx, state.AuthKey, state.IntroEncKey, state.ClientPublic, servicePublic, ProtoIdBytes);
        // MAC key is the secret input; the message is the t-string (tor's crypto_mac_sha3_256 order).
        byte[] ntorKeySeed = Mac256(rendSecret, THsEnc);
        byte[] verify = Mac256(rendSecret, THsVerify);
        byte[] expectedAuth = Mac256(Concat(verify, state.AuthKey, state.IntroEncKey, servicePublic, state.ClientPublic, ProtoIdBytes, ServerStr), THsMac);

        return CryptographicOperations.FixedTimeEquals(expectedAuth, receivedAuth) ? ntorKeySeed : null;
    }

    /// <summary>Expand NTOR_KEY_SEED into rendezvous-circuit key material: SHAKE-256(seed ‖ m_hsexpand).</summary>
    public static byte[] DeriveKeys(byte[] ntorKeySeed, int length)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(ntorKeySeed, 0, ntorKeySeed.Length);
        shake.BlockUpdate(MHsExpand, 0, MHsExpand.Length);
        var outb = new byte[length];
        shake.OutputFinal(outb, 0, length);
        return outb;
    }

    /// <summary>The hs-ntor SHA3-256 MAC used for the INTRODUCE1 body: SHA3_256(INT_8(len(key)) ‖ key ‖ message).</summary>
    public static byte[] Mac256(byte[] key, byte[] message) => Mac(message, key);

    private static (byte[] Enc, byte[] Mac) IntroKeys(byte[] introSecret, byte[] subcredential)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(introSecret, 0, introSecret.Length);
        shake.BlockUpdate(THsEnc, 0, THsEnc.Length);
        shake.BlockUpdate(MHsExpand, 0, MHsExpand.Length);   // info = m_hsexpand | subcredential
        shake.BlockUpdate(subcredential, 0, subcredential.Length);
        var keys = new byte[KeyLen + MacKeyLen];
        shake.OutputFinal(keys, 0, keys.Length);
        return (keys[..KeyLen], keys[KeyLen..]);
    }

    // MAC(message, key) = SHA3-256( INT_8(len(key)) | key | message ).
    private static byte[] Mac(byte[] message, byte[] key)
    {
        var sha3 = new Sha3Digest(256);
        Span<byte> len = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(len, key.Length);
        sha3.BlockUpdate(len);
        sha3.BlockUpdate(key, 0, key.Length);
        sha3.BlockUpdate(message, 0, message.Length);
        var outb = new byte[32];
        sha3.DoFinal(outb, 0);
        return outb;
    }

    private static byte[]? Agree(X25519PrivateKeyParameters priv, byte[] peerPublic)
    {
        if (peerPublic.Length != KeyLen) return null;
        var agreement = new X25519Agreement();
        agreement.Init(priv);
        var shared = new byte[agreement.AgreementSize];
        try { agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublic, 0), shared, 0); }
        catch (Exception) { return null; }
        int acc = 0;
        foreach (byte b in shared) acc |= b;
        return acc == 0 ? null : shared;
    }

    private static byte[]? AgreeRaw(byte[] privateKey, byte[] peerPublic) =>
        Agree(new X25519PrivateKeyParameters(privateKey, 0), peerPublic);

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

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
