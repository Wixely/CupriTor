using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace CupriTor.Protocol;

/// <summary>
/// A continuous AES-128 counter-mode keystream (zero IV, big-endian 128-bit counter). Tor treats the
/// relay cipher as a pure stream cipher whose counter persists across cells, so this XORs data in
/// place and keeps partial-block state between calls.
/// </summary>
internal sealed class AesCtrKeystream
{
    private readonly AesEngine _engine = new();
    private readonly byte[] _counter = new byte[16];
    private readonly byte[] _block = new byte[16];
    private int _blockPos = 16; // force a fresh block on first byte

    public AesCtrKeystream(byte[] key, ReadOnlySpan<byte> iv = default)
    {
        _engine.Init(forEncryption: true, new KeyParameter(key));
        if (!iv.IsEmpty) iv.CopyTo(_counter); // initial counter (zero for relay cells; a derived IV for HS descriptors)
    }

    public void XorInPlace(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (_blockPos == 16)
            {
                _engine.ProcessBlock(_counter, 0, _block, 0);
                IncrementCounter();
                _blockPos = 0;
            }
            data[i] ^= _block[_blockPos++];
        }
    }

    private void IncrementCounter()
    {
        for (int i = 15; i >= 0; i--)
            if (++_counter[i] != 0) break;
    }
}

/// <summary>
/// Per-hop relay-cell cryptography (tor-spec §5.5): forward/backward AES-CTR layers and the running
/// integrity digests seeded by Df/Db. Two modes: the legacy ntor hop (72-byte material Df20‖Db20‖Kf16‖Kb16,
/// SHA-1 running digests, AES-128) used for normal circuit hops, and the v3 onion-service rendezvous hop
/// (128-byte material Df32‖Db32‖Kf32‖Kb32, SHA3-256 running digests, AES-256 — tor's
/// RELAY_CRYPTO_ALG_TOR1_HSC/HSS). The client holds one instance per hop; a relay/onion-service holds one per circuit.
/// </summary>
internal sealed class RelayCrypto
{
    public const int KeyMaterialLength = 20 + 20 + 16 + 16;      // legacy ntor: SHA-1 digests, AES-128
    public const int KeyMaterialLengthV3Hs = 32 + 32 + 32 + 32;  // v3 HS rendezvous: SHA3-256 digests, AES-256

    private readonly AesCtrKeystream _forward;
    private readonly AesCtrKeystream _backward;
    private readonly IDigest _forwardDigest;
    private readonly IDigest _backwardDigest;

    /// <summary>Legacy ntor circuit hop (SHA-1 running digests, AES-128, 72-byte key material).</summary>
    public RelayCrypto(ReadOnlySpan<byte> keyMaterial)
        : this(keyMaterial, digestSeedLength: 20, keyLength: 16, useSha3: false) { }

    /// <summary>v3 onion-service rendezvous hop (SHA3-256 running digests, AES-256, 128-byte key material).</summary>
    public static RelayCrypto CreateV3Hs(ReadOnlySpan<byte> keyMaterial) =>
        new(keyMaterial, digestSeedLength: 32, keyLength: 32, useSha3: true);

    private RelayCrypto(ReadOnlySpan<byte> keyMaterial, int digestSeedLength, int keyLength, bool useSha3)
    {
        int need = digestSeedLength * 2 + keyLength * 2;
        if (keyMaterial.Length < need)
            throw new ArgumentException($"Need {need} bytes of key material.", nameof(keyMaterial));

        byte[] df = keyMaterial[..digestSeedLength].ToArray();
        byte[] db = keyMaterial[digestSeedLength..(2 * digestSeedLength)].ToArray();
        int k = 2 * digestSeedLength;
        _forward = new AesCtrKeystream(keyMaterial[k..(k + keyLength)].ToArray());       // AES-128 or AES-256 by key length
        _backward = new AesCtrKeystream(keyMaterial[(k + keyLength)..(k + 2 * keyLength)].ToArray());

        _forwardDigest = useSha3 ? new Sha3Digest(256) : new Sha1Digest();
        _backwardDigest = useSha3 ? new Sha3Digest(256) : new Sha1Digest();
        _forwardDigest.BlockUpdate(df, 0, df.Length);
        _backwardDigest.BlockUpdate(db, 0, db.Length);
    }

    /// <summary>Apply/remove one forward (client→relay) crypto layer in place. Encryption and decryption are identical.</summary>
    public void CryptForward(Span<byte> cell) => _forward.XorInPlace(cell);

    /// <summary>Apply/remove one backward (relay→client) crypto layer in place.</summary>
    public void CryptBackward(Span<byte> cell) => _backward.XorInPlace(cell);

    /// <summary>Advance the forward running digest with a cell (digest field must be zeroed) and return its first 4 bytes.</summary>
    public byte[] ForwardDigest(ReadOnlySpan<byte> cellWithZeroedDigest) => Digest(_forwardDigest, cellWithZeroedDigest);

    /// <summary>Advance the backward running digest with a cell (digest field must be zeroed) and return its first 4 bytes.</summary>
    public byte[] BackwardDigest(ReadOnlySpan<byte> cellWithZeroedDigest) => Digest(_backwardDigest, cellWithZeroedDigest);

    private static byte[] Digest(IDigest running, ReadOnlySpan<byte> cell)
    {
        running.BlockUpdate(cell);                          // advance the persistent running hash
        var snapshot = (IDigest)((IMemoable)running).Copy(); // finalize a copy so the running state continues
        var full = new byte[snapshot.GetDigestSize()];
        snapshot.DoFinal(full, 0);
        return full[..4];
    }
}
