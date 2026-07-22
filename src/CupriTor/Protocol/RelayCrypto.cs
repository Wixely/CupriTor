using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

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

    public AesCtrKeystream(byte[] key)
    {
        _engine.Init(forEncryption: true, new KeyParameter(key));
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
/// Per-hop relay-cell cryptography (tor-spec §5.5): forward/backward AES-128-CTR layers and the
/// running SHA-1 integrity digests seeded by Df/Db. Key material is the 72-byte ntor output
/// (Df‖Db‖Kf‖Kb). The client holds one instance per hop; a relay/onion-service holds one per circuit.
/// </summary>
internal sealed class RelayCrypto
{
    public const int KeyMaterialLength = 20 + 20 + 16 + 16; // Df, Db, Kf, Kb

    private readonly AesCtrKeystream _forward;
    private readonly AesCtrKeystream _backward;
    private readonly Sha1Digest _forwardDigest = new();
    private readonly Sha1Digest _backwardDigest = new();

    public RelayCrypto(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length < KeyMaterialLength)
            throw new ArgumentException($"Need {KeyMaterialLength} bytes of key material.", nameof(keyMaterial));

        byte[] df = keyMaterial[..20].ToArray();
        byte[] db = keyMaterial[20..40].ToArray();
        _forward = new AesCtrKeystream(keyMaterial[40..56].ToArray());
        _backward = new AesCtrKeystream(keyMaterial[56..72].ToArray());

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

    private static byte[] Digest(Sha1Digest running, ReadOnlySpan<byte> cell)
    {
        running.BlockUpdate(cell);                 // advance the persistent running hash
        var snapshot = new Sha1Digest(running);    // finalize a copy so the running state continues
        var full = new byte[snapshot.GetDigestSize()];
        snapshot.DoFinal(full, 0);
        return full[..4];
    }
}
