using System.Text;
using CupriTor.Internal;
using CupriCurve;
using Org.BouncyCastle.Crypto.Digests;

namespace CupriTor;

/// <summary>
/// Thrown when a string is not a valid v3 <c>.onion</c> address (bad length, version, checksum, or key). Derives
/// from <see cref="ArgumentException"/> so existing <c>catch (ArgumentException)</c> handlers still catch it.
/// </summary>
public sealed class InvalidOnionAddressException(string onion)
    : ArgumentException($"Not a valid v3 .onion address: {onion}", "onion")
{
    /// <summary>The offending input string.</summary>
    public string Onion { get; } = onion;
}

/// <summary>
/// A Tor v3 onion service address. The wire form is
/// <c>base32(PUBKEY ‖ CHECKSUM ‖ VERSION) + ".onion"</c> where PUBKEY is a 32-byte Ed25519 public
/// key, VERSION is 0x03, and CHECKSUM is the first two bytes of
/// <c>SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)</c> (rend-spec-v3 §6).
/// </summary>
public readonly struct OnionAddress : IEquatable<OnionAddress>
{
    /// <summary>Length of the Ed25519 identity public key, in bytes.</summary>
    public const int PublicKeyLength = 32;

    /// <summary>The v3 address version byte.</summary>
    public const byte Version = 0x03;

    private const int EncodedByteLength = PublicKeyLength + 2 + 1; // pubkey + checksum + version = 35
    private const int Base32Length = 56;                          // ceil(35*8/5)
    private static readonly byte[] ChecksumPrefix = Encoding.ASCII.GetBytes(".onion checksum");

    private readonly byte[] _publicKey;

    private OnionAddress(byte[] publicKey) => _publicKey = publicKey;

    /// <summary>The 32-byte Ed25519 identity public key this address encodes.</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    /// <summary>True if this address has been initialized (parsed or constructed).</summary>
    public bool IsValid => _publicKey is { Length: PublicKeyLength };

    /// <summary>
    /// Build an address from a 32-byte Ed25519 public key. The key must be a valid curve point.
    /// </summary>
    public static OnionAddress FromPublicKey(ReadOnlySpan<byte> publicKey32)
    {
        if (publicKey32.Length != PublicKeyLength)
            throw new ArgumentException($"Public key must be {PublicKeyLength} bytes.", nameof(publicKey32));
        if (!Ed25519Point.TryDecode(publicKey32, out _))
            throw new ArgumentException("Public key is not a valid Ed25519 point.", nameof(publicKey32));
        return new OnionAddress(publicKey32.ToArray());
    }

    /// <summary>
    /// Parse a v3 <c>.onion</c> address, verifying the version and checksum (and that the key is a
    /// valid curve point). Returns false on any malformed or inconsistent input.
    /// </summary>
    public static bool TryParse(string? value, out OnionAddress address)
    {
        address = default;
        if (string.IsNullOrEmpty(value)) return false;

        ReadOnlySpan<char> s = value.AsSpan().Trim();
        if (s.EndsWith(".onion", StringComparison.OrdinalIgnoreCase))
            s = s[..^6];
        if (s.Length != Base32Length) return false;

        if (!Base32.TryDecode(s.ToString(), out byte[] decoded) || decoded.Length < EncodedByteLength)
            return false;

        ReadOnlySpan<byte> pubkey = decoded.AsSpan(0, PublicKeyLength);
        ReadOnlySpan<byte> checksum = decoded.AsSpan(PublicKeyLength, 2);
        byte version = decoded[PublicKeyLength + 2];
        if (version != Version) return false;

        Span<byte> expected = stackalloc byte[2];
        ComputeChecksum(pubkey, version, expected);
        if (!CryptographicEquals(checksum, expected)) return false;

        if (!Ed25519Point.TryDecode(pubkey, out _)) return false;

        address = new OnionAddress(pubkey.ToArray());
        return true;
    }

    /// <summary>Render the canonical lowercase <c>.onion</c> string.</summary>
    public override string ToString()
    {
        if (!IsValid) return string.Empty;
        Span<byte> buf = stackalloc byte[EncodedByteLength];
        _publicKey.CopyTo(buf);
        ComputeChecksum(_publicKey, Version, buf.Slice(PublicKeyLength, 2));
        buf[PublicKeyLength + 2] = Version;
        return Base32.Encode(buf) + ".onion";
    }

    private static void ComputeChecksum(ReadOnlySpan<byte> pubkey, byte version, Span<byte> out2)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(ChecksumPrefix, 0, ChecksumPrefix.Length);
        Span<byte> pk = stackalloc byte[PublicKeyLength];
        pubkey.CopyTo(pk);
        sha3.BlockUpdate(pk[..PublicKeyLength]);
        sha3.Update(version);
        Span<byte> digest = stackalloc byte[32];
        sha3.DoFinal(digest);
        digest[..2].CopyTo(out2);
    }

    private static bool CryptographicEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length) return false;
        int acc = 0;
        for (int i = 0; i < a.Length; i++) acc |= a[i] ^ b[i];
        return acc == 0;
    }

    /// <inheritdoc/>
    public bool Equals(OnionAddress other)
    {
        if (!IsValid || !other.IsValid) return IsValid == other.IsValid;
        return _publicKey.AsSpan().SequenceEqual(other._publicKey);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is OnionAddress o && Equals(o);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        if (!IsValid) return 0;
        var hc = new HashCode();
        hc.AddBytes(_publicKey);
        return hc.ToHashCode();
    }
}
