using System.Buffers.Binary;
using System.Text;
using CupriCurve;
using Org.BouncyCastle.Crypto.Digests;

namespace CupriTor.OnionService;

/// <summary>
/// v3 onion-service time periods (rend-spec-v3 §2.2.1). Descriptors and blinded keys rotate once per
/// period; the period number indexes the blinding.
/// </summary>
internal static class HsTimePeriod
{
    /// <summary>Default period length (consensus param <c>hsdir-interval</c>), in minutes.</summary>
    public const int DefaultLengthMinutes = 1440; // 24h

    /// <summary>Rotation offset so periods turn over at 12:00 UTC (aligned with shared-random rotation).</summary>
    public const int RotationOffsetMinutes = 720; // 12h

    public static long Number(DateTimeOffset time, int lengthMinutes = DefaultLengthMinutes)
    {
        long minutes = time.ToUnixTimeSeconds() / 60;
        return (minutes - RotationOffsetMinutes) / lengthMinutes;
    }

    public static DateTimeOffset Start(long number, int lengthMinutes = DefaultLengthMinutes)
    {
        long minutes = number * lengthMinutes + RotationOffsetMinutes;
        return DateTimeOffset.FromUnixTimeSeconds(minutes * 60);
    }
}

/// <summary>
/// v3 onion-service key blinding and subcredential derivation (rend-spec-v3 §A.2, §2.1). The blinding
/// factor is SHA3-256 over a fixed construction; the per-period blinded public key is derived via
/// CupriCurve's Ed25519 key blinding, and the subcredential ties the blinded key back to the identity.
/// </summary>
internal static class HsBlinding
{
    private static readonly byte[] BlindString = Concat(Ascii("Derive temporary signing key"), new byte[] { 0 });
    private static readonly byte[] KeyBlind = Ascii("key-blind");

    // The Ed25519 base point, as the exact ASCII coordinate string Tor hashes (rend-spec-v3 §A.2).
    private static readonly byte[] BasePoint = Ascii(
        "(15112221349535400772501151409588531511454012693041857206046113283949847762202, " +
        "46316835694926478169428394003475163141307993866256225615783033603165251855960)");

    /// <summary>The 32-byte clamped blinding scalar h for the given identity key and time period.</summary>
    public static byte[] BlindingFactor(ReadOnlySpan<byte> identityKey, long periodNumber, int periodLength)
    {
        var n = new byte[KeyBlind.Length + 16];
        KeyBlind.CopyTo(n, 0);
        BinaryPrimitives.WriteInt64BigEndian(n.AsSpan(KeyBlind.Length), periodNumber);
        BinaryPrimitives.WriteInt64BigEndian(n.AsSpan(KeyBlind.Length + 8), periodLength);

        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(BlindString, 0, BlindString.Length);
        Span<byte> a = stackalloc byte[32];
        identityKey.Slice(0, 32).CopyTo(a);
        sha3.BlockUpdate(a);
        sha3.BlockUpdate(BasePoint, 0, BasePoint.Length);
        sha3.BlockUpdate(n, 0, n.Length);
        var h = new byte[32];
        sha3.DoFinal(h, 0);

        h[0] &= 248;
        h[31] &= 63;
        h[31] |= 64;
        return h;
    }

    /// <summary>Derive the per-period blinded public key A' = [h]A. Returns false if the identity isn't a valid point.</summary>
    public static bool TryBlindPublicKey(ReadOnlySpan<byte> identityKey, long periodNumber, int periodLength, Span<byte> blindedKey)
    {
        byte[] h = BlindingFactor(identityKey, periodNumber, periodLength);
        return TorBlinding.TryBlindPublicKey(identityKey, h, blindedKey);
    }

    /// <summary>
    /// The subcredential for a period: SHA3-256("subcredential" ‖ credential ‖ blindedKey), where
    /// credential = SHA3-256("credential" ‖ identityKey).
    /// </summary>
    public static byte[] Subcredential(ReadOnlySpan<byte> identityKey, ReadOnlySpan<byte> blindedKey)
    {
        byte[] credential = Sha3(Ascii("credential"), identityKey);

        var sha3 = new Sha3Digest(256);
        byte[] prefix = Ascii("subcredential");
        sha3.BlockUpdate(prefix, 0, prefix.Length);
        sha3.BlockUpdate(credential, 0, credential.Length);
        Span<byte> b = stackalloc byte[32];
        blindedKey.Slice(0, 32).CopyTo(b);
        sha3.BlockUpdate(b);
        var result = new byte[32];
        sha3.DoFinal(result, 0);
        return result;
    }

    private static byte[] Sha3(byte[] prefix, ReadOnlySpan<byte> data)
    {
        var sha3 = new Sha3Digest(256);
        sha3.BlockUpdate(prefix, 0, prefix.Length);
        Span<byte> d = stackalloc byte[32];
        data.Slice(0, 32).CopyTo(d);
        sha3.BlockUpdate(d);
        var result = new byte[32];
        sha3.DoFinal(result, 0);
        return result;
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }
}
