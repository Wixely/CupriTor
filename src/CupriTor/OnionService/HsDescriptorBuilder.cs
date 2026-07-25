using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using CupriCurve;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriTor.OnionService;

/// <summary>An introduction point to advertise in a published descriptor.</summary>
internal sealed record PublishIntroPoint(
    byte[] LinkSpecifierBlock,   // serialized NSPEC ‖ link specifiers of the intro relay
    byte[] IntroRelayNtorKey,    // the intro relay's ntor onion key (32)
    byte[] AuthKeyPublic,        // KP_hs_ipt_sid, the per-intro ed25519 auth key (32)
    byte[] EncKeyPublic);        // KP_hss_ntor, the service's curve25519 enc key at this intro (32)

/// <summary>
/// Builds a v3 onion-service descriptor for PUBLISHING (rend-spec-v3 §2.5). Assembles the encrypted (inner)
/// layer listing introduction points, wraps it in the superencrypted (outer) layer (desc-auth-type x25519 +
/// ephemeral key + the mandatory multiple-of-16 fake auth-client lines), and signs the outer document via
/// <see cref="HsDescriptor.Build"/>. Reuses <see cref="HsLayerCrypto"/> for both layer encryptions.
/// </summary>
internal static class HsDescriptorBuilder
{
    private const int InnerPadMultiple = 10000; // tor asserts inner plaintext length % 10000 == 0
    private const int FakeAuthClients = 16;     // count must be a multiple of 16; emit 16 when no client auth

    public static string Build(
        Ed25519ExpandedKey blindedKey,
        byte[] blindedPublic,
        byte[] subcredential,
        long revisionCounter,
        int lifetimeMinutes,
        DateTimeOffset certExpiration,
        IReadOnlyList<PublishIntroPoint> introPoints)
    {
        // A fresh per-descriptor signing key; it signs the outer document AND the per-intro certs.
        byte[] signingSeed = RandomBytes(32);
        var signingKey = Ed25519ExpandedKey.FromSeed(signingSeed);
        var signingPub = new byte[32];
        signingKey.GetPublicKey(signingPub);

        byte[] secretInput = HsLayerCrypto.SecretInput(blindedPublic, subcredential, revisionCounter);

        byte[] innerPlain = ZeroPad(Encoding.ASCII.GetBytes(BuildInnerLayer(introPoints, signingKey, signingPub, certExpiration)), InnerPadMultiple);
        byte[] innerBlob = HsLayerCrypto.EncryptRandomSalt(innerPlain, secretInput, HsLayerCrypto.EncryptedConstant);

        byte[] outerPlain = Encoding.ASCII.GetBytes(BuildOuterLayer(innerBlob));
        byte[] superBlob = HsLayerCrypto.EncryptRandomSalt(outerPlain, secretInput, HsLayerCrypto.SuperencryptedConstant);

        return HsDescriptor.Build(blindedKey, blindedPublic, signingSeed, revisionCounter, lifetimeMinutes, certExpiration, superBlob);
    }

    // Encrypted (inner) layer: "create2-formats 2" then one block per intro point (rend-spec-v3 §2.5.2.2).
    private static string BuildInnerLayer(IReadOnlyList<PublishIntroPoint> introPoints, Ed25519ExpandedKey signingKey, byte[] signingPub, DateTimeOffset expiry)
    {
        var sb = new StringBuilder();
        sb.Append("create2-formats 2\n");
        foreach (PublishIntroPoint ip in introPoints)
        {
            sb.Append("introduction-point ").Append(Convert.ToBase64String(ip.LinkSpecifierBlock)).Append('\n');
            sb.Append("onion-key ntor ").Append(Unpadded(ip.IntroRelayNtorKey)).Append('\n');

            byte[] authCert = HsDescriptor.BuildCert(0x09, ip.AuthKeyPublic, signingPub, expiry, signingKey, signingPub);
            sb.Append("auth-key\n").Append(Pem("ED25519 CERT", authCert));

            sb.Append("enc-key ntor ").Append(Unpadded(ip.EncKeyPublic)).Append('\n');
            byte[] encEd25519 = Curve25519ToEd25519Public(ip.EncKeyPublic);
            byte[] encCert = HsDescriptor.BuildCert(0x0B, encEd25519, signingPub, expiry, signingKey, signingPub);
            sb.Append("enc-key-cert\n").Append(Pem("ED25519 CERT", encCert));
        }
        return sb.ToString();
    }

    // Superencrypted (outer) layer: mandatory even with no client auth (rend-spec-v3 §2.5.1.2).
    private static string BuildOuterLayer(byte[] innerBlob)
    {
        var sb = new StringBuilder();
        sb.Append("desc-auth-type x25519\n");
        byte[] ephemeral = new X25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey().GetEncoded();
        sb.Append("desc-auth-ephemeral-key ").Append(Convert.ToBase64String(ephemeral)).Append('\n');
        for (int i = 0; i < FakeAuthClients; i++)
            sb.Append("auth-client ").Append(Unpadded(RandomBytes(8))).Append(' ')
              .Append(Unpadded(RandomBytes(16))).Append(' ').Append(Unpadded(RandomBytes(16))).Append('\n');
        sb.Append("encrypted\n").Append(Pem("MESSAGE", innerBlob));
        return sb.ToString();
    }

    /// <summary>Curve25519 (Montgomery u) → Ed25519 public key: y = (u-1)/(u+1) mod p, little-endian, sign bit 0.</summary>
    internal static byte[] Curve25519ToEd25519Public(ReadOnlySpan<byte> curve25519Public)
    {
        var p = (BigInteger.One << 255) - 19;
        byte[] ule = curve25519Public.ToArray();
        ule[31] &= 0x7F; // the Montgomery u-coordinate ignores the high bit
        BigInteger u = new BigInteger(ule, isUnsigned: true, isBigEndian: false) % p;
        BigInteger num = Mod(u - 1, p);
        BigInteger den = Mod(u + 1, p);
        BigInteger y = Mod(num * BigInteger.ModPow(den, p - 2, p), p); // (u-1) * (u+1)^{-1} mod p

        byte[] le = y.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        Array.Copy(le, result, Math.Min(le.Length, 32)); // sign bit (byte[31] high bit) stays 0
        return result;
    }

    private static BigInteger Mod(BigInteger a, BigInteger p) => ((a % p) + p) % p;

    private static byte[] ZeroPad(byte[] data, int multiple)
    {
        int padded = ((data.Length + multiple - 1) / multiple) * multiple;
        if (padded == data.Length) return data;
        var result = new byte[padded];
        data.CopyTo(result, 0);
        return result;
    }

    private static string Pem(string type, ReadOnlySpan<byte> data) =>
        $"-----BEGIN {type}-----\n{Convert.ToBase64String(data)}\n-----END {type}-----\n";

    private static string Unpadded(ReadOnlySpan<byte> data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }
}
