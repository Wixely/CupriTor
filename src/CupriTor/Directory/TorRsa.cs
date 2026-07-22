using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CupriTor.Directory;

/// <summary>
/// RSA helpers for Tor directory documents. Tor keys are PKCS#1 <c>RSAPublicKey</c> (modulus +
/// exponent), and directory signatures are a Tor-specific "raw" PKCS#1 v1.5 signature: the RSA
/// operation recovers the bare digest, with no ASN.1 DigestInfo/OID wrapper — so a standard
/// RSA-SHA1/RSA-SHA256 verifier cannot be used. We public-decrypt and compare to the digest.
/// </summary>
internal static class TorRsa
{
    /// <summary>Parse a PKCS#1 <c>RSAPublicKey</c> DER blob (a Tor "RSA PUBLIC KEY" object).</summary>
    public static RsaKeyParameters ParsePkcs1PublicKey(byte[] der)
    {
        var seq = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(der));
        var modulus = DerInteger.GetInstance(seq[0]).PositiveValue;
        var exponent = DerInteger.GetInstance(seq[1]).PositiveValue;
        return new RsaKeyParameters(isPrivate: false, modulus, exponent);
    }

    /// <summary>The Tor RSA identity fingerprint: SHA-1 of the PKCS#1 public-key DER.</summary>
    public static byte[] Fingerprint(byte[] pkcs1Der) => SHA1.HashData(pkcs1Der);

    /// <summary>
    /// Verify a Tor raw PKCS#1 v1.5 signature: public-decrypt <paramref name="signature"/> and
    /// compare the recovered bytes to <paramref name="expectedDigest"/>. BouncyCastle's PKCS#1
    /// decoding accepts both block type 1 (used by Tor) and type 2.
    /// </summary>
    public static bool VerifyRawPkcs1(RsaKeyParameters publicKey, byte[] signature, byte[] expectedDigest)
    {
        try
        {
            var engine = new Pkcs1Encoding(new RsaEngine());
            engine.Init(forEncryption: false, publicKey);
            byte[] recovered = engine.ProcessBlock(signature, 0, signature.Length);
            return CryptographicOperations.FixedTimeEquals(recovered, expectedDigest);
        }
        catch
        {
            return false;
        }
    }
}
