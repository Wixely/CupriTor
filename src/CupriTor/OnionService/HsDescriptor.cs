using System.Buffers.Binary;
using System.Text;
using CupriCurve;
using CupriTor.Directory;
using CupriTor.Protocol;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.OnionService;

/// <summary>
/// Build and parse/verify a v3 onion-service descriptor's outer document (rend-spec-v3 §2.4): the
/// plaintext wrapper carrying the descriptor-signing-key certificate (signed by the per-period blinded
/// key), the revision counter, the superencrypted payload, and the descriptor signature. The
/// superencrypted blob itself is handled by <see cref="HsLayerCrypto"/>.
/// </summary>
internal static class HsDescriptor
{
    private const byte CertTypeHsDescSigning = 0x08;
    private static readonly byte[] SignaturePrefix = Encoding.ASCII.GetBytes("Tor onion service descriptor sig v3");

    /// <summary>
    /// Assemble and sign a descriptor. <paramref name="blindedKey"/> (the per-period blinded expanded
    /// private key) signs the signing-key certificate; a fresh descriptor signing key signs the document.
    /// </summary>
    public static string Build(
        Ed25519ExpandedKey blindedKey,
        ReadOnlySpan<byte> blindedPublicKey,
        ReadOnlySpan<byte> signingSeed,
        long revisionCounter,
        int lifetimeMinutes,
        DateTimeOffset certExpiration,
        ReadOnlySpan<byte> superencryptedBlob)
    {
        var signingKey = Ed25519ExpandedKey.FromSeed(signingSeed);
        Span<byte> signingPub = stackalloc byte[32];
        signingKey.GetPublicKey(signingPub);

        byte[] cert = BuildCert(CertTypeHsDescSigning, signingPub, blindedPublicKey, certExpiration, blindedKey, blindedPublicKey);

        var sb = new StringBuilder();
        sb.Append("hs-descriptor 3\n");
        sb.Append("descriptor-lifetime ").Append(lifetimeMinutes).Append('\n');
        sb.Append("descriptor-signing-key-cert\n").Append(PemBlock("ED25519 CERT", cert));
        sb.Append("revision-counter ").Append(revisionCounter).Append('\n');
        sb.Append("superencrypted\n").Append(PemBlock("MESSAGE", superencryptedBlob));
        // The signature covers the descriptor up to and including the newline before "signature"
        // (i.e. NOT the "signature" keyword itself), prefixed with the signing string.
        string signedPortion = sb.ToString();

        byte[] toSign = Concat(SignaturePrefix, Encoding.ASCII.GetBytes(signedPortion));
        var signature = new byte[Ed25519.SignatureSize];
        Ed25519.SignWithExpandedKey(signingKey, signingPub, toSign, signature);

        sb.Append("signature ").Append(Base64Unpadded(signature)).Append('\n');
        return sb.ToString();
    }

    /// <summary>Parse a descriptor's outer document.</summary>
    public static bool TryParse(string text, out HsDescriptorView view)
    {
        view = default!;
        try
        {
            List<DirectoryItem> items = DirectoryReader.Parse(text);
            int lifetime = 0;
            long revision = 0;
            byte[]? cert = null, superBlob = null, signature = null;

            foreach (DirectoryItem item in items)
            {
                switch (item.Keyword)
                {
                    case "hs-descriptor":
                        if (item.Arguments is not ["3", ..]) return false;
                        break;
                    case "descriptor-lifetime":
                        lifetime = int.Parse(item.Arguments[0]);
                        break;
                    case "descriptor-signing-key-cert":
                        cert = item.ObjectData;
                        break;
                    case "revision-counter":
                        revision = long.Parse(item.Arguments[0]);
                        break;
                    case "superencrypted":
                        superBlob = item.ObjectData;
                        break;
                    case "signature":
                        signature = item.Arguments.Length >= 1 ? DirectoryReader.Base64(item.Arguments[0]) : null;
                        break;
                }
            }

            if (cert is null || superBlob is null || signature is null) return false;

            int idx = text.IndexOf("\nsignature ", StringComparison.Ordinal);
            if (idx < 0) return false;
            // Signed body ends at (and includes) the newline before "signature".
            byte[] signedBody = Encoding.ASCII.GetBytes(text.Substring(0, idx + 1));

            view = new HsDescriptorView(lifetime, revision, cert, superBlob, signature, signedBody);
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException)
        {
            return false;
        }
    }

    private static byte[] BuildCert(byte certType, ReadOnlySpan<byte> certifiedKey, ReadOnlySpan<byte> signedWithKey,
        DateTimeOffset expiration, Ed25519ExpandedKey signer, ReadOnlySpan<byte> signerPublic)
    {
        uint hours = (uint)(expiration - DateTimeOffset.UnixEpoch).TotalHours;
        var body = new List<byte> { 0x01, certType };
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, hours);
        body.AddRange(h.ToArray());
        body.Add(0x01); // cert_key_type = ed25519
        body.AddRange(certifiedKey.ToArray());
        body.Add(0x01); // one extension
        Span<byte> extLen = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(extLen, 32);
        body.AddRange(extLen.ToArray());
        body.Add(0x04); // signed-with-ed25519-key
        body.Add(0x00);
        body.AddRange(signedWithKey.ToArray());

        byte[] bodyArr = body.ToArray();
        var sig = new byte[Ed25519.SignatureSize];
        Ed25519.SignWithExpandedKey(signer, signerPublic, bodyArr, sig);

        var cert = new byte[bodyArr.Length + sig.Length];
        bodyArr.CopyTo(cert, 0);
        sig.CopyTo(cert, bodyArr.Length);
        return cert;
    }

    private static string PemBlock(string type, ReadOnlySpan<byte> data) =>
        $"-----BEGIN {type}-----\n{Convert.ToBase64String(data)}\n-----END {type}-----\n";

    private static string Base64Unpadded(ReadOnlySpan<byte> data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    internal static byte[] SignaturePrefixBytes => SignaturePrefix;
}

/// <summary>A parsed outer descriptor, with verification against the expected per-period blinded key.</summary>
internal sealed class HsDescriptorView(int lifetime, long revisionCounter, byte[] signingCert, byte[] superencryptedBlob, byte[] signature, byte[] signedBody)
{
    public int Lifetime => lifetime;
    public long RevisionCounter => revisionCounter;
    public ReadOnlyMemory<byte> SuperencryptedBlob => superencryptedBlob;

    /// <summary>
    /// Verify the descriptor: the signing-key cert is signed by <paramref name="expectedBlindedKey"/>
    /// (which the client derives from the .onion identity + time period), and the document signature is
    /// valid under the certified descriptor signing key. On success, exposes that signing key.
    /// </summary>
    public bool TryVerify(ReadOnlySpan<byte> expectedBlindedKey, out byte[] descriptorSigningKey)
    {
        descriptorSigningKey = Array.Empty<byte>();

        if (!TorCertificate.TryParse(signingCert, out TorCertificate cert)) return false;
        if (cert.CertType != TorCertificate.Type.HsDescSigning) return false;
        if (cert.SigningKey is not { } ca || !ca.Span.SequenceEqual(expectedBlindedKey)) return false;
        if (!cert.VerifySignatureWithEmbeddedKey()) return false; // blinded key signed the cert

        byte[] signingKey = cert.CertifiedKey.ToArray();

        byte[] toVerify = new byte[HsDescriptor.SignaturePrefixBytes.Length + signedBody.Length];
        HsDescriptor.SignaturePrefixBytes.CopyTo(toVerify, 0);
        signedBody.CopyTo(toVerify, HsDescriptor.SignaturePrefixBytes.Length);

        if (signature.Length != Ed25519.SignatureSize) return false;
        if (!BcEd25519.Verify(signature, 0, signingKey, 0, toVerify, 0, toVerify.Length)) return false;

        descriptorSigningKey = signingKey;
        return true;
    }
}
