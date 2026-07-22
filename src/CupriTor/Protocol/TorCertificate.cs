using System.Buffers.Binary;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.Protocol;

/// <summary>
/// A Tor Ed25519 certificate (tor cert-spec §2.1) — the format carried in the link-handshake
/// CERTS cell and in onion-service descriptors. Fixed header, a list of extensions, and a trailing
/// Ed25519 signature over everything that precedes it.
/// </summary>
internal sealed class TorCertificate
{
    /// <summary>Certificate type (cert-spec §2.1 CERT_TYPE).</summary>
    public enum Type : byte
    {
        SigningByIdentity = 0x04,   // Ed25519 signing key, signed by the identity key
        TlsLinkBySigning = 0x05,    // TLS link cert (SHA-256 of X.509), signed by the signing key
        AuthBySigning = 0x06,       // Ed25519 auth key, signed by the signing key
        HsDescSigning = 0x08,       // onion-service descriptor signing key
        HsIntroSigning = 0x09,      // onion-service intro-point auth key
        HsNtor = 0x0B,              // onion-service ntor-extension cross-cert
    }

    /// <summary>Certified-key type (cert-spec CERT_KEY_TYPE).</summary>
    public enum KeyType : byte
    {
        Ed25519 = 0x01,
        Sha256OfX509 = 0x03,
        Sha256OfRsa = 0x02,
    }

    private const byte ExtSignedWithEd25519Key = 0x04;
    private const int HeaderLength = 1 + 1 + 4 + 1 + 32 + 1; // version..n_extensions
    private const int SignatureLength = 64;

    public byte Version { get; private init; }
    public Type CertType { get; private init; }
    public DateTimeOffset Expiration { get; private init; }
    public KeyType CertifiedKeyType { get; private init; }
    public ReadOnlyMemory<byte> CertifiedKey { get; private init; }
    public IReadOnlyList<Extension> Extensions { get; private init; } = Array.Empty<Extension>();
    public ReadOnlyMemory<byte> Signature { get; private init; }

    // Bytes covered by the signature (everything before the 64-byte signature).
    private ReadOnlyMemory<byte> _signed;

    public readonly record struct Extension(byte ExtType, byte Flags, ReadOnlyMemory<byte> Data);

    /// <summary>The Ed25519 key that signed this cert, if carried in a "signed-with-ed25519-key" extension.</summary>
    public ReadOnlyMemory<byte>? SigningKey
    {
        get
        {
            foreach (Extension e in Extensions)
                if (e.ExtType == ExtSignedWithEd25519Key && e.Data.Length == 32)
                    return e.Data;
            return null;
        }
    }

    /// <summary>Parse a certificate with strict bounds checking. Returns false on any malformed input.</summary>
    public static bool TryParse(ReadOnlyMemory<byte> buffer, out TorCertificate certificate)
    {
        certificate = null!;
        ReadOnlySpan<byte> s = buffer.Span;
        if (s.Length < HeaderLength + SignatureLength) return false;

        byte version = s[0];
        if (version != 0x01) return false;

        var type = (Type)s[1];
        uint hours = BinaryPrimitives.ReadUInt32BigEndian(s.Slice(2, 4));
        var keyType = (KeyType)s[6];
        ReadOnlyMemory<byte> certifiedKey = buffer.Slice(7, 32);
        int nExt = s[39];

        int pos = HeaderLength;
        var extensions = new List<Extension>(nExt);
        for (int i = 0; i < nExt; i++)
        {
            if (pos + 4 > s.Length) return false;
            int extLen = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(pos, 2));
            byte extType = s[pos + 2];
            byte flags = s[pos + 3];
            pos += 4;
            if (pos + extLen > s.Length) return false;
            extensions.Add(new Extension(extType, flags, buffer.Slice(pos, extLen)));
            pos += extLen;
        }

        if (pos + SignatureLength != s.Length) return false; // signature must be exactly the tail

        DateTimeOffset expiration;
        try
        {
            expiration = DateTimeOffset.UnixEpoch.AddHours(hours);
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }

        certificate = new TorCertificate
        {
            Version = version,
            CertType = type,
            Expiration = expiration,
            CertifiedKeyType = keyType,
            CertifiedKey = certifiedKey,
            Extensions = extensions,
            Signature = buffer.Slice(pos, SignatureLength),
            _signed = buffer.Slice(0, pos),
        };
        return true;
    }

    /// <summary>True if the certificate has expired at <paramref name="now"/>.</summary>
    public bool IsExpired(DateTimeOffset now) => now >= Expiration;

    /// <summary>Verify the Ed25519 signature against an explicitly supplied signing key.</summary>
    public bool VerifySignature(ReadOnlySpan<byte> signingKey32)
    {
        if (signingKey32.Length != 32) return false;
        return BcEd25519.Verify(
            Signature.ToArray(), 0,
            signingKey32.ToArray(), 0,
            _signed.ToArray(), 0, _signed.Length);
    }

    /// <summary>
    /// Verify using the signing key carried in this cert's "signed-with-ed25519-key" extension.
    /// Returns false if no such extension is present (the signer must then be supplied externally).
    /// </summary>
    public bool VerifySignatureWithEmbeddedKey()
    {
        return SigningKey is { } key && VerifySignature(key.Span);
    }
}
