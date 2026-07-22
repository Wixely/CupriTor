using System.Buffers.Binary;
using CupriTor.Protocol;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.Tests;

public class TorCertificateTests
{
    // Build a well-formed cert-spec Ed25519 certificate (type 0x04) with an embedded signing-key extension.
    private static byte[] BuildCert(byte[] signingSeed, out byte[] signingPub, DateTimeOffset expiration, byte[]? certifiedKey = null)
    {
        signingPub = new byte[32];
        BcEd25519.GeneratePublicKey(signingSeed, 0, signingPub, 0);
        certifiedKey ??= new byte[32];

        uint hours = (uint)(expiration - DateTimeOffset.UnixEpoch).TotalHours;
        var body = new List<byte> { 0x01, 0x04 };
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, hours);
        body.AddRange(h.ToArray());
        body.Add(0x01);                 // cert_key_type = ed25519
        body.AddRange(certifiedKey);    // certified_key (32)
        body.Add(0x01);                 // n_extensions
        // extension: signed-with-ed25519-key
        Span<byte> el = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(el, 32);
        body.AddRange(el.ToArray());
        body.Add(0x04);                 // ext type
        body.Add(0x00);                 // ext flags
        body.AddRange(signingPub);      // ext data (32)

        var bodyArr = body.ToArray();
        var sig = new byte[64];
        BcEd25519.Sign(signingSeed, 0, bodyArr, 0, bodyArr.Length, sig, 0);

        var cert = new byte[bodyArr.Length + 64];
        bodyArr.CopyTo(cert, 0);
        sig.CopyTo(cert, bodyArr.Length);
        return cert;
    }

    private static byte[] Seed(byte b) { var s = new byte[32]; Array.Fill(s, b); return s; }

    [Fact]
    public void Parses_And_Verifies_Valid_Certificate()
    {
        var future = DateTimeOffset.UtcNow.AddDays(30);
        var certified = new byte[32]; Array.Fill(certified, (byte)0xAB);
        byte[] cert = BuildCert(Seed(1), out byte[] signingPub, future, certified);

        Assert.True(TorCertificate.TryParse(cert, out var c));
        Assert.Equal(1, c.Version);
        Assert.Equal(TorCertificate.Type.SigningByIdentity, c.CertType);
        Assert.Equal(TorCertificate.KeyType.Ed25519, c.CertifiedKeyType);
        Assert.Equal(certified, c.CertifiedKey.ToArray());
        Assert.Equal(signingPub, c.SigningKey!.Value.ToArray());
        Assert.False(c.IsExpired(DateTimeOffset.UtcNow));

        Assert.True(c.VerifySignatureWithEmbeddedKey());
        Assert.True(c.VerifySignature(signingPub));
    }

    [Fact]
    public void Rejects_Tampered_Body()
    {
        byte[] cert = BuildCert(Seed(2), out _, DateTimeOffset.UtcNow.AddDays(1));
        cert[8] ^= 0xFF; // flip a byte in the certified-key region
        Assert.True(TorCertificate.TryParse(cert, out var c));
        Assert.False(c.VerifySignatureWithEmbeddedKey());
    }

    [Fact]
    public void Rejects_Tampered_Signature()
    {
        byte[] cert = BuildCert(Seed(3), out _, DateTimeOffset.UtcNow.AddDays(1));
        cert[^1] ^= 0xFF;
        Assert.True(TorCertificate.TryParse(cert, out var c));
        Assert.False(c.VerifySignatureWithEmbeddedKey());
    }

    [Fact]
    public void Detects_Expiration()
    {
        var past = DateTimeOffset.UnixEpoch.AddHours((uint)(DateTimeOffset.UtcNow.AddHours(-5) - DateTimeOffset.UnixEpoch).TotalHours);
        byte[] cert = BuildCert(Seed(4), out _, past);
        Assert.True(TorCertificate.TryParse(cert, out var c));
        Assert.True(c.IsExpired(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Rejects_Malformed_Input()
    {
        byte[] cert = BuildCert(Seed(5), out _, DateTimeOffset.UtcNow.AddDays(1));
        Assert.False(TorCertificate.TryParse(cert.AsMemory(0, 10), out _));   // truncated
        Assert.False(TorCertificate.TryParse(ReadOnlyMemory<byte>.Empty, out _));

        var badVersion = (byte[])cert.Clone();
        badVersion[0] = 0x02;
        Assert.False(TorCertificate.TryParse(badVersion, out _));
    }
}
