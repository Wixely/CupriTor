using System.Security.Cryptography;
using System.Text;
using CupriTor.Directory;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

public class ConsensusVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 22, 8, 30, 0, TimeSpan.Zero);

    private static AsymmetricCipherKeyPair GenRsa()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return gen.GenerateKeyPair();
    }

    private static byte[] Pkcs1Der(RsaKeyParameters pub) =>
        new DerSequence(new DerInteger(pub.Modulus), new DerInteger(pub.Exponent)).GetDerEncoded();

    private static byte[] RawSign(byte[] digest, RsaKeyParameters priv)
    {
        var engine = new Pkcs1Encoding(new RsaEngine());
        engine.Init(true, priv);
        return engine.ProcessBlock(digest, 0, digest.Length);
    }

    private sealed record Authority(string IdFpHex, string SkDigestHex, string CertText, RsaKeyParameters SigningPriv);

    private static Authority BuildAuthority()
    {
        AsymmetricCipherKeyPair id = GenRsa(), sk = GenRsa();
        var idPub = (RsaKeyParameters)id.Public;
        var idPriv = (RsaKeyParameters)id.Private;
        var skPub = (RsaKeyParameters)sk.Public;

        byte[] idDer = Pkcs1Der(idPub), skDer = Pkcs1Der(skPub);
        string idFpHex = Convert.ToHexString(SHA1.HashData(idDer));
        string skDigestHex = Convert.ToHexString(SHA1.HashData(skDer));

        var sb = new StringBuilder();
        sb.Append("dir-key-certificate-version 3\n");
        sb.Append("fingerprint ").Append(idFpHex).Append('\n');
        sb.Append("dir-key-published 2026-07-01 00:00:00\n");
        sb.Append("dir-key-expires 2027-07-01 00:00:00\n");
        sb.Append("dir-identity-key\n-----BEGIN RSA PUBLIC KEY-----\n").Append(Convert.ToBase64String(idDer)).Append("\n-----END RSA PUBLIC KEY-----\n");
        sb.Append("dir-signing-key\n-----BEGIN RSA PUBLIC KEY-----\n").Append(Convert.ToBase64String(skDer)).Append("\n-----END RSA PUBLIC KEY-----\n");
        sb.Append("dir-key-certification\n");
        string prefix = sb.ToString();

        byte[] certSig = RawSign(SHA1.HashData(Encoding.ASCII.GetBytes(prefix)), idPriv);
        string certText = prefix + "-----BEGIN SIGNATURE-----\n" + Convert.ToBase64String(certSig) + "\n-----END SIGNATURE-----\n";

        return new Authority(idFpHex, skDigestHex, certText, (RsaKeyParameters)sk.Private);
    }

    private static string BuildSignedConsensus(Authority a, bool corruptSignature = false)
    {
        var sb = new StringBuilder();
        sb.Append("network-status-version 3 microdesc\n");
        sb.Append("vote-status consensus\n");
        sb.Append("consensus-method 34\n");
        sb.Append("valid-after 2026-07-22 08:00:00\n");
        sb.Append("fresh-until 2026-07-22 09:00:00\n");
        sb.Append("valid-until 2026-07-22 11:00:00\n");
        sb.Append("directory-footer\n");
        sb.Append("directory-signature ");
        string signedBody = sb.ToString();

        byte[] sig = RawSign(SHA256.HashData(Encoding.ASCII.GetBytes(signedBody)), a.SigningPriv);
        if (corruptSignature) sig[0] ^= 0xFF;

        return signedBody + $"sha256 {a.IdFpHex} {a.SkDigestHex}\n"
            + "-----BEGIN SIGNATURE-----\n" + Convert.ToBase64String(sig) + "\n-----END SIGNATURE-----\n";
    }

    [Fact]
    public void AuthorityCertificate_Parses_And_SelfVerifies()
    {
        Authority a = BuildAuthority();
        Assert.True(AuthorityKeyCertificate.TryParse(a.CertText, out var cert));
        Assert.Equal(a.IdFpHex, Convert.ToHexString(cert.IdentityFingerprint));
        Assert.Equal(a.SkDigestHex, Convert.ToHexString(cert.SigningKeyDigest));
        Assert.False(cert.IsExpired(Now));
    }

    [Fact]
    public void AuthorityCertificate_Rejects_Tampered_Fingerprint()
    {
        Authority a = BuildAuthority();
        // Corrupt the stated fingerprint so it no longer matches the identity key.
        string bad = a.CertText.Replace("fingerprint " + a.IdFpHex, "fingerprint " + new string('A', 40));
        Assert.False(AuthorityKeyCertificate.TryParse(bad, out _));
    }

    [Fact]
    public void Consensus_Verifies_With_Majority()
    {
        Authority a = BuildAuthority();
        Assert.True(AuthorityKeyCertificate.TryParse(a.CertText, out var cert));
        Assert.True(Consensus.TryParse(BuildSignedConsensus(a), out var consensus));

        bool ok = ConsensusVerifier.Verify(consensus, new[] { cert }, new[] { a.IdFpHex }, Now, out int valid);
        Assert.True(ok);
        Assert.Equal(1, valid);
    }

    [Fact]
    public void Consensus_Fails_With_Untrusted_Authority()
    {
        Authority a = BuildAuthority();
        AuthorityKeyCertificate.TryParse(a.CertText, out var cert);
        Consensus.TryParse(BuildSignedConsensus(a), out var consensus);

        Assert.False(ConsensusVerifier.Verify(consensus, new[] { cert }, Array.Empty<string>(), Now, out _));
        Assert.False(ConsensusVerifier.Verify(consensus, new[] { cert }, new[] { new string('F', 40) }, Now, out _));
    }

    [Fact]
    public void Consensus_Fails_With_Corrupt_Signature()
    {
        Authority a = BuildAuthority();
        AuthorityKeyCertificate.TryParse(a.CertText, out var cert);
        Consensus.TryParse(BuildSignedConsensus(a, corruptSignature: true), out var consensus);

        Assert.False(ConsensusVerifier.Verify(consensus, new[] { cert }, new[] { a.IdFpHex }, Now, out int valid));
        Assert.Equal(0, valid);
    }

    [Fact]
    public void Consensus_Fails_When_Expired()
    {
        Authority a = BuildAuthority();
        AuthorityKeyCertificate.TryParse(a.CertText, out var cert);
        Consensus.TryParse(BuildSignedConsensus(a), out var consensus);

        var afterExpiry = new DateTimeOffset(2026, 7, 22, 12, 0, 0, TimeSpan.Zero);
        Assert.False(ConsensusVerifier.Verify(consensus, new[] { cert }, new[] { a.IdFpHex }, afterExpiry, out _));
    }
}
