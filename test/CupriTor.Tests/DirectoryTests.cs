using System.Net;
using System.Security.Cryptography;
using System.Text;
using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

public class DirectoryTests
{
    private static string B64Unpadded(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static byte[] Filled(int len, byte val) { var b = new byte[len]; Array.Fill(b, val); return b; }

    private static string BuildMicrodescriptor(byte[] rsaOnionDer, byte[] ntor, byte[] ed)
    {
        var sb = new StringBuilder();
        sb.Append("onion-key\n");
        sb.Append("-----BEGIN RSA PUBLIC KEY-----\n");
        sb.Append(Convert.ToBase64String(rsaOnionDer)).Append('\n');
        sb.Append("-----END RSA PUBLIC KEY-----\n");
        sb.Append("ntor-onion-key ").Append(B64Unpadded(ntor)).Append('\n');
        sb.Append("id ed25519 ").Append(B64Unpadded(ed)).Append('\n');
        return sb.ToString();
    }

    [Fact]
    public void Parses_Microdescriptor_And_Digest_Matches()
    {
        byte[] rsa = Filled(64, 0xAA), ntor = Filled(32, 0xBB), ed = Filled(32, 0xCC);
        string mdText = BuildMicrodescriptor(rsa, ntor, ed);
        byte[] mdBytes = Encoding.ASCII.GetBytes(mdText);

        Assert.True(Microdescriptor.TryParse(mdText, out var md));
        Assert.Equal(rsa, md.RsaOnionKeyDer);
        Assert.Equal(ntor, md.NtorOnionKey);
        Assert.Equal(ed, md.Ed25519Identity);
        Assert.Equal(SHA256.HashData(mdBytes), Microdescriptor.ComputeDigest(mdBytes));
    }

    [Fact]
    public void Parses_Microdesc_Consensus()
    {
        byte[] identityFp = Filled(20, 0x11);
        byte[] mdDigest = Filled(32, 0x22);
        byte[] authIdFp = Filled(20, 0x33);
        byte[] authSkFp = Filled(20, 0x44);
        byte[] sig = Filled(128, 0x55);
        byte[] sharedRand = Filled(32, 0x66);

        var sb = new StringBuilder();
        sb.Append("network-status-version 3 microdesc\n");
        sb.Append("vote-status consensus\n");
        sb.Append("consensus-method 34\n");
        sb.Append("valid-after 2026-07-22 08:00:00\n");
        sb.Append("fresh-until 2026-07-22 09:00:00\n");
        sb.Append("valid-until 2026-07-22 11:00:00\n");
        sb.Append("voting-delay 300 300\n");
        sb.Append("known-flags Exit Fast Guard Running Stable Valid\n");
        sb.Append("shared-rand-current-value 8 ").Append(B64Unpadded(sharedRand)).Append('\n');
        sb.Append("r TestRelay ").Append(B64Unpadded(identityFp)).Append(" 2026-07-22 07:00:00 203.0.113.5 9001 0\n");
        sb.Append("m ").Append(B64Unpadded(mdDigest)).Append('\n');
        sb.Append("s Fast Guard Running Stable Valid\n");
        sb.Append("v Tor 0.4.8.10\n");
        sb.Append("pr Link=1-5 LinkAuth=3\n");
        sb.Append("w Bandwidth=1000 Measured=950\n");
        sb.Append("directory-footer\n");
        sb.Append("directory-signature sha256 ")
          .Append(Convert.ToHexString(authIdFp)).Append(' ')
          .Append(Convert.ToHexString(authSkFp)).Append('\n');
        sb.Append("-----BEGIN SIGNATURE-----\n");
        sb.Append(Convert.ToBase64String(sig)).Append('\n');
        sb.Append("-----END SIGNATURE-----\n");
        string text = sb.ToString();

        Assert.True(Consensus.TryParse(text, out var c));
        Assert.Equal(34, c.ConsensusMethod);
        Assert.Equal(new DateTimeOffset(2026, 7, 22, 8, 0, 0, TimeSpan.Zero), c.ValidAfter);
        Assert.Equal(new DateTimeOffset(2026, 7, 22, 11, 0, 0, TimeSpan.Zero), c.ValidUntil);
        Assert.Contains("Guard", c.KnownFlags);
        Assert.Equal(sharedRand, c.SharedRandomCurrentValue);

        Assert.Single(c.Routers);
        RouterStatusEntry r = c.Routers[0];
        Assert.Equal("TestRelay", r.Nickname);
        Assert.Equal(identityFp, r.RsaIdentityDigest);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), r.Address);
        Assert.Equal(9001, r.OrPort);
        Assert.Equal(1000, r.Bandwidth);
        Assert.Contains("Guard", r.Flags);
        Assert.Equal(mdDigest, r.MicrodescriptorSha256);
        Assert.Equal("Tor 0.4.8.10", r.Version);

        Assert.Single(c.Signatures);
        DirectorySignature s = c.Signatures[0];
        Assert.Equal("sha256", s.Algorithm);
        Assert.Equal(authIdFp, s.IdentityFingerprint);
        Assert.Equal(authSkFp, s.SigningKeyDigest);
        Assert.Equal(sig, s.Signature);

        // Signed body ends at "directory-signature " and drives the (later) signature check.
        string signedText = Encoding.ASCII.GetString(c.SignedBody);
        Assert.EndsWith("directory-signature ", signedText);
        Assert.Equal(32, c.SignedBodySha256.Length);
    }

    [Fact]
    public void IsValidAt_Respects_Lifetime()
    {
        Assert.True(Consensus.TryParse(MinimalConsensus(), out var c));
        Assert.True(c.IsValidAt(new DateTimeOffset(2026, 7, 22, 8, 30, 0, TimeSpan.Zero)));
        Assert.False(c.IsValidAt(new DateTimeOffset(2026, 7, 22, 12, 0, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void Rejects_NonConsensus_And_Truncated()
    {
        Assert.False(Consensus.TryParse("network-status-version 3 microdesc\nvote-status vote\n", out _));
        Assert.False(Consensus.TryParse("garbage", out _));
    }

    private static string MinimalConsensus()
    {
        var sb = new StringBuilder();
        sb.Append("network-status-version 3 microdesc\n");
        sb.Append("vote-status consensus\n");
        sb.Append("consensus-method 34\n");
        sb.Append("valid-after 2026-07-22 08:00:00\n");
        sb.Append("fresh-until 2026-07-22 09:00:00\n");
        sb.Append("valid-until 2026-07-22 11:00:00\n");
        sb.Append("directory-footer\n");
        sb.Append("directory-signature sha256 ").Append(new string('A', 40)).Append(' ').Append(new string('B', 40)).Append('\n');
        sb.Append("-----BEGIN SIGNATURE-----\n").Append(Convert.ToBase64String(Filled(64, 1))).Append("\n-----END SIGNATURE-----\n");
        return sb.ToString();
    }
}
