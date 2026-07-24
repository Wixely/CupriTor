using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// Regression tests against real Tor data captured by CupriCollector (a live signed consensus's
/// authority key certificates). Proves our parser handles real authority certs and that the hardcoded
/// authority set corresponds to real, self-verifying certificates.
/// </summary>
public class RealDataTests
{
    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "fixtures", name);

    private static IEnumerable<string> SplitCertificates(string text)
    {
        const string marker = "dir-key-certificate-version";
        int idx = text.IndexOf(marker, StringComparison.Ordinal);
        while (idx >= 0)
        {
            int next = text.IndexOf(marker, idx + marker.Length, StringComparison.Ordinal);
            yield return next < 0 ? text[idx..] : text[idx..next];
            idx = next;
        }
    }

    [Fact]
    public void DirectoryAuthorities_Are_Nine_Distinct_Valid_Fingerprints()
    {
        var auths = DirectoryAuthorities.Default;
        Assert.Equal(9, auths.Count);
        Assert.All(auths, a =>
        {
            Assert.Equal(40, a.IdentityFingerprint.Length);
            Assert.Matches("^[0-9A-F]{40}$", a.IdentityFingerprint);
        });
        Assert.Equal(9, auths.Select(a => a.IdentityFingerprint).Distinct().Count());
    }

    [Fact]
    public void Real_Authority_Certificates_Parse_And_SelfVerify()
    {
        string text = File.ReadAllText(FixturePath("authority-keys.txt"));

        var verifiedFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int total = 0, ok = 0;
        foreach (string block in SplitCertificates(text))
        {
            total++;
            if (AuthorityKeyCertificate.TryParse(block, out var cert))
            {
                ok++;
                verifiedFingerprints.Add(Convert.ToHexString(cert.IdentityFingerprint));
            }
        }

        // Every real authority certificate parses and self-verifies (identity key signs the cert).
        Assert.True(total >= 9);
        Assert.Equal(total, ok);

        // Each hardcoded authority has a real, self-verifying certificate in the captured data.
        foreach (DirectoryAuthority auth in DirectoryAuthorities.Default)
            Assert.Contains(auth.IdentityFingerprint, verifiedFingerprints);
    }
}
