namespace CupriTor.Directory;

/// <summary>A trusted directory authority: a nickname and its long-term identity fingerprint (uppercase hex).</summary>
internal sealed record DirectoryAuthority(string Nickname, string IdentityFingerprint);

/// <summary>
/// The hardcoded directory authorities that anchor consensus trust — the fixed set whose majority
/// signature makes a consensus trustworthy. These identity fingerprints were taken from a live signed
/// consensus (consensus-method 35, valid-after 2026-07-24) and cross-checked against the authority key
/// certificates. This set changes rarely; it must be kept in sync with the Tor authorities and must
/// NOT be derived from a consensus at runtime (that would let a hostile consensus name its own signers).
/// </summary>
internal static class DirectoryAuthorities
{
    public static IReadOnlyList<DirectoryAuthority> Default { get; } = new DirectoryAuthority[]
    {
        new("moria1", "F533C81CEF0BC0267857C99B2F471ADF249FA232"),
        new("tor26", "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C"),
        new("dizum", "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58"),
        new("gabelmoo", "ED03BB616EB2F60BEC80151114BB25CEF515B226"),
        new("dannenberg", "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"),
        new("maatuska", "49015F787433103580E3B66A1707A00E60F2D15B"),
        new("longclaw", "23D15D965BC35114467363C165C4F724B64B4F66"),
        new("bastet", "27102BC123E7AF1D4741AE047E160C91ADC76B21"),
        new("faravahar", "70849B868D606BAECFB6128C5E3D782029AA394F"),
    };

    /// <summary>The identity fingerprints (uppercase hex) of the trusted authorities.</summary>
    public static IReadOnlyCollection<string> DefaultFingerprints { get; } =
        Default.Select(a => a.IdentityFingerprint).ToArray();
}

/// <summary>
/// Verifies a consensus against the directory authorities (dir-spec §3.4.2): each authority signature
/// is checked with that authority's signing key (from its verified key certificate), and the consensus
/// is trusted only if a strict majority of the trusted authorities produced a valid signature.
/// </summary>
internal static class ConsensusVerifier
{
    /// <summary>
    /// Returns true if <paramref name="consensus"/> is valid at <paramref name="now"/> and signed by a
    /// majority of <paramref name="trustedFingerprints"/> (uppercase hex), using the supplied
    /// authority key certificates.
    /// </summary>
    public static bool Verify(
        Consensus consensus,
        IEnumerable<AuthorityKeyCertificate> certificates,
        IReadOnlyCollection<string> trustedFingerprints,
        DateTimeOffset now,
        out int validSignatures)
    {
        validSignatures = 0;
        if (trustedFingerprints.Count == 0) return false;
        if (!consensus.IsValidAt(now)) return false;

        var trusted = new HashSet<string>(trustedFingerprints, StringComparer.OrdinalIgnoreCase);
        var certs = certificates.ToList();
        var signers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (DirectorySignature sig in consensus.Signatures)
        {
            string identityHex = Convert.ToHexString(sig.IdentityFingerprint);
            if (!trusted.Contains(identityHex)) continue;
            if (signers.Contains(identityHex)) continue; // count each authority once

            AuthorityKeyCertificate? cert = certs.FirstOrDefault(c =>
                c.IdentityFingerprint.AsSpan().SequenceEqual(sig.IdentityFingerprint) &&
                c.SigningKeyDigest.AsSpan().SequenceEqual(sig.SigningKeyDigest));
            if (cert is null || cert.IsExpired(now)) continue;

            byte[]? digest = sig.Algorithm switch
            {
                "sha256" => consensus.SignedBodySha256,
                "sha1" => consensus.SignedBodySha1,
                _ => null,
            };
            if (digest is null) continue;

            if (TorRsa.VerifyRawPkcs1(cert.SigningKey, sig.Signature, digest))
                signers.Add(identityHex);
        }

        validSignatures = signers.Count;
        return validSignatures * 2 > trusted.Count; // strict majority
    }
}
