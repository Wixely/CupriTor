namespace CupriTor.Directory;

/// <summary>A trusted directory authority: a nickname and its long-term identity fingerprint (uppercase hex).</summary>
internal sealed record DirectoryAuthority(string Nickname, string IdentityFingerprint);

/// <summary>
/// The hardcoded directory authorities that anchor consensus trust.
/// <para>
/// DATA PLACEHOLDER: the real Tor directory-authority identity fingerprints/keys must be populated
/// from the Tor source (authority_dirs) and shipped as data. They are intentionally left empty here
/// rather than guessed, since a wrong value is a silent security hole. Callers can supply their own
/// set until this is filled.
/// </para>
/// </summary>
internal static class DirectoryAuthorities
{
    public static IReadOnlyList<DirectoryAuthority> Default { get; } = Array.Empty<DirectoryAuthority>();
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
