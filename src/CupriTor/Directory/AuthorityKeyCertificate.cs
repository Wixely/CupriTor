using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace CupriTor.Directory;

/// <summary>
/// A directory authority key certificate (dir-spec §3.1): binds an authority's medium-term signing
/// key to its long-term identity key. Parsing self-verifies the certificate (the identity key signs
/// it) and that the stated fingerprint matches the identity key. The identity fingerprint is the
/// trust anchor callers compare against the hardcoded authority set.
/// </summary>
internal sealed class AuthorityKeyCertificate
{
    public byte[] IdentityFingerprint { get; private init; } = Array.Empty<byte>(); // 20-byte SHA-1
    public RsaKeyParameters SigningKey { get; private init; } = null!;
    public byte[] SigningKeyDigest { get; private init; } = Array.Empty<byte>();     // SHA-1 of signing key DER
    public DateTimeOffset Expires { get; private init; }

    public bool IsExpired(DateTimeOffset now) => now >= Expires;

    public static bool TryParse(string text, out AuthorityKeyCertificate certificate)
    {
        certificate = null!;
        try
        {
            List<DirectoryItem> items = DirectoryReader.Parse(text);

            byte[]? statedFingerprint = null;
            byte[]? identityDer = null;
            byte[]? signingDer = null;
            byte[]? certificationSig = null;
            DateTimeOffset expires = default;

            foreach (DirectoryItem item in items)
            {
                switch (item.Keyword)
                {
                    case "fingerprint":
                        if (item.Arguments.Length >= 1) statedFingerprint = Convert.FromHexString(item.Arguments[0]);
                        break;
                    case "dir-key-expires":
                        expires = ParseTime(item.Arguments);
                        break;
                    case "dir-identity-key":
                        identityDer = item.ObjectData;
                        break;
                    case "dir-signing-key":
                        signingDer = item.ObjectData;
                        break;
                    case "dir-key-certification":
                        certificationSig = item.ObjectData;
                        break;
                }
            }

            if (statedFingerprint is null || identityDer is null || signingDer is null || certificationSig is null)
                return false;

            // The stated fingerprint must be the SHA-1 of the identity key.
            byte[] computedFp = TorRsa.Fingerprint(identityDer);
            if (!CryptographicOperations.FixedTimeEquals(computedFp, statedFingerprint))
                return false;

            // The identity key must sign the certificate (through "dir-key-certification\n").
            const string token = "dir-key-certification\n";
            int idx = text.IndexOf(token, StringComparison.Ordinal);
            if (idx < 0) return false;
            byte[] signedBody = Encoding.ASCII.GetBytes(text.Substring(0, idx + token.Length));
            byte[] signedDigest = SHA1.HashData(signedBody);

            RsaKeyParameters identityKey = TorRsa.ParsePkcs1PublicKey(identityDer);
            if (!TorRsa.VerifyRawPkcs1(identityKey, certificationSig, signedDigest))
                return false;

            certificate = new AuthorityKeyCertificate
            {
                IdentityFingerprint = computedFp,
                SigningKey = TorRsa.ParsePkcs1PublicKey(signingDer),
                SigningKeyDigest = TorRsa.Fingerprint(signingDer),
                Expires = expires,
            };
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException or OverflowException or IndexOutOfRangeException or ArgumentException)
        {
            return false;
        }
    }

    private static DateTimeOffset ParseTime(string[] a)
    {
        if (a.Length < 2) throw new DirectoryParseException("Malformed timestamp.");
        return DateTimeOffset.ParseExact($"{a[0]} {a[1]}", "yyyy-MM-dd HH:mm:ss",
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    }
}
