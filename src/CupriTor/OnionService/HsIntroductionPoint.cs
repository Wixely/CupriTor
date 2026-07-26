using System.Text;
using CupriTor.Directory;
using CupriTor.Protocol;

namespace CupriTor.OnionService;

/// <summary>
/// An introduction point from a decrypted descriptor (rend-spec-v3 §2.5.2.2): how to reach the intro
/// relay (link specifiers + its ntor onion key), the intro auth key, and the service's encryption key
/// at that intro point (the <c>B</c> used in hs-ntor).
/// </summary>
internal sealed record IntroductionPoint(
    ReadOnlyMemory<byte> LinkSpecifiers,
    byte[] OnionKeyNtor,
    byte[] AuthKey,
    byte[] EncKey);

/// <summary>Parsing of the descriptor's superencrypted (outer) decrypted layer (rend-spec-v3 §2.5.1.2).</summary>
internal static class HsSuperencryptedLayer
{
    /// <summary>Extract the inner encrypted blob (the "encrypted" MESSAGE) from the decrypted superencrypted layer.</summary>
    public static bool TryExtractInner(ReadOnlySpan<byte> plaintext, out byte[] innerBlob)
    {
        innerBlob = Array.Empty<byte>();
        try
        {
            foreach (DirectoryItem item in DirectoryReader.Parse(Encoding.ASCII.GetString(plaintext)))
            {
                if (item.Keyword == "encrypted" && item.ObjectData is not null)
                {
                    innerBlob = item.ObjectData;
                    return true;
                }
            }
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException or OverflowException or IndexOutOfRangeException or ArgumentException) { }
        return false;
    }
}

/// <summary>Parsing of the descriptor's inner (encrypted) decrypted layer into introduction points (rend-spec-v3 §2.5.2.2).</summary>
internal static class HsInnerLayer
{
    public static bool TryParse(ReadOnlySpan<byte> plaintext, out List<IntroductionPoint> introductionPoints)
    {
        var result = new List<IntroductionPoint>();
        introductionPoints = result;
        try
        {
            List<DirectoryItem> items = DirectoryReader.Parse(Encoding.ASCII.GetString(plaintext));

            Builder? current = null;
            void Flush()
            {
                if (current?.TryBuild(out IntroductionPoint? ip) == true)
                    result.Add(ip!);
                current = null;
            }

            foreach (DirectoryItem item in items)
            {
                switch (item.Keyword)
                {
                    case "introduction-point":
                        Flush();
                        current = new Builder();
                        if (item.Arguments.Length >= 1) current.LinkSpecifiers = DirectoryReader.Base64(item.Arguments[0]);
                        break;
                    case "onion-key":
                        if (current is not null && item.Arguments is ["ntor", var ok, ..])
                            current.OnionKey = DirectoryReader.Base64(ok);
                        break;
                    case "auth-key":
                        if (current is not null && item.ObjectData is not null && TorCertificate.TryParse(item.ObjectData, out TorCertificate authCert))
                            current.AuthKey = authCert.CertifiedKey.ToArray();
                        break;
                    case "enc-key":
                        if (current is not null && item.Arguments is ["ntor", var ek, ..])
                            current.EncKey = DirectoryReader.Base64(ek);
                        break;
                }
            }
            Flush();
            return true;
        }
        catch (Exception e) when (e is DirectoryParseException or FormatException or OverflowException or IndexOutOfRangeException or ArgumentException)
        {
            introductionPoints = new List<IntroductionPoint>();
            return false;
        }
    }

    private sealed class Builder
    {
        public byte[]? LinkSpecifiers;
        public byte[]? OnionKey;
        public byte[]? AuthKey;
        public byte[]? EncKey;

        public bool TryBuild(out IntroductionPoint? introductionPoint)
        {
            introductionPoint = null;
            if (LinkSpecifiers is null || OnionKey is not { Length: 32 } || AuthKey is not { Length: 32 } || EncKey is not { Length: 32 })
                return false;
            introductionPoint = new IntroductionPoint(LinkSpecifiers, OnionKey, AuthKey, EncKey);
            return true;
        }
    }
}
