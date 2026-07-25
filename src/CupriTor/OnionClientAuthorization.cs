using CupriTor.Internal;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriTor;

/// <summary>
/// Client authorization for a private v3 onion service (rend-spec-v3 §2.5.1.2). A client has an x25519
/// keypair; the service is configured with the client's public key so only authorized clients can decrypt
/// the descriptor and connect. Keys use tor's base32 <c>descriptor:x25519:BASE32</c> format, interoperable
/// with the Tor Browser / c-tor <c>ClientOnionAuthDir</c> and <c>&lt;service&gt;/authorized_clients</c> files.
/// </summary>
public static class OnionClientAuthorization
{
    private const string Prefix = "descriptor:x25519:";

    /// <summary>Parse an authorized-client public key: a base32 x25519 key, with or without the "descriptor:x25519:" prefix.</summary>
    public static byte[] ParsePublicKey(string value)
    {
        string b32 = value.Trim();
        if (b32.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) b32 = b32[Prefix.Length..];
        if (!Base32.TryDecode(b32, out byte[] key) || key.Length != 32)
            throw new FormatException("Expected a base32-encoded 32-byte x25519 public key (optionally prefixed with 'descriptor:x25519:').");
        return key;
    }

    /// <summary>Format a 32-byte x25519 public key as a tor client-auth line: <c>descriptor:x25519:BASE32</c>.</summary>
    public static string FormatPublicKey(ReadOnlySpan<byte> publicKey32) => Prefix + Base32.Encode(publicKey32);

    /// <summary>
    /// Generate a fresh client authorization keypair. Give the <c>PublicLine</c> to the service operator
    /// (authorized clients); keep the <c>PrivateLine</c> in the client's Tor <c>ClientOnionAuthDir</c>.
    /// </summary>
    public static (string PublicLine, string PrivateLine, byte[] PublicKey, byte[] PrivateKey) GenerateClientKeyPair()
    {
        var priv = new X25519PrivateKeyParameters(new SecureRandom());
        byte[] privateKey = priv.GetEncoded();
        byte[] publicKey = priv.GeneratePublicKey().GetEncoded();
        return (FormatPublicKey(publicKey), Prefix + Base32.Encode(privateKey), publicKey, privateKey);
    }
}
