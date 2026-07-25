using System.Security.Cryptography;
using System.Text;
using CupriCurve;

namespace CupriTor;

/// <summary>
/// The long-term identity of a v3 onion service: an Ed25519 key whose public key encodes the .onion
/// address. Create a fresh random one, restore a persisted one, or import a pre-generated vanity key
/// (e.g. from mkp224o). Persist it as tor's own <c>hs_ed25519_secret_key</c> file so the address is stable
/// across restarts and interoperable with the Tor ecosystem.
///
/// Internally this is the <b>expanded</b> secret key (clamped scalar ‖ nonce prefix), which is what tor and
/// vanity generators store — a vanity key has no recoverable seed, so the expanded form is canonical.
/// </summary>
public sealed class OnionServiceKey
{
    private const string SecretTagText = "== ed25519v1-secret: type0 ==";
    private const string PublicTagText = "== ed25519v1-public: type0 ==";
    private const int TagLength = 32;
    private const int ExpandedLength = 64;              // scalar(32) ‖ prefix(32)
    private const int TorSecretFileLength = TagLength + ExpandedLength; // 96

    private readonly Ed25519ExpandedKey _expandedKey;

    /// <summary>The 32-byte Ed25519 identity public key (this encodes the .onion address).</summary>
    public byte[] PublicKey { get; }

    /// <summary>The onion address for this identity.</summary>
    public OnionAddress Address { get; }

    /// <summary>The onion address as a string, e.g. <c>xxxx…d.onion</c>.</summary>
    public string OnionAddress => Address.ToString();

    /// <summary>The expanded blinding-capable identity key (used internally by the service to sign descriptors).</summary>
    internal Ed25519ExpandedKey ExpandedKey => _expandedKey;

    private OnionServiceKey(Ed25519ExpandedKey expandedKey)
    {
        _expandedKey = expandedKey;
        var pub = new byte[32];
        expandedKey.GetPublicKey(pub);
        PublicKey = pub;
        Address = CupriTor.OnionAddress.FromPublicKey(pub); // throws if the key isn't a valid point
    }

    /// <summary>Generate a brand-new random identity (a fresh .onion address).</summary>
    public static OnionServiceKey CreateRandom()
    {
        Span<byte> seed = stackalloc byte[32];
        RandomNumberGenerator.Fill(seed);
        return new OnionServiceKey(Ed25519ExpandedKey.FromSeed(seed));
    }

    /// <summary>Derive an identity from a 32-byte Ed25519 seed (deterministic: same seed ⇒ same address).</summary>
    public static OnionServiceKey FromSeed(ReadOnlySpan<byte> seed32)
    {
        if (seed32.Length != 32) throw new ArgumentException("Seed must be 32 bytes.", nameof(seed32));
        return new OnionServiceKey(Ed25519ExpandedKey.FromSeed(seed32));
    }

    /// <summary>Import a 64-byte expanded secret key (clamped scalar ‖ nonce prefix) — e.g. a vanity key.</summary>
    public static OnionServiceKey FromExpandedSecretKey(ReadOnlySpan<byte> expanded64)
    {
        if (expanded64.Length != ExpandedLength) throw new ArgumentException("Expanded secret key must be 64 bytes.", nameof(expanded64));
        return new OnionServiceKey(Ed25519ExpandedKey.FromParts(expanded64[..32], expanded64[32..]));
    }

    /// <summary>
    /// Load an identity from tor's <c>hs_ed25519_secret_key</c> contents (96 bytes: a 32-byte tag + the
    /// 64-byte expanded key) or from a raw 64-byte expanded key. This is what mkp224o and tor produce.
    /// </summary>
    public static OnionServiceKey FromTorSecretKey(ReadOnlySpan<byte> fileContents) => fileContents.Length switch
    {
        TorSecretFileLength => FromExpandedSecretKey(fileContents[TagLength..]),
        ExpandedLength => FromExpandedSecretKey(fileContents),
        _ => throw new ArgumentException($"Expected {TorSecretFileLength} (tagged) or {ExpandedLength} (raw) bytes.", nameof(fileContents)),
    };

    /// <summary>The 64-byte expanded secret key (clamped scalar ‖ nonce prefix). Persist this to keep the address.</summary>
    public byte[] ExpandedSecretKey()
    {
        var result = new byte[ExpandedLength];
        _expandedKey.Scalar.CopyTo(result);
        _expandedKey.Prefix.CopyTo(result.AsSpan(32));
        return result;
    }

    /// <summary>Serialize to tor's <c>hs_ed25519_secret_key</c> file format (32-byte tag + 64-byte expanded key).</summary>
    public byte[] ToTorSecretKey() => Concat(Tag(SecretTagText), ExpandedSecretKey());

    /// <summary>Serialize to tor's <c>hs_ed25519_public_key</c> file format (32-byte tag + 32-byte public key).</summary>
    public byte[] ToTorPublicKey() => Concat(Tag(PublicTagText), PublicKey);

    /// <summary>The <c>hostname</c> file contents: the .onion address followed by a newline.</summary>
    public string Hostname => OnionAddress + "\n";

    private static byte[] Tag(string text)
    {
        var tag = new byte[TagLength];
        Encoding.ASCII.GetBytes(text).CopyTo(tag, 0); // NUL-padded to 32 bytes, matching tor
        return tag;
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }
}
