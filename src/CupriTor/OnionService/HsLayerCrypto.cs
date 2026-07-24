using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Digests;

namespace CupriTor.OnionService;

/// <summary>
/// The v3 HS descriptor layer encryption (rend-spec-v3 §2.5.1.1): each layer is
/// <c>SALT ‖ ENCRYPTED ‖ MAC</c>, where the AES-256-CTR key/IV and the SHA3-256 MAC key are derived
/// from SHAKE-256 over <c>secret_input ‖ salt ‖ string_constant</c>. Used for both the superencrypted
/// (outer) and encrypted (inner) layers, distinguished by the string constant.
/// </summary>
internal static class HsLayerCrypto
{
    public const int SaltLength = 16;
    private const int KeyLength = 32;   // AES-256
    private const int IvLength = 16;
    private const int MacKeyLength = 32;
    public const int MacLength = 32;

    public static readonly byte[] SuperencryptedConstant = Encoding.ASCII.GetBytes("hsdir-superencrypted-data");
    public static readonly byte[] EncryptedConstant = Encoding.ASCII.GetBytes("hsdir-encrypted-data");

    /// <summary>secret_input = blinded_public_key ‖ subcredential ‖ INT_8(revision_counter).</summary>
    public static byte[] SecretInput(ReadOnlySpan<byte> blindedKey, ReadOnlySpan<byte> subcredential, long revisionCounter)
    {
        var si = new byte[32 + 32 + 8];
        blindedKey.Slice(0, 32).CopyTo(si);
        subcredential.Slice(0, 32).CopyTo(si.AsSpan(32));
        BinaryPrimitives.WriteInt64BigEndian(si.AsSpan(64), revisionCounter);
        return si;
    }

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> secretInput, byte[] stringConstant, ReadOnlySpan<byte> salt)
    {
        (byte[] key, byte[] iv, byte[] macKey) = DeriveKeys(secretInput, salt, stringConstant);

        var encrypted = plaintext.ToArray();
        new AesCtrKeystream(key, iv).XorInPlace(encrypted);
        byte[] mac = Mac(macKey, salt, encrypted);

        var blob = new byte[salt.Length + encrypted.Length + mac.Length];
        salt.CopyTo(blob);
        encrypted.CopyTo(blob.AsSpan(salt.Length));
        mac.CopyTo(blob.AsSpan(salt.Length + encrypted.Length));
        return blob;
    }

    public static byte[] EncryptRandomSalt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> secretInput, byte[] stringConstant)
    {
        Span<byte> salt = stackalloc byte[SaltLength];
        RandomNumberGenerator.Fill(salt);
        return Encrypt(plaintext, secretInput, stringConstant, salt);
    }

    public static bool TryDecrypt(ReadOnlySpan<byte> blob, ReadOnlySpan<byte> secretInput, byte[] stringConstant, out byte[] plaintext)
    {
        plaintext = Array.Empty<byte>();
        if (blob.Length < SaltLength + MacLength) return false;

        ReadOnlySpan<byte> salt = blob.Slice(0, SaltLength);
        ReadOnlySpan<byte> encrypted = blob.Slice(SaltLength, blob.Length - SaltLength - MacLength);
        ReadOnlySpan<byte> mac = blob.Slice(blob.Length - MacLength);

        (byte[] key, byte[] iv, byte[] macKey) = DeriveKeys(secretInput, salt, stringConstant);

        byte[] expectedMac = Mac(macKey, salt, encrypted);
        if (!CryptographicOperations.FixedTimeEquals(expectedMac, mac)) return false;

        var decrypted = encrypted.ToArray();
        new AesCtrKeystream(key, iv).XorInPlace(decrypted);
        plaintext = decrypted;
        return true;
    }

    private static (byte[] Key, byte[] Iv, byte[] MacKey) DeriveKeys(ReadOnlySpan<byte> secretInput, ReadOnlySpan<byte> salt, byte[] stringConstant)
    {
        var shake = new ShakeDigest(256);
        shake.BlockUpdate(secretInput);
        shake.BlockUpdate(salt);
        shake.BlockUpdate(stringConstant, 0, stringConstant.Length);
        var keys = new byte[KeyLength + IvLength + MacKeyLength];
        shake.OutputFinal(keys, 0, keys.Length);

        return (keys[..KeyLength], keys[KeyLength..(KeyLength + IvLength)], keys[(KeyLength + IvLength)..]);
    }

    // MAC = SHA3-256( INT_8(len MAC_KEY) | MAC_KEY | INT_8(len SALT) | SALT | ENCRYPTED ).
    private static byte[] Mac(byte[] macKey, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> encrypted)
    {
        var sha3 = new Sha3Digest(256);
        Span<byte> len = stackalloc byte[8];

        BinaryPrimitives.WriteInt64BigEndian(len, macKey.Length);
        sha3.BlockUpdate(len);
        sha3.BlockUpdate(macKey, 0, macKey.Length);

        BinaryPrimitives.WriteInt64BigEndian(len, salt.Length);
        sha3.BlockUpdate(len);
        sha3.BlockUpdate(salt);

        sha3.BlockUpdate(encrypted);
        var result = new byte[32];
        sha3.DoFinal(result, 0);
        return result;
    }
}
