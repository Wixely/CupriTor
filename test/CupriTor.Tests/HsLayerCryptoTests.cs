using System.Security.Cryptography;
using System.Text;
using CupriCurve;
using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

public class HsLayerCryptoTests
{
    private static byte[] Identity(byte b)
    {
        var seed = new byte[32]; Array.Fill(seed, b);
        var pub = new byte[32]; Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(pub);
        return pub;
    }

    private static (byte[] SecretInput, byte[] Blinded, byte[] Subcred) Context(byte idByte, long revision)
    {
        byte[] identity = Identity(idByte);
        var blinded = new byte[32];
        HsBlinding.TryBlindPublicKey(identity, 500, HsTimePeriod.DefaultLengthMinutes, blinded);
        byte[] subcred = HsBlinding.Subcredential(identity, blinded);
        byte[] si = HsLayerCrypto.SecretInput(blinded, subcred, revision);
        return (si, blinded, subcred);
    }

    [Fact]
    public void Layer_Encrypt_Decrypt_RoundTrips()
    {
        (byte[] si, _, _) = Context(1, revision: 3);
        byte[] plaintext = Encoding.ASCII.GetBytes("intro points and stuff go here");

        byte[] blob = HsLayerCrypto.EncryptRandomSalt(plaintext, si, HsLayerCrypto.EncryptedConstant);
        Assert.True(HsLayerCrypto.TryDecrypt(blob, si, HsLayerCrypto.EncryptedConstant, out byte[] recovered));
        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Two_Layers_Superencrypted_Then_Encrypted_RoundTrip()
    {
        (byte[] si, _, _) = Context(2, revision: 7);
        byte[] inner = Encoding.ASCII.GetBytes("the real inner descriptor with introduction-point sections");

        // Inner (encrypted) layer, then wrap it in the outer (superencrypted) layer.
        byte[] innerBlob = HsLayerCrypto.EncryptRandomSalt(inner, si, HsLayerCrypto.EncryptedConstant);
        byte[] superBlob = HsLayerCrypto.EncryptRandomSalt(innerBlob, si, HsLayerCrypto.SuperencryptedConstant);

        Assert.True(HsLayerCrypto.TryDecrypt(superBlob, si, HsLayerCrypto.SuperencryptedConstant, out byte[] recoveredInnerBlob));
        Assert.Equal(innerBlob, recoveredInnerBlob);
        Assert.True(HsLayerCrypto.TryDecrypt(recoveredInnerBlob, si, HsLayerCrypto.EncryptedConstant, out byte[] recoveredInner));
        Assert.Equal(inner, recoveredInner);
    }

    [Fact]
    public void Wrong_String_Constant_Fails_Mac()
    {
        (byte[] si, _, _) = Context(3, revision: 1);
        byte[] blob = HsLayerCrypto.EncryptRandomSalt(new byte[] { 1, 2, 3, 4 }, si, HsLayerCrypto.EncryptedConstant);
        Assert.False(HsLayerCrypto.TryDecrypt(blob, si, HsLayerCrypto.SuperencryptedConstant, out _)); // different key -> MAC mismatch
    }

    [Fact]
    public void Tampering_Fails_Mac()
    {
        (byte[] si, _, _) = Context(4, revision: 1);
        byte[] blob = HsLayerCrypto.EncryptRandomSalt(new byte[64], si, HsLayerCrypto.EncryptedConstant);

        byte[] tamperedCipher = (byte[])blob.Clone();
        tamperedCipher[HsLayerCrypto.SaltLength] ^= 0xFF;
        Assert.False(HsLayerCrypto.TryDecrypt(tamperedCipher, si, HsLayerCrypto.EncryptedConstant, out _));

        byte[] tamperedMac = (byte[])blob.Clone();
        tamperedMac[^1] ^= 0xFF;
        Assert.False(HsLayerCrypto.TryDecrypt(tamperedMac, si, HsLayerCrypto.EncryptedConstant, out _));
    }

    [Fact]
    public void Different_Revision_Yields_Different_Ciphertext()
    {
        (byte[] si1, _, _) = Context(5, revision: 1);
        (byte[] si2, _, _) = Context(5, revision: 2);
        byte[] salt = new byte[HsLayerCrypto.SaltLength]; // fixed salt to isolate the revision effect
        RandomNumberGenerator.Fill(salt);
        byte[] plain = Encoding.ASCII.GetBytes("same plaintext");

        byte[] a = HsLayerCrypto.Encrypt(plain, si1, HsLayerCrypto.EncryptedConstant, salt);
        byte[] b = HsLayerCrypto.Encrypt(plain, si2, HsLayerCrypto.EncryptedConstant, salt);
        Assert.NotEqual(a, b);
    }
}
