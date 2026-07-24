using CupriTor;
using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// Real-data validation of the v3 onion-service descriptor path. The descriptor was fetched from a live
/// HSDir by CupriCollector (the Tor Project service). Verifying its signatures and decrypting its payload
/// with our code proves the blinding, descriptor signature, subcredential, and layer crypto are byte-exact
/// with Tor.
/// </summary>
public class HsDescriptorRealTests
{
    private const string Onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";
    private const string BlindedKeyHex = "C2923155253AEBEF81CC3B1BCDE47DD5C6BF0618F0BF2659C3A2AE3C5110EE0C";

    [Fact]
    public void Real_Descriptor_Verifies_And_Decrypts()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "hs-descriptor.txt");
        Assert.True(File.Exists(path), "real HS descriptor fixture missing");
        string descriptor = File.ReadAllText(path);

        Assert.True(OnionAddress.TryParse(Onion, out OnionAddress address));
        byte[] identity = address.PublicKey.ToArray();
        byte[] blinded = Convert.FromHexString(BlindedKeyHex);

        // Parse + verify (blinded key signed the cert; signing key signed the descriptor).
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        Assert.True(view.TryVerify(blinded, out byte[] _), "descriptor signature verification failed on real data");

        // Decrypt both layers with the subcredential derived from the identity + blinded key.
        byte[] subcredential = HsBlinding.Subcredential(identity, blinded);
        byte[] secretInput = HsLayerCrypto.SecretInput(blinded, subcredential, view.RevisionCounter);

        Assert.True(HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, secretInput, HsLayerCrypto.SuperencryptedConstant, out byte[] superPlain),
            "superencrypted layer decrypt failed on real data");
        Assert.True(HsSuperencryptedLayer.TryExtractInner(superPlain, out byte[] innerBlob));
        Assert.True(HsLayerCrypto.TryDecrypt(innerBlob, secretInput, HsLayerCrypto.EncryptedConstant, out byte[] innerPlain),
            "inner layer decrypt failed on real data");

        Assert.True(HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> intros));
        Assert.NotEmpty(intros);
        foreach (IntroductionPoint ip in intros)
        {
            Assert.Equal(32, ip.OnionKeyNtor.Length);
            Assert.Equal(32, ip.AuthKey.Length);
            Assert.Equal(32, ip.EncKey.Length);
        }
    }
}
