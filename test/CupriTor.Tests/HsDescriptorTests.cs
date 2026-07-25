using System.Net;
using System.Text;
using CupriCurve;
using CupriTor.OnionService;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class HsDescriptorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 24, 15, 0, 0, TimeSpan.Zero);
    private static readonly byte[] Personalization = Encoding.ASCII.GetBytes("Derive temporary signing key hash input");
    private const int PeriodLen = 1440;
    private const long Revision = 5;

    private static byte[] Fill(byte b) { var a = new byte[32]; Array.Fill(a, b); return a; }

    private sealed record Service(byte[] IdentityPublic, Ed25519ExpandedKey BlindedKey, byte[] BlindedPublic, long Tp);

    private static Service MakeService(byte idByte)
    {
        var identityKey = Ed25519ExpandedKey.FromSeed(Fill(idByte));
        var identityPub = new byte[32];
        identityKey.GetPublicKey(identityPub);

        long tp = HsTimePeriod.Number(Now, PeriodLen);
        byte[] h = HsBlinding.BlindingFactor(identityPub, tp, PeriodLen);

        var aPrime = new byte[32];
        var rhPrime = new byte[32];
        TorBlinding.BlindPrivateKey(identityKey, h, Personalization, aPrime, rhPrime);
        var blindedKey = Ed25519ExpandedKey.FromParts(aPrime, rhPrime);

        var blindedPub = new byte[32];
        HsBlinding.TryBlindPublicKey(identityPub, tp, PeriodLen, blindedPub);

        // The blinded private key's public must match the point-blinded public key.
        var check = new byte[32];
        blindedKey.GetPublicKey(check);
        Assert.Equal(blindedPub, check);

        return new Service(identityPub, blindedKey, blindedPub, tp);
    }

    private static string BuildDescriptor(Service s, byte[] innerPlaintext)
    {
        byte[] subcred = HsBlinding.Subcredential(s.IdentityPublic, s.BlindedPublic);
        byte[] secretInput = HsLayerCrypto.SecretInput(s.BlindedPublic, subcred, Revision);
        byte[] superBlob = HsLayerCrypto.EncryptRandomSalt(innerPlaintext, secretInput, HsLayerCrypto.SuperencryptedConstant);
        return HsDescriptor.Build(s.BlindedKey, s.BlindedPublic, Fill(0x99), Revision, 180, Now.AddHours(54), superBlob);
    }

    [Fact]
    public void Descriptor_Builds_Verifies_And_Decrypts_As_Client()
    {
        Service svc = MakeService(0x42);
        byte[] inner = Encoding.ASCII.GetBytes("create2-formats 2\nintroduction-point AQAG... (intro sections here)");
        string descriptor = BuildDescriptor(svc, inner);

        // Client parses.
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        Assert.Equal(180, view.Lifetime);
        Assert.Equal(Revision, view.RevisionCounter);

        // Client independently derives the blinded key from the identity + period, then verifies.
        var clientBlinded = new byte[32];
        HsBlinding.TryBlindPublicKey(svc.IdentityPublic, svc.Tp, PeriodLen, clientBlinded);
        Assert.True(view.TryVerify(clientBlinded, out byte[] _));

        // Client decrypts the superencrypted payload.
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, clientBlinded);
        byte[] secretInput = HsLayerCrypto.SecretInput(clientBlinded, subcred, view.RevisionCounter);
        Assert.True(HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, secretInput, HsLayerCrypto.SuperencryptedConstant, out byte[] recovered));
        Assert.Equal(inner, recovered);
    }

    [Fact]
    public void Published_Descriptor_RoundTrips_Through_Client_Decrypt_And_IntroParse()
    {
        Service svc = MakeService(0x50);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);

        var rng = new Random(9);
        byte[] Rand(int n) { var a = new byte[n]; rng.NextBytes(a); return a; }

        var ips = new List<PublishIntroPoint>();
        for (int i = 0; i < 2; i++)
        {
            byte[] specs = LinkSpecifier.EncodeList(new List<LinkSpecifier>
            {
                LinkSpecifier.FromIPv4(IPAddress.Parse($"10.0.0.{i + 1}"), (ushort)(9000 + i)),
                LinkSpecifier.FromLegacyId(Rand(20)),
                LinkSpecifier.FromEd25519Id(Rand(32)),
            });
            var authKey = Ed25519ExpandedKey.FromSeed(Rand(32));
            var authPub = new byte[32];
            authKey.GetPublicKey(authPub);
            ips.Add(new PublishIntroPoint(specs, Rand(32), authPub, Rand(32)));
        }

        // Service builds the full descriptor (inner intro-point layer + superencrypted layer + signed outer).
        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), ips);

        // Client side: parse, verify the signatures, decrypt BOTH layers, and parse the intro points back.
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        var clientBlinded = new byte[32];
        HsBlinding.TryBlindPublicKey(svc.IdentityPublic, svc.Tp, PeriodLen, clientBlinded);
        Assert.True(view.TryVerify(clientBlinded, out _));

        byte[] clientSubcred = HsBlinding.Subcredential(svc.IdentityPublic, clientBlinded);
        byte[] secretInput = HsLayerCrypto.SecretInput(clientBlinded, clientSubcred, view.RevisionCounter);
        Assert.True(HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, secretInput, HsLayerCrypto.SuperencryptedConstant, out byte[] superPlain));
        Assert.True(HsSuperencryptedLayer.TryExtractInner(superPlain, out byte[] innerBlob));
        Assert.True(HsLayerCrypto.TryDecrypt(innerBlob, secretInput, HsLayerCrypto.EncryptedConstant, out byte[] innerPlain));
        Assert.True(HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> parsed));

        Assert.Equal(2, parsed.Count);
        Assert.Equal(ips[0].AuthKeyPublic, parsed[0].AuthKey);
        Assert.Equal(ips[0].EncKeyPublic, parsed[0].EncKey);
        Assert.Equal(ips[0].IntroRelayNtorKey, parsed[0].OnionKeyNtor);
        Assert.Equal(ips[1].AuthKeyPublic, parsed[1].AuthKey);
    }

    [Fact]
    public void Verification_Fails_For_Wrong_Blinded_Key()
    {
        Service svc = MakeService(0x43);
        string descriptor = BuildDescriptor(svc, Encoding.ASCII.GetBytes("inner"));
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));

        var wrong = new byte[32];
        HsBlinding.TryBlindPublicKey(MakeService(0x44).IdentityPublic, svc.Tp, PeriodLen, wrong);
        Assert.False(view.TryVerify(wrong, out _));
    }

    [Fact]
    public void Verification_Fails_When_Document_Tampered()
    {
        Service svc = MakeService(0x45);
        string descriptor = BuildDescriptor(svc, Encoding.ASCII.GetBytes("inner"));

        // Flip a digit in the revision-counter (inside the signed body).
        string tampered = descriptor.Replace("revision-counter 5", "revision-counter 6");
        Assert.True(HsDescriptor.TryParse(tampered, out HsDescriptorView view));

        var clientBlinded = new byte[32];
        HsBlinding.TryBlindPublicKey(svc.IdentityPublic, svc.Tp, PeriodLen, clientBlinded);
        Assert.False(view.TryVerify(clientBlinded, out _));
    }
}
