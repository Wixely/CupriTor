using System.Net;
using System.Text;
using CupriCurve;
using CupriTor.Directory;
using CupriTor.OnionService;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
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
    public void Private_Descriptor_Only_Authorized_Client_Can_Decrypt()
    {
        Service svc = MakeService(0x60);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);

        // The authorized client's x25519 keypair.
        var clientPriv = new X25519PrivateKeyParameters(new SecureRandom());
        byte[] clientPub = clientPriv.GeneratePublicKey().GetEncoded();
        byte[] clientPrivRaw = clientPriv.GetEncoded();

        var rng = new Random(11);
        byte[] Rand(int n) { var a = new byte[n]; rng.NextBytes(a); return a; }
        var specs = LinkSpecifier.EncodeList(new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(IPAddress.Parse("10.1.2.3"), 9001),
            LinkSpecifier.FromLegacyId(Rand(20)),
        });
        var authKey = Ed25519ExpandedKey.FromSeed(Rand(32));
        var authPub = new byte[32];
        authKey.GetPublicKey(authPub);
        var ips = new List<PublishIntroPoint> { new(specs, Rand(32), authPub, Rand(32)) };

        // Service publishes a PRIVATE descriptor authorizing this one client.
        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), ips, new[] { clientPub });

        // Client: verify + decrypt the outer (no cookie) layer.
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        var clientBlinded = new byte[32];
        HsBlinding.TryBlindPublicKey(svc.IdentityPublic, svc.Tp, PeriodLen, clientBlinded);
        Assert.True(view.TryVerify(clientBlinded, out _));
        byte[] clientSubcred = HsBlinding.Subcredential(svc.IdentityPublic, clientBlinded);
        byte[] outerSecret = HsLayerCrypto.SecretInput(clientBlinded, clientSubcred, view.RevisionCounter);
        Assert.True(HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, outerSecret, HsLayerCrypto.SuperencryptedConstant, out byte[] outerPlain));

        // The authorized client recovers the descriptor cookie and decrypts the inner layer.
        byte[]? cookie = RecoverCookie(outerPlain, clientPrivRaw, clientSubcred);
        Assert.NotNull(cookie);
        Assert.True(HsSuperencryptedLayer.TryExtractInner(outerPlain, out byte[] innerBlob));
        byte[] innerSecret = HsLayerCrypto.SecretInput(clientBlinded, clientSubcred, view.RevisionCounter, cookie);
        Assert.True(HsLayerCrypto.TryDecrypt(innerBlob, innerSecret, HsLayerCrypto.EncryptedConstant, out byte[] innerPlain));
        Assert.True(HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> parsed));
        Assert.Single(parsed);
        Assert.Equal(authPub, parsed[0].AuthKey);

        // An UNAUTHORIZED client (different key) cannot find its entry / recover the cookie.
        byte[] stranger = new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();
        Assert.Null(RecoverCookie(outerPlain, stranger, clientSubcred));
    }

    // Client-side recovery of the descriptor cookie from the decrypted superencrypted layer (rend-spec-v3 §2.5.1.3).
    private static byte[]? RecoverCookie(byte[] outerPlain, byte[] clientPrivate, byte[] subcredential)
    {
        byte[]? ephemeralPub = null;
        var entries = new List<(byte[] Id, byte[] Iv, byte[] Enc)>();
        foreach (DirectoryItem item in DirectoryReader.Parse(Encoding.ASCII.GetString(outerPlain)))
        {
            if (item.Keyword == "desc-auth-ephemeral-key") ephemeralPub = DirectoryReader.Base64(item.Arguments[0]);
            else if (item.Keyword == "auth-client")
                entries.Add((DirectoryReader.Base64(item.Arguments[0]), DirectoryReader.Base64(item.Arguments[1]), DirectoryReader.Base64(item.Arguments[2])));
        }
        if (ephemeralPub is null) return null;

        var ag = new X25519Agreement();
        ag.Init(new X25519PrivateKeyParameters(clientPrivate, 0));
        var seed = new byte[ag.AgreementSize];
        ag.CalculateAgreement(new X25519PublicKeyParameters(ephemeralPub, 0), seed, 0);

        var shake = new ShakeDigest(256);
        shake.BlockUpdate(subcredential, 0, subcredential.Length);
        shake.BlockUpdate(seed, 0, seed.Length);
        var keys = new byte[40];
        shake.OutputFinal(keys, 0, keys.Length);
        byte[] clientId = keys[..8];
        byte[] cookieKey = keys[8..40];

        foreach ((byte[] id, byte[] iv, byte[] enc) in entries)
            if (id.AsSpan().SequenceEqual(clientId))
            {
                byte[] cookie = (byte[])enc.Clone();
                new AesCtrKeystream(cookieKey, iv).XorInPlace(cookie);
                return cookie;
            }
        return null;
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

    // ---- Client-side connect to PRIVATE onions: the PRODUCTION decrypt path (HsDescriptorClient.DecryptIntroPoints),
    //      round-tripped offline against the service-side HsDescriptorBuilder. ----

    private static List<PublishIntroPoint> SampleIntroPoints(int seed, int count = 2)
    {
        var rng = new Random(seed);
        byte[] Rand(int n) { var a = new byte[n]; rng.NextBytes(a); return a; }
        var ips = new List<PublishIntroPoint>();
        for (int i = 0; i < count; i++)
        {
            byte[] specs = LinkSpecifier.EncodeList(new List<LinkSpecifier>
            {
                LinkSpecifier.FromIPv4(IPAddress.Parse($"10.5.0.{i + 1}"), (ushort)(9100 + i)),
                LinkSpecifier.FromLegacyId(Rand(20)),
                LinkSpecifier.FromEd25519Id(Rand(32)),
            });
            var authKey = Ed25519ExpandedKey.FromSeed(Rand(32));
            var authPub = new byte[32];
            authKey.GetPublicKey(authPub);
            ips.Add(new PublishIntroPoint(specs, Rand(32), authPub, Rand(32)));
        }
        return ips;
    }

    private static (byte[] Blinded, byte[] Subcred) ClientView(Service svc)
    {
        var blinded = new byte[32];
        HsBlinding.TryBlindPublicKey(svc.IdentityPublic, svc.Tp, PeriodLen, blinded);
        return (blinded, HsBlinding.Subcredential(svc.IdentityPublic, blinded));
    }

    [Fact]
    public void Production_Decrypt_Recovers_IntroPoints_For_An_Authorized_Client()
    {
        Service svc = MakeService(0x70);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);

        var clientPriv = new X25519PrivateKeyParameters(new SecureRandom());
        byte[] clientPub = clientPriv.GeneratePublicKey().GetEncoded();
        byte[] clientPrivRaw = clientPriv.GetEncoded();

        List<PublishIntroPoint> ips = SampleIntroPoints(21, 2);
        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), ips, new[] { clientPub });

        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        (byte[] blinded, byte[] clientSubcred) = ClientView(svc);
        Assert.True(view.TryVerify(blinded, out _));

        List<IntroductionPoint>? intros = HsDescriptorClient.DecryptIntroPoints(view, blinded, clientSubcred, clientPrivRaw);
        Assert.NotNull(intros);
        Assert.Equal(2, intros!.Count);
        Assert.Equal(ips[0].AuthKeyPublic, intros[0].AuthKey);
        Assert.Equal(ips[1].AuthKeyPublic, intros[1].AuthKey);
    }

    [Fact]
    public void Production_Decrypt_Throws_For_An_Unauthorized_Key()
    {
        Service svc = MakeService(0x71);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);

        byte[] authorizedPub = new X25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey().GetEncoded();
        byte[] strangerPrivRaw = new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();

        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), SampleIntroPoints(22), new[] { authorizedPub });
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        (byte[] blinded, byte[] clientSubcred) = ClientView(svc);

        var ex = Assert.Throws<OnionClientAuthorizationRequiredException>(() =>
            HsDescriptorClient.DecryptIntroPoints(view, blinded, clientSubcred, strangerPrivRaw));
        Assert.False(ex.NoKeySupplied); // a key was supplied, it just wasn't authorized
    }

    [Fact]
    public void Production_Decrypt_Throws_When_A_Private_Onion_Gets_No_Key()
    {
        Service svc = MakeService(0x72);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);
        byte[] authorizedPub = new X25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey().GetEncoded();

        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), SampleIntroPoints(23), new[] { authorizedPub });
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        (byte[] blinded, byte[] clientSubcred) = ClientView(svc);

        var ex = Assert.Throws<OnionClientAuthorizationRequiredException>(() =>
            HsDescriptorClient.DecryptIntroPoints(view, blinded, clientSubcred, ReadOnlySpan<byte>.Empty));
        Assert.True(ex.NoKeySupplied); // private onion, no key at all
    }

    [Fact]
    public void Production_Decrypt_Handles_A_Public_Onion_Without_A_Key()
    {
        Service svc = MakeService(0x73);
        byte[] subcred = HsBlinding.Subcredential(svc.IdentityPublic, svc.BlindedPublic);

        // Public descriptor (no authorized clients) still decrypts with no key — the private path doesn't regress it.
        string descriptor = HsDescriptorBuilder.Build(svc.BlindedKey, svc.BlindedPublic, subcred, Revision, 180, Now.AddHours(3), SampleIntroPoints(24, 3));
        Assert.True(HsDescriptor.TryParse(descriptor, out HsDescriptorView view));
        (byte[] blinded, byte[] clientSubcred) = ClientView(svc);

        List<IntroductionPoint>? intros = HsDescriptorClient.DecryptIntroPoints(view, blinded, clientSubcred, ReadOnlySpan<byte>.Empty);
        Assert.NotNull(intros);
        Assert.Equal(3, intros!.Count);
    }

    [Fact]
    public void OnionClientAuth_Parses_A_Tor_Private_Line_To_The_Raw_Key()
    {
        (string _, string privateLine, byte[] _, byte[] privateKey) = OnionClientAuthorization.GenerateClientKeyPair();
        Assert.StartsWith("descriptor:x25519:", privateLine);
        Assert.Equal(32, privateKey.Length);

        OnionClientAuth fromLine = OnionClientAuth.FromTorPrivateKey(privateLine);
        OnionClientAuth fromRaw = OnionClientAuth.FromX25519PrivateKey(privateKey);
        Assert.Equal(privateKey, fromLine.PrivateKey.ToArray());
        Assert.Equal(privateKey, fromRaw.PrivateKey.ToArray());

        Assert.Throws<ArgumentException>(() => OnionClientAuth.FromX25519PrivateKey(new byte[31]));
    }
}
