using System.Net;
using CupriTor.OnionService;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// Cross-checks the client INTRODUCE1 construction against the service open path and completes a full
/// hs-ntor rendezvous, all in-process. This validates the INTRODUCE1 byte layout, the AES-256-CTR
/// encryption, the MAC coverage, and that both sides derive the same rendezvous NTOR_KEY_SEED — the
/// crypto/format most likely to be subtly wrong. (Full Tor interop is validated live by the collector.)
/// </summary>
public class HsIntroduceTests
{
    [Fact]
    public void Client_Introduce1_Opens_And_Rendezvous_Key_Agrees()
    {
        var rng = new SecureRandom();

        // Service's introduction-point encryption keypair (Curve25519 "B").
        var introEncPriv = new X25519PrivateKeyParameters(rng);
        byte[] introEncPrivate = introEncPriv.GetEncoded();
        byte[] introEncPublic = introEncPriv.GeneratePublicKey().GetEncoded();

        byte[] authKey = RandomBytes(rng, 32);
        byte[] subcredential = RandomBytes(rng, 32);

        // Client builds INTRODUCE1.
        HsNtor.ClientState hs = HsNtor.ClientIntroduce(introEncPublic, authKey, subcredential);
        byte[] cookie = HsCells.NewRendezvousCookie();
        byte[] rpNtorKey = RandomBytes(rng, 32);
        var rpSpecs = new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(IPAddress.Parse("1.2.3.4"), 9001),
            LinkSpecifier.FromLegacyId(RandomBytes(rng, 20)),
            LinkSpecifier.FromEd25519Id(RandomBytes(rng, 32)),
        };
        byte[] rpSpecsBlob = LinkSpecifier.EncodeList(rpSpecs);

        byte[] introduce1 = HsIntroduce.Build(hs, authKey, cookie, rpNtorKey, rpSpecsBlob);

        // Service opens it: MAC verifies, decrypts, recovers the rendezvous info.
        Assert.True(HsIntroduce.TryOpen(introduce1, introEncPrivate, introEncPublic, subcredential, out IntroduceRequest req));
        Assert.Equal(cookie, req.RendezvousCookie);
        Assert.Equal(rpNtorKey, req.RendezvousNtorKey);
        Assert.Equal(hs.ClientPublic, req.ClientPublic);
        Assert.Equal(3, req.RendezvousLinkSpecifiers.Count);

        // Both sides derive the same rendezvous key seed.
        var rendezvous = HsNtor.ServiceRendezvous(introEncPrivate, introEncPublic, authKey, req.ClientPublic);
        Assert.NotNull(rendezvous);
        byte[]? clientSeed = HsNtor.ClientRendezvous(hs, rendezvous!.Value.ServicePublic, rendezvous.Value.Auth);
        Assert.NotNull(clientSeed);
        Assert.Equal(rendezvous.Value.NtorKeySeed, clientSeed);
    }

    [Fact]
    public void Tampered_Introduce1_Fails_Mac()
    {
        var rng = new SecureRandom();
        var introEncPriv = new X25519PrivateKeyParameters(rng);
        byte[] introEncPrivate = introEncPriv.GetEncoded();
        byte[] introEncPublic = introEncPriv.GeneratePublicKey().GetEncoded();
        byte[] authKey = RandomBytes(rng, 32);
        byte[] subcredential = RandomBytes(rng, 32);

        HsNtor.ClientState hs = HsNtor.ClientIntroduce(introEncPublic, authKey, subcredential);
        byte[] rpSpecsBlob = LinkSpecifier.EncodeList(new List<LinkSpecifier> { LinkSpecifier.FromLegacyId(RandomBytes(rng, 20)) });
        byte[] introduce1 = HsIntroduce.Build(hs, authKey, HsCells.NewRendezvousCookie(), RandomBytes(rng, 32), rpSpecsBlob);

        introduce1[^40] ^= 0xFF; // flip a byte inside the encrypted region
        Assert.False(HsIntroduce.TryOpen(introduce1, introEncPrivate, introEncPublic, subcredential, out _));
    }

    private static byte[] RandomBytes(SecureRandom rng, int n)
    {
        var b = new byte[n];
        rng.NextBytes(b);
        return b;
    }
}
