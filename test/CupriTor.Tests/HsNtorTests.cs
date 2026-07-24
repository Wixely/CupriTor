using CupriTor.OnionService;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

public class HsNtorTests
{
    private static (byte[] Private, byte[] Public) IntroEncKey(SecureRandom rng)
    {
        var priv = new X25519PrivateKeyParameters(rng);
        return (priv.GetEncoded(), priv.GeneratePublicKey().GetEncoded());
    }

    [Fact]
    public void Client_And_Service_Agree_On_Intro_And_Rendezvous_Keys()
    {
        var rng = new SecureRandom();
        (byte[] introPriv, byte[] introPub) = IntroEncKey(rng);
        var authKey = new byte[32]; rng.NextBytes(authKey);
        var subcred = new byte[32]; rng.NextBytes(subcred);

        // Client builds INTRODUCE1 keys.
        HsNtor.ClientState client = HsNtor.ClientIntroduce(introPub, authKey, subcred, rng);

        // Service recovers the same INTRODUCE1 keys.
        var serviceIntro = HsNtor.ServiceIntroduce(introPriv, introPub, authKey, subcred, client.ClientPublic);
        Assert.NotNull(serviceIntro);
        Assert.Equal(client.IntroEncryptKey, serviceIntro!.Value.EncKey);
        Assert.Equal(client.IntroMacKey, serviceIntro.Value.MacKey);

        // Service completes the rendezvous.
        var rend = HsNtor.ServiceRendezvous(introPriv, introPub, authKey, client.ClientPublic, rng);
        Assert.NotNull(rend);
        (byte[] servicePub, byte[] serviceSeed, byte[] auth) = rend!.Value;

        // Client verifies and derives the same NTOR_KEY_SEED.
        byte[]? clientSeed = HsNtor.ClientRendezvous(client, servicePub, auth);
        Assert.NotNull(clientSeed);
        Assert.Equal(serviceSeed, clientSeed);

        Assert.Equal(HsNtor.DeriveKeys(serviceSeed, 72), HsNtor.DeriveKeys(clientSeed!, 72));
    }

    [Fact]
    public void Client_Rejects_Tampered_Auth()
    {
        var rng = new SecureRandom();
        (byte[] introPriv, byte[] introPub) = IntroEncKey(rng);
        var authKey = new byte[32]; rng.NextBytes(authKey);
        var subcred = new byte[32]; rng.NextBytes(subcred);

        HsNtor.ClientState client = HsNtor.ClientIntroduce(introPub, authKey, subcred, rng);
        (byte[] servicePub, _, byte[] auth) = HsNtor.ServiceRendezvous(introPriv, introPub, authKey, client.ClientPublic, rng)!.Value;
        auth[^1] ^= 0xFF;

        Assert.Null(HsNtor.ClientRendezvous(client, servicePub, auth));
    }

    [Fact]
    public void Wrong_Subcredential_Breaks_Intro_Keys()
    {
        var rng = new SecureRandom();
        (byte[] introPriv, byte[] introPub) = IntroEncKey(rng);
        var authKey = new byte[32]; rng.NextBytes(authKey);
        var subcred = new byte[32]; rng.NextBytes(subcred);
        var wrongSubcred = new byte[32]; rng.NextBytes(wrongSubcred);

        HsNtor.ClientState client = HsNtor.ClientIntroduce(introPub, authKey, subcred, rng);
        var serviceIntro = HsNtor.ServiceIntroduce(introPriv, introPub, authKey, wrongSubcred, client.ClientPublic);
        Assert.NotNull(serviceIntro);
        Assert.NotEqual(client.IntroEncryptKey, serviceIntro!.Value.EncKey);
    }
}
