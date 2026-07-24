using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// A real-relay ntor known-answer test. These values were captured by CupriCollector completing an
/// actual CREATE2/CREATED2 handshake with a live Tor relay (fsckinggoogle / node
/// 7C781344302E21A6A954D7D794255CFD294D50EE) on 2026-07-24. Reconstructing the client state with the
/// recorded ephemeral key must reproduce the exact KEY_SEED the relay agreed on — proving our ntor
/// (X25519 + HMAC/HKDF + the secret-input construction) interoperates with real Tor, deterministically.
/// </summary>
public class NtorRealVectorTests
{
    private static byte[] Hex(string s) => Convert.FromHexString(s);

    [Fact]
    public void Reproduces_Live_Relay_KeySeed()
    {
        byte[] nodeId = Hex("7C781344302E21A6A954D7D794255CFD294D50EE");
        byte[] ntorOnionKey = Hex("5DDEC3767F635DE07000D6806A37EE8EFB35A24C1E7572997C30A8FA2D80E775");
        byte[] ephemeralPrivate = Hex("E09B7BB2BDF118C962FC9CB350F486317A73F5A732FEB39F9290C0123D448452");
        byte[] clientPublic = Hex("1FC4AC8FD7EDBFB5580ED633E889EE998FA83BFE9106F705438718E585365927");
        byte[] created2 = Hex("ECA492E3B364FF352A133029CB0C2D2E554BBDEBD9ABAB493B6F0418ECAD0C52BED274176904070FD160ABA3F7326D8C0C9FF25545042949FC00C5A569E36D05");
        byte[] expectedKeySeed = Hex("D31EB6A831EFD02709847B588CCE02BD793134B6FDD3F6AE2B8776F9FFED7450");

        var state = new Ntor.ClientState
        {
            NodeId = nodeId,
            RelayNtorKey = ntorOnionKey,
            Ephemeral = new X25519PrivateKeyParameters(ephemeralPrivate, 0),
            X = clientPublic,
        };

        byte[]? keySeed = Ntor.CompleteClient(state, created2);

        Assert.NotNull(keySeed);
        Assert.Equal(expectedKeySeed, keySeed);

        // And the derived relay key material is likewise reproducible.
        Assert.Equal(72, Ntor.DeriveKeys(keySeed!, 72).Length);
    }
}
