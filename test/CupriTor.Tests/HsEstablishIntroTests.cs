using CupriCurve;
using CupriTor.OnionService;
using Org.BouncyCastle.Security;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.Tests;

public class HsEstablishIntroTests
{
    [Fact]
    public void EstablishIntro_Layout_Mac_And_Signature_Are_Correct()
    {
        var rng = new SecureRandom();
        var seed = new byte[32];
        rng.NextBytes(seed);
        var signer = Ed25519ExpandedKey.FromSeed(seed);
        var authPub = new byte[32];
        signer.GetPublicKey(authPub);
        var kh = new byte[20];
        rng.NextBytes(kh);

        byte[] cell = HsEstablishIntro.Build(authPub, signer, kh);

        // AUTH_KEY_TYPE(1) AUTH_KEY_LEN(2) AUTH_KEY(32) N_EXTENSIONS(1) HANDSHAKE_AUTH(32) SIG_LEN(2) SIG(64) = 134.
        Assert.Equal(134, cell.Length);
        Assert.Equal(0x02, cell[0]);
        Assert.Equal(0x0020, (cell[1] << 8) | cell[2]);
        Assert.Equal(authPub, cell[3..35]);
        Assert.Equal(0x00, cell[35]);                 // N_EXTENSIONS
        Assert.Equal(0x0040, (cell[68] << 8) | cell[69]); // SIG_LEN

        byte[] preArr = cell[..36];
        byte[] handshakeAuth = cell[36..68];
        byte[] sig = cell[70..134];

        // HANDSHAKE_AUTH = crypto_mac_sha3_256(KH, region-before-HANDSHAKE_AUTH).
        Assert.Equal(HsNtor.Mac256(kh, preArr), handshakeAuth);

        // SIG covers "Tor establish-intro cell v1" ‖ preArr ‖ HANDSHAKE_AUTH, verified by the auth key.
        byte[] signed = new byte[HsEstablishIntro.SigPrefixBytes.Length + 68];
        HsEstablishIntro.SigPrefixBytes.CopyTo(signed, 0);
        cell.AsSpan(0, 68).CopyTo(signed.AsSpan(HsEstablishIntro.SigPrefixBytes.Length));
        Assert.True(BcEd25519.Verify(sig, 0, authPub, 0, signed, 0, signed.Length));
    }

    [Fact]
    public void ParseEstablished_Accepts_Empty_And_Extension_List()
    {
        Assert.True(HsEstablishIntro.ParseEstablished(Array.Empty<byte>()));
        Assert.True(HsEstablishIntro.ParseEstablished(new byte[] { 0x00 }));            // N_EXTENSIONS = 0
        Assert.True(HsEstablishIntro.ParseEstablished(new byte[] { 0x01, 0x02, 0x01, 0xAA })); // one ext
        Assert.False(HsEstablishIntro.ParseEstablished(new byte[] { 0x01, 0x02, 0x05, 0xAA })); // len overruns
    }
}
