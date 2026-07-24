using System.Buffers.Binary;
using System.Text;
using CupriTor.OnionService;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.Tests;

public class HsIntroAndCellsTests
{
    // A minimal cert-spec Ed25519 cert whose certified key is `certifiedKey`, signed by `signerSeed`.
    private static byte[] BuildCert(byte[] certifiedKey, byte[] signerSeed)
    {
        var body = new List<byte> { 0x01, 0x09 }; // version, cert_type (HS intro auth, arbitrary here)
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, 2_000_000);
        body.AddRange(h.ToArray());
        body.Add(0x01); // ed25519 key
        body.AddRange(certifiedKey);
        body.Add(0x00); // no extensions
        var arr = body.ToArray();
        var sig = new byte[64];
        BcEd25519.Sign(signerSeed, 0, arr, 0, arr.Length, sig, 0);
        return arr.Concat(sig).ToArray();
    }

    private static string Pem(string type, byte[] data) => $"-----BEGIN {type}-----\n{Convert.ToBase64String(data)}\n-----END {type}-----\n";
    private static string B64(byte[] d) => Convert.ToBase64String(d).TrimEnd('=');
    private static byte[] Fill(byte b, int n = 32) { var a = new byte[n]; Array.Fill(a, b); return a; }

    [Fact]
    public void Inner_Layer_Parses_Introduction_Points()
    {
        byte[] signerSeed = Fill(0x01);
        byte[] linkSpecs1 = { 3, 0x00, 6, 203, 0, 113, 5, 0x23, 0x29 }; // nspec=3? (opaque bytes; parser keeps them raw)
        byte[] onion1 = Fill(0xA1), auth1 = Fill(0xA2), enc1 = Fill(0xA3);
        byte[] linkSpecs2 = { 1, 0x02, 20 };
        byte[] onion2 = Fill(0xB1), auth2 = Fill(0xB2), enc2 = Fill(0xB3);

        var sb = new StringBuilder();
        sb.Append("create2-formats 2\n");
        void AddIntro(byte[] ls, byte[] onion, byte[] auth, byte[] enc)
        {
            sb.Append("introduction-point ").Append(B64(ls)).Append('\n');
            sb.Append("onion-key ntor ").Append(B64(onion)).Append('\n');
            sb.Append("auth-key\n").Append(Pem("ED25519 CERT", BuildCert(auth, signerSeed)));
            sb.Append("enc-key ntor ").Append(B64(enc)).Append('\n');
            sb.Append("enc-key-cert\n").Append(Pem("ED25519 CERT", BuildCert(enc, signerSeed)));
        }
        AddIntro(linkSpecs1, onion1, auth1, enc1);
        AddIntro(linkSpecs2, onion2, auth2, enc2);

        byte[] plaintext = Encoding.ASCII.GetBytes(sb.ToString());
        Assert.True(HsInnerLayer.TryParse(plaintext, out var intros));
        Assert.Equal(2, intros.Count);

        Assert.Equal(linkSpecs1, intros[0].LinkSpecifiers.ToArray());
        Assert.Equal(onion1, intros[0].OnionKeyNtor);
        Assert.Equal(auth1, intros[0].AuthKey);
        Assert.Equal(enc1, intros[0].EncKey);
        Assert.Equal(auth2, intros[1].AuthKey);
        Assert.Equal(enc2, intros[1].EncKey);
    }

    [Fact]
    public void Superencrypted_Layer_Extracts_Inner_Blob()
    {
        byte[] inner = Fill(0x7c, 100);
        var text = "desc-auth-type x25519\nencrypted\n" + Pem("MESSAGE", inner);
        Assert.True(HsSuperencryptedLayer.TryExtractInner(Encoding.ASCII.GetBytes(text), out byte[] blob));
        Assert.Equal(inner, blob);
    }

    [Fact]
    public void Introduce_Cell_RoundTrips()
    {
        byte[] authKey = Fill(0x11);
        byte[] encrypted = Fill(0x22, 120);
        byte[] payload = HsCells.BuildIntroduce(authKey, encrypted);

        Assert.True(HsCells.TryParseIntroduce(payload, out byte[] gotAuth, out byte[] gotEnc));
        Assert.Equal(authKey, gotAuth);
        Assert.Equal(encrypted, gotEnc);
    }

    [Fact]
    public void Rendezvous_Handshake_And_Rendezvous1_RoundTrip()
    {
        byte[] y = Fill(0x33), auth = Fill(0x44);
        byte[] handshake = HsCells.BuildRendezvousHandshake(y, auth);
        Assert.Equal(HsCells.RendezvousHandshakeLength, handshake.Length);
        Assert.True(HsCells.TryParseRendezvousHandshake(handshake, out byte[] gy, out byte[] ga));
        Assert.Equal(y, gy);
        Assert.Equal(auth, ga);

        byte[] cookie = HsCells.NewRendezvousCookie();
        Assert.Equal(HsCells.RendezvousCookieLength, cookie.Length);
        byte[] rend1 = HsCells.BuildRendezvous1(cookie, handshake);
        Assert.True(HsCells.TryParseRendezvous1(rend1, out byte[] gc, out byte[] gh));
        Assert.Equal(cookie, gc);
        Assert.Equal(handshake, gh);
    }
}
