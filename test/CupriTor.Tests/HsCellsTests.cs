using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

public class HsCellsTests
{
    [Fact]
    public void Rendezvous1_Is_Random_Padded_To_168_Bytes()
    {
        byte[] cookie = HsCells.NewRendezvousCookie();
        var handshake = new byte[HsCells.RendezvousHandshakeLength]; // Y(32) + AUTH(32) = 64
        for (int i = 0; i < handshake.Length; i++) handshake[i] = (byte)(i + 1);

        byte[] a = HsCells.BuildRendezvous1Padded(cookie, handshake);
        byte[] b = HsCells.BuildRendezvous1Padded(cookie, handshake);

        Assert.Equal(168, a.Length);
        Assert.Equal(cookie, a[..20]);                       // cookie
        Assert.Equal(handshake, a[20..84]);                  // Y | AUTH
        Assert.NotEqual(a[84..], b[84..]);                   // pad is random, not zeros/fixed
    }
}
