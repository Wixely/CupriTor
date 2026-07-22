using System.Net;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class StreamCellTests
{
    [Fact]
    public void RelayBegin_RoundTrips()
    {
        var begin = new RelayBeginPayload("example.com:443", RelayBeginFlags.IPv6Okay | RelayBeginFlags.IPv6Preferred);
        Assert.True(RelayBeginPayload.TryParse(begin.Encode(), out var parsed));
        Assert.Equal("example.com:443", parsed.Target);
        Assert.Equal(RelayBeginFlags.IPv6Okay | RelayBeginFlags.IPv6Preferred, parsed.Flags);
    }

    [Fact]
    public void RelayBegin_OnionStyle_Empty_Host()
    {
        var begin = new RelayBeginPayload(":9735");
        Assert.True(RelayBeginPayload.TryParse(begin.Encode(), out var parsed));
        Assert.Equal(":9735", parsed.Target);
        Assert.Equal(RelayBeginFlags.None, parsed.Flags);
    }

    [Fact]
    public void RelayConnected_Empty_And_IPv4()
    {
        Assert.True(RelayConnectedPayload.TryParse(new RelayConnectedPayload(null, 0).Encode(), out var empty));
        Assert.Null(empty.Address);

        var connected = new RelayConnectedPayload(IPAddress.Parse("203.0.113.5"), 3600);
        Assert.True(RelayConnectedPayload.TryParse(connected.Encode(), out var parsed));
        Assert.Equal(IPAddress.Parse("203.0.113.5"), parsed.Address);
        Assert.Equal(3600u, parsed.Ttl);
    }

    [Fact]
    public void RelayEnd_RoundTrips()
    {
        Assert.True(RelayEndPayload.TryParse(new RelayEndPayload(RelayEndReason.Done).Encode(), out var parsed));
        Assert.Equal(RelayEndReason.Done, parsed.Reason);
    }

    [Fact]
    public void RelaySendme_Legacy_And_V1()
    {
        Assert.True(RelaySendmePayload.TryParse(RelaySendmePayload.Legacy().Encode(), out var v0));
        Assert.Equal(0, v0.Version);
        Assert.Equal(0, v0.Data.Length);

        var digest = new byte[20]; Array.Fill(digest, (byte)0x77);
        Assert.True(RelaySendmePayload.TryParse(new RelaySendmePayload(1, digest).Encode(), out var v1));
        Assert.Equal(1, v1.Version);
        Assert.Equal(digest, v1.Data.ToArray());
    }

    [Fact]
    public void FlowControl_Package_Window_Blocks_And_Resumes()
    {
        var w = FlowControlWindow.Circuit();
        for (int i = 0; i < 1000; i++) Assert.True(w.TryPackage());
        Assert.False(w.TryPackage());      // window exhausted
        Assert.False(w.CanPackage);

        w.OnSendmeReceived();              // peer grants another 100
        for (int i = 0; i < 100; i++) Assert.True(w.TryPackage());
        Assert.False(w.TryPackage());
    }

    [Fact]
    public void FlowControl_Deliver_Triggers_Sendme_Every_Increment()
    {
        var w = FlowControlWindow.Circuit();
        int sendmes = 0;
        for (int i = 1; i <= 250; i++)
            if (w.OnDeliver()) sendmes++;

        Assert.Equal(2, sendmes);          // SENDME at the 100th and 200th delivered cell
        Assert.Equal(1000 - 50, w.DeliverWindow); // 250 delivered, 200 replenished -> 950
    }

    [Fact]
    public void FlowControl_Stream_Uses_500_50()
    {
        var w = FlowControlWindow.Stream();
        int sendmes = 0;
        for (int i = 0; i < 100; i++)
            if (w.OnDeliver()) sendmes++;
        Assert.Equal(2, sendmes);          // every 50 delivered cells
    }
}
