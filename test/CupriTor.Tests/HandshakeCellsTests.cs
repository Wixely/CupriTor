using System.Buffers.Binary;
using System.Net;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class HandshakeCellsTests
{
    [Fact]
    public void Versions_RoundTrip_And_HighestCommon()
    {
        byte[] payload = VersionsCell.Build(3, 4, 5);
        Assert.Equal(new byte[] { 0, 3, 0, 4, 0, 5 }, payload);

        Assert.True(VersionsCell.TryParse(payload, out ushort[] versions));
        Assert.Equal(new ushort[] { 3, 4, 5 }, versions);

        Assert.Equal((ushort)5, VersionsCell.HighestCommon(new ushort[] { 4, 5, 6 }, versions));
        Assert.Null(VersionsCell.HighestCommon(new ushort[] { 1, 2 }, versions));
    }

    [Fact]
    public void Versions_Rejects_Odd_Length()
    {
        Assert.False(VersionsCell.TryParse(new byte[] { 0, 4, 5 }, out _));
    }

    [Fact]
    public void Certs_RoundTrips()
    {
        var entries = new List<CertsCell.Entry>
        {
            new(0x04, new byte[] { 1, 2, 3 }),
            new(0x05, new byte[] { 9, 8, 7, 6 }),
        };
        byte[] payload = CertsCell.Build(entries);

        Assert.True(CertsCell.TryParse(payload, out var cell));
        Assert.Equal(2, cell.Certs.Count);
        Assert.Equal(new byte[] { 1, 2, 3 }, cell.Find(0x04)!.Value.ToArray());
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, cell.Find(0x05)!.Value.ToArray());
        Assert.Null(cell.Find(0x07));
    }

    [Fact]
    public void Certs_Rejects_Truncated()
    {
        byte[] payload = CertsCell.Build(new List<CertsCell.Entry> { new(0x04, new byte[] { 1, 2, 3 }) });
        Assert.False(CertsCell.TryParse(payload.AsMemory(0, payload.Length - 1), out _));
    }

    [Fact]
    public void AuthChallenge_Parses()
    {
        var payload = new byte[32 + 2 + 4];
        for (int i = 0; i < 32; i++) payload[i] = (byte)i;
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(32), 2);   // 2 methods
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(34), 1);   // method 1
        BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(36), 3);   // method 3

        Assert.True(AuthChallengeCell.TryParse(payload, out var cell));
        Assert.Equal(32, cell.Challenge.Length);
        Assert.Equal(new ushort[] { 1, 3 }, cell.Methods);
    }

    [Fact]
    public void AuthChallenge_Rejects_Short()
    {
        Assert.False(AuthChallengeCell.TryParse(new byte[10], out _));
    }

    [Fact]
    public void NetInfo_RoundTrips()
    {
        var other = TorAddress.FromIP(IPAddress.Parse("203.0.113.5"));
        var mine = new List<TorAddress> { TorAddress.FromIP(IPAddress.Parse("198.51.100.9")) };
        byte[] payload = NetInfoCell.Build(1_700_000_000u, other, mine);

        Assert.True(NetInfoCell.TryParse(payload, out var cell));
        Assert.Equal(1_700_000_000u, cell.Timestamp);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), cell.OtherAddress.ToIPAddress());
        Assert.Single(cell.MyAddresses);
        Assert.Equal(IPAddress.Parse("198.51.100.9"), cell.MyAddresses[0].ToIPAddress());
    }

    [Fact]
    public void NetInfo_Parses_With_Trailing_Padding()
    {
        var other = TorAddress.FromIP(IPAddress.Parse("203.0.113.5"));
        byte[] structured = NetInfoCell.Build(42u, other, Array.Empty<TorAddress>());
        var padded = new byte[509]; // as delivered inside a fixed-length cell
        structured.CopyTo(padded, 0);

        Assert.True(NetInfoCell.TryParse(padded, out var cell));
        Assert.Equal(42u, cell.Timestamp);
        Assert.Empty(cell.MyAddresses);
    }

    [Fact]
    public void NetInfo_IPv6_RoundTrips()
    {
        var other = TorAddress.FromIP(IPAddress.Parse("2001:db8::1"));
        byte[] payload = NetInfoCell.Build(1u, other, Array.Empty<TorAddress>());
        Assert.True(NetInfoCell.TryParse(payload, out var cell));
        Assert.Equal(TorAddress.TypeIPv6, cell.OtherAddress.Type);
        Assert.Equal(IPAddress.Parse("2001:db8::1"), cell.OtherAddress.ToIPAddress());
    }
}
