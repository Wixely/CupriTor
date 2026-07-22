using System.Net;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

public class CircuitCellTests
{
    [Fact]
    public void RelayCell_RoundTrips_And_Rejects_Unrecognized()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var cell = new RelayCell(RelayCommand.Data, 0x1234, data);

        var buf = new byte[RelayCell.CellLength];
        cell.EncodeTo(buf);
        Assert.Equal(0, buf[RelayCell.RecognizedOffset]);       // recognized zeroed for the crypto layer
        Assert.Equal(0, buf[RelayCell.RecognizedOffset + 1]);

        Assert.True(RelayCell.TryParse(buf, out var parsed));
        Assert.Equal(RelayCommand.Data, parsed.Command);
        Assert.Equal((ushort)0x1234, parsed.StreamId);
        Assert.Equal(data, parsed.Data.ToArray());

        buf[RelayCell.RecognizedOffset] = 1; // not for us
        Assert.False(RelayCell.TryParse(buf, out _));
    }

    [Fact]
    public void RelayCell_Rejects_Oversized_Data()
    {
        Assert.Throws<ArgumentException>(() => new RelayCell(RelayCommand.Data, 0, new byte[RelayCell.MaxDataLength + 1]));
    }

    [Fact]
    public void Create2_And_Created2_RoundTrip()
    {
        var hdata = new byte[84];
        for (int i = 0; i < hdata.Length; i++) hdata[i] = (byte)i;

        byte[] enc = new Create2Payload(HandshakeType.Ntor, hdata).Encode();
        Assert.True(Create2Payload.TryParse(enc, out var c2));
        Assert.Equal(HandshakeType.Ntor, c2.Type);
        Assert.Equal(hdata, c2.Data.ToArray());

        var reply = new byte[64];
        byte[] encR = new Created2Payload(reply).Encode();
        Assert.True(Created2Payload.TryParse(encR, out var cr2));
        Assert.Equal(reply, cr2.Data.ToArray());

        Assert.False(Create2Payload.TryParse(enc.AsSpan(0, 3), out _)); // truncated header
    }

    [Fact]
    public void LinkSpecifier_IPv4_Encodes_Correctly()
    {
        var spec = LinkSpecifier.FromIPv4(IPAddress.Parse("203.0.113.5"), 9001);
        Span<byte> buf = stackalloc byte[spec.EncodedSize];
        spec.WriteTo(buf);
        Assert.Equal(new byte[] { 0x00, 6, 203, 0, 113, 5, 0x23, 0x29 }, buf.ToArray());
    }

    [Fact]
    public void Extend2_RoundTrips_With_Multiple_Specifiers()
    {
        var legacyId = new byte[20]; Array.Fill(legacyId, (byte)0xAB);
        var edId = new byte[32]; Array.Fill(edId, (byte)0xCD);
        var hdata = new byte[84]; Array.Fill(hdata, (byte)0x11);

        var specs = new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(IPAddress.Parse("198.51.100.7"), 443),
            LinkSpecifier.FromLegacyId(legacyId),
            LinkSpecifier.FromEd25519Id(edId),
        };
        byte[] enc = new Extend2Payload(specs, HandshakeType.Ntor, hdata).Encode();

        Assert.True(Extend2Payload.TryParse(enc, out var ext));
        Assert.Equal(3, ext.Specifiers.Count);
        Assert.Equal(LinkSpecifier.TypeTlsIPv4, ext.Specifiers[0].Type);
        Assert.Equal(legacyId, ext.Specifiers[1].Data.ToArray());
        Assert.Equal(edId, ext.Specifiers[2].Data.ToArray());
        Assert.Equal(HandshakeType.Ntor, ext.Type);
        Assert.Equal(hdata, ext.Data.ToArray());
    }

    [Fact]
    public void Ntor_Handshake_Fits_In_Create2_And_Extend2_Cells()
    {
        var rng = new SecureRandom();
        var relayPriv = new X25519PrivateKeyParameters(rng);
        byte[] B = relayPriv.GeneratePublicKey().GetEncoded();
        var nodeId = new byte[20]; rng.NextBytes(nodeId);

        (byte[] hs, _) = Ntor.CreateClient(nodeId, B, rng);

        // CREATE2 for the first hop.
        byte[] create2 = new Create2Payload(HandshakeType.Ntor, hs).Encode();
        Assert.True(Create2Payload.TryParse(create2, out var c2));
        Assert.Equal(hs, c2.Data.ToArray());

        // EXTEND2 for a later hop, carried inside a RELAY_EARLY cell.
        var specs = new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(IPAddress.Parse("203.0.113.9"), 9001),
            LinkSpecifier.FromLegacyId(nodeId),
        };
        byte[] extend2 = new Extend2Payload(specs, HandshakeType.Ntor, hs).Encode();
        Assert.True(extend2.Length <= RelayCell.MaxDataLength);

        var relay = new RelayCell(RelayCommand.Extend2, 0, extend2);
        var cell = new byte[RelayCell.CellLength];
        relay.EncodeTo(cell);
        Assert.True(RelayCell.TryParse(cell, out var parsed));
        Assert.Equal(RelayCommand.Extend2, parsed.Command);
        Assert.True(Extend2Payload.TryParse(parsed.Data.Span, out var ext));
        Assert.Equal(hs, ext.Data.ToArray());
    }
}
