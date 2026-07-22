using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class CellCodecTests
{
    [Fact]
    public void FixedCell_RoundTrips_And_Pads_Payload()
    {
        var codec = new CellCodec(4);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var cell = new Cell(0xDEADBEEF, CellCommand.Netinfo, payload);

        var buf = new byte[codec.EncodedSize(cell)];
        int n = codec.Encode(cell, buf);

        Assert.Equal(4 + 1 + 509, n);            // circid + command + fixed payload
        Assert.True(codec.TryDecode(buf, out var got, out int consumed));
        Assert.Equal(n, consumed);
        Assert.Equal(0xDEADBEEFu, got.CircId);
        Assert.Equal(CellCommand.Netinfo, got.Command);
        Assert.Equal(509, got.Payload.Length);
        Assert.Equal(payload, got.Payload.Span.Slice(0, 5).ToArray());
        Assert.All(got.Payload.Span.Slice(5).ToArray(), b => Assert.Equal(0, b)); // zero-padded
    }

    [Fact]
    public void VariableCell_RoundTrips_Exact_Length()
    {
        var codec = new CellCodec(4);
        var payload = new byte[1000];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;
        var cell = new Cell(0x01020304, CellCommand.Certs, payload);

        var buf = new byte[codec.EncodedSize(cell)];
        int n = codec.Encode(cell, buf);

        Assert.Equal(4 + 1 + 2 + 1000, n);
        Assert.True(codec.TryDecode(buf, out var got, out _));
        Assert.Equal(CellCommand.Certs, got.Command);
        Assert.Equal(payload, got.Payload.ToArray());
    }

    [Fact]
    public void VersionsCell_Always_Uses_TwoByte_CircId()
    {
        var codec = new CellCodec(4); // negotiated 4-byte width, but VERSIONS must stay 2-byte
        var payload = new byte[] { 0x00, 0x04, 0x00, 0x05 }; // versions 4 and 5
        var cell = new Cell(0, CellCommand.Versions, payload);

        var buf = new byte[codec.EncodedSize(cell)];
        int n = codec.Encode(cell, buf);

        Assert.Equal(2 + 1 + 2 + payload.Length, n);
        Assert.Equal((byte)CellCommand.Versions, buf[2]); // command at offset 2 (after 2-byte circid)

        // Decodes with the initial 2-byte codec.
        Assert.True(CellCodec.Initial.TryDecode(buf, out var got, out _));
        Assert.Equal(CellCommand.Versions, got.Command);
        Assert.Equal(payload, got.Payload.ToArray());
    }

    [Fact]
    public async Task Stream_RoundTrips_Multiple_Cells()
    {
        var codec = new CellCodec(4);
        var c1 = new Cell(1, CellCommand.Netinfo, new byte[] { 9, 9 });
        var c2 = new Cell(2, CellCommand.Certs, new byte[] { 7, 7, 7 });

        using var ms = new MemoryStream();
        await codec.WriteAsync(ms, c1);
        await codec.WriteAsync(ms, c2);
        ms.Position = 0;

        var r1 = await codec.ReadAsync(ms);
        var r2 = await codec.ReadAsync(ms);

        Assert.Equal(CellCommand.Netinfo, r1.Command);
        Assert.Equal(1u, r1.CircId);
        Assert.Equal(509, r1.Payload.Length);
        Assert.Equal(CellCommand.Certs, r2.Command);
        Assert.Equal(new byte[] { 7, 7, 7 }, r2.Payload.ToArray());
    }

    [Fact]
    public void TryDecode_Returns_False_On_Partial_Input()
    {
        var codec = new CellCodec(4);
        var cell = new Cell(1, CellCommand.Certs, new byte[] { 1, 2, 3 });
        var buf = new byte[codec.EncodedSize(cell)];
        codec.Encode(cell, buf);

        Assert.False(codec.TryDecode(buf.AsSpan(0, buf.Length - 1), out _, out _)); // one byte short
        Assert.False(codec.TryDecode(buf.AsSpan(0, 3), out _, out _));              // header incomplete
    }

    [Fact]
    public void Encode_Rejects_Oversized_Fixed_Payload()
    {
        var codec = new CellCodec(4);
        var cell = new Cell(1, CellCommand.Netinfo, new byte[510]);
        Assert.Throws<ArgumentException>(() => codec.Encode(cell, new byte[1024]));
    }

    [Fact]
    public void Constructor_Rejects_Bad_Width()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CellCodec(3));
    }
}
