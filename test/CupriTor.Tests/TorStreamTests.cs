using System.Collections.Concurrent;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class TorStreamTests
{
    private sealed class MockController : IRelayStreamController
    {
        public readonly ConcurrentQueue<byte[]> Data = new();
        public int Sendmes;
        public int Ends;

        public ValueTask SendDataAsync(ushort streamId, ReadOnlyMemory<byte> data, CancellationToken ct) { Data.Enqueue(data.ToArray()); return ValueTask.CompletedTask; }
        public ValueTask SendSendmeAsync(ushort streamId, CancellationToken ct) { Interlocked.Increment(ref Sendmes); return ValueTask.CompletedTask; }
        public ValueTask SendEndAsync(ushort streamId, CancellationToken ct) { Interlocked.Increment(ref Ends); return ValueTask.CompletedTask; }
    }

    [Fact]
    public async Task Write_Chunks_Into_RelayData_Sized_Pieces()
    {
        var mock = new MockController();
        var stream = new TorStream(1, mock);

        var payload = new byte[1000];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)i;
        await stream.WriteAsync(payload);

        // 1000 bytes -> 498 + 498 + 4.
        Assert.Equal(3, mock.Data.Count);
        var reassembled = mock.Data.SelectMany(x => x).ToArray();
        Assert.Equal(payload, reassembled);
        Assert.True(mock.Data.All(c => c.Length <= RelayCell.MaxDataLength));
    }

    [Fact]
    public async Task Read_Returns_Delivered_Data_With_Partial_Reads()
    {
        var mock = new MockController();
        var stream = new TorStream(2, mock);

        await stream.OnDataAsync(new byte[] { 1, 2, 3, 4, 5 });
        await stream.OnDataAsync(new byte[] { 6, 7 });

        var buf = new byte[3];
        Assert.Equal(3, await stream.ReadAsync(buf));
        Assert.Equal(new byte[] { 1, 2, 3 }, buf);
        Assert.Equal(2, await stream.ReadAsync(buf));         // leftover 4,5
        Assert.Equal(new byte[] { 4, 5 }, buf[..2]);
        Assert.Equal(2, await stream.ReadAsync(buf));         // next chunk 6,7
        Assert.Equal(new byte[] { 6, 7 }, buf[..2]);
    }

    [Fact]
    public async Task Read_Returns_Zero_After_End()
    {
        var mock = new MockController();
        var stream = new TorStream(3, mock);
        await stream.OnDataAsync(new byte[] { 9 });
        stream.OnEnd();

        var buf = new byte[8];
        Assert.Equal(1, await stream.ReadAsync(buf));
        Assert.Equal(0, await stream.ReadAsync(buf)); // EOF
    }

    [Fact]
    public async Task Deliver_Triggers_Sendme_Every_Increment()
    {
        var mock = new MockController();
        var stream = new TorStream(4, mock);
        for (int i = 0; i < 100; i++) await stream.OnDataAsync(new byte[] { (byte)i });
        Assert.Equal(2, mock.Sendmes); // stream increment is 50
    }

    [Fact]
    public async Task Write_Blocks_When_Package_Window_Exhausted_And_Resumes_On_Sendme()
    {
        var mock = new MockController();
        var stream = new TorStream(5, mock);

        // Stream package window starts at 500; each 1-byte write consumes one cell.
        for (int i = 0; i < 500; i++) await stream.WriteAsync(new byte[] { 1 });
        Assert.Equal(500, mock.Data.Count);

        // The 501st write must block until a SENDME replenishes the window.
        var blocked = stream.WriteAsync(new byte[] { 2 }).AsTask();
        Assert.False(blocked.IsCompleted);

        stream.OnSendme();
        await blocked; // now completes
        Assert.Equal(501, mock.Data.Count);
    }

    [Fact]
    public void Dispose_Sends_End()
    {
        var mock = new MockController();
        var stream = new TorStream(6, mock);
        stream.Dispose();
        Assert.Equal(1, mock.Ends);
    }
}
