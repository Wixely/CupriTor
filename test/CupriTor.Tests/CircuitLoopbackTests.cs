using System.Text;
using System.Threading.Channels;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// End-to-end test of <see cref="Circuit"/> and <see cref="TorStream"/> against a faithful in-memory,
/// single-hop relay: a real ntor CREATE2/CREATED2 exchange followed by the exact relay-cell crypto
/// (symmetric AES-CTR keystream + running SHA-1 digests). This exercises the same code paths the live
/// collector validates against the real network, but offline and deterministically.
/// </summary>
public class CircuitLoopbackTests
{
    [Fact]
    public async Task Builds_Circuit_Opens_Stream_And_Echoes_Data()
    {
        (Stream client, Stream relaySide) = InMemoryDuplex.Pair();
        var relay = new LoopbackRelay(relaySide, 0x80000001);
        Task relayTask = relay.RunAsync();

        var codec = new CellCodec(4);
        await using var circuit = new Circuit(client, codec, 0x80000001);
        await circuit.CreateFirstHopAsync(relay.HopInfo, TestTimeout());
        Assert.Equal(1, circuit.HopCount);

        circuit.Start();
        TorStream stream = await circuit.OpenDirectoryStreamAsync(TestTimeout());

        byte[] payload = Encoding.ASCII.GetBytes("hello onion");
        await stream.WriteAsync(payload, TestTimeout());

        var buf = new byte[payload.Length];
        int read = 0;
        while (read < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(read), TestTimeout());
            Assert.True(n > 0);
            read += n;
        }
        Assert.Equal(payload, buf);

        relay.Stop();
        await relayTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Multiplexes_Two_Concurrent_Streams()
    {
        (Stream client, Stream relaySide) = InMemoryDuplex.Pair();
        var relay = new LoopbackRelay(relaySide, 0x80000002);
        Task relayTask = relay.RunAsync();

        await using var circuit = new Circuit(client, new CellCodec(4), 0x80000002);
        await circuit.CreateFirstHopAsync(relay.HopInfo, TestTimeout());
        circuit.Start();

        TorStream a = await circuit.OpenDirectoryStreamAsync(TestTimeout());
        TorStream b = await circuit.OpenDirectoryStreamAsync(TestTimeout());

        await a.WriteAsync(Encoding.ASCII.GetBytes("AAAA"), TestTimeout());
        await b.WriteAsync(Encoding.ASCII.GetBytes("BBBBBB"), TestTimeout());

        Assert.Equal("AAAA", await ReadExactAsync(a, 4));
        Assert.Equal("BBBBBB", await ReadExactAsync(b, 6));

        relay.Stop();
        await relayTask.WaitAsync(TimeSpan.FromSeconds(10));
    }

    private static async Task<string> ReadExactAsync(Stream s, int count)
    {
        var buf = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(read), TestTimeout());
            if (n == 0) break;
            read += n;
        }
        return Encoding.ASCII.GetString(buf, 0, read);
    }

    private static CancellationToken TestTimeout() => new CancellationTokenSource(TimeSpan.FromSeconds(30)).Token;

    /// <summary>A single-hop relay that speaks CREATE2/CREATED2 then echoes RELAY_DATA back to the client.</summary>
    private sealed class LoopbackRelay
    {
        private readonly Stream _stream;
        private readonly uint _circId;
        private readonly CellCodec _codec = new(4);
        private readonly X25519PrivateKeyParameters _ntorPriv;
        private readonly byte[] _ntorPub;
        private readonly byte[] _nodeId = RandomBytes(20);
        private readonly CancellationTokenSource _cts = new();
        private RelayCrypto? _crypto;

        public LoopbackRelay(Stream stream, uint circId)
        {
            _stream = stream;
            _circId = circId;
            _ntorPriv = new X25519PrivateKeyParameters(new SecureRandom());
            _ntorPub = _ntorPriv.GeneratePublicKey().GetEncoded();
        }

        public RelayHopInfo HopInfo => new(System.Net.IPAddress.Loopback, 9001, _nodeId, _ntorPub, null);

        public void Stop() => _cts.Cancel();

        public async Task RunAsync()
        {
            try
            {
                // 1. ntor CREATE2 -> CREATED2
                Cell create = await _codec.ReadAsync(_stream, _cts.Token);
                Assert.Equal(CellCommand.Create2, create.Command);
                Assert.True(Create2Payload.TryParse(create.Payload.Span, out var c2));
                var responded = Ntor.Respond(c2.Data.ToArray(), _nodeId, _ntorPriv, _ntorPub)
                    ?? throw new InvalidOperationException("ntor Respond failed");
                _crypto = new RelayCrypto(Ntor.DeriveKeys(responded.KeySeed, RelayCrypto.KeyMaterialLength));
                byte[] created = new Created2Payload(responded.CreatedData).Encode();
                await _codec.WriteAsync(_stream, new Cell(_circId, CellCommand.Created2, created), _cts.Token);

                // 2. serve relay cells until stopped or the client closes
                while (!_cts.IsCancellationRequested)
                {
                    Cell cell;
                    try { cell = await _codec.ReadAsync(_stream, _cts.Token); }
                    catch (EndOfStreamException) { break; }
                    catch (OperationCanceledException) { break; }
                    if (cell.Command is not (CellCommand.Relay or CellCommand.RelayEarly)) continue;

                    RelayCell relay = DecryptForward(cell.Payload.ToArray());
                    switch (relay.Command)
                    {
                        case RelayCommand.BeginDir:
                        case RelayCommand.Begin:
                            await SendBackAsync(new RelayCell(RelayCommand.Connected, relay.StreamId, Array.Empty<byte>()));
                            break;
                        case RelayCommand.Data:
                            await SendBackAsync(new RelayCell(RelayCommand.Data, relay.StreamId, relay.Data));
                            break;
                        case RelayCommand.End:
                            break;
                        default:
                            break;
                    }
                }
            }
            catch (EndOfStreamException) { /* client closed */ }
            catch (OperationCanceledException) { /* stopped */ }
        }

        private RelayCell DecryptForward(byte[] body)
        {
            _crypto!.CryptForward(body);
            byte[] received = body[RelayCell.DigestOffset..(RelayCell.DigestOffset + 4)];
            var zeroed = (byte[])body.Clone();
            Array.Clear(zeroed, RelayCell.DigestOffset, 4);
            byte[] expected = _crypto.ForwardDigest(zeroed);
            Assert.True(expected.AsSpan().SequenceEqual(received), "relay forward digest mismatch");
            Assert.True(RelayCell.TryParse(body, out RelayCell parsed));
            return parsed;
        }

        private async Task SendBackAsync(RelayCell relayCell)
        {
            var cell = new byte[RelayCell.CellLength];
            relayCell.EncodeTo(cell);
            byte[] digest = _crypto!.BackwardDigest(cell);
            digest.CopyTo(cell, RelayCell.DigestOffset);
            _crypto.CryptBackward(cell);
            await _codec.WriteAsync(_stream, new Cell(_circId, CellCommand.Relay, cell));
        }

        private static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            new SecureRandom().NextBytes(b);
            return b;
        }
    }

    /// <summary>A pair of cross-wired in-memory streams (no OS sockets).</summary>
    private sealed class InMemoryDuplex : Stream
    {
        private readonly ChannelReader<byte[]> _in;
        private readonly ChannelWriter<byte[]> _out;
        private byte[]? _leftover;
        private int _pos;

        private InMemoryDuplex(ChannelReader<byte[]> input, ChannelWriter<byte[]> output) { _in = input; _out = output; }

        public static (Stream A, Stream B) Pair()
        {
            var a2b = Channel.CreateUnbounded<byte[]>();
            var b2a = Channel.CreateUnbounded<byte[]>();
            return (new InMemoryDuplex(b2a.Reader, a2b.Writer), new InMemoryDuplex(a2b.Reader, b2a.Writer));
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_leftover is null)
            {
                if (!await _in.WaitToReadAsync(ct).ConfigureAwait(false)) return 0;
                _in.TryRead(out _leftover);
                _pos = 0;
            }
            int n = Math.Min(_leftover!.Length - _pos, buffer.Length);
            _leftover.AsSpan(_pos, n).CopyTo(buffer.Span);
            _pos += n;
            if (_pos >= _leftover.Length) _leftover = null;
            return n;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) =>
            await _out.WriteAsync(buffer.ToArray(), ct).ConfigureAwait(false);

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Flush() { }
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
