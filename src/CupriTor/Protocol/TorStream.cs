using System.Threading.Channels;

namespace CupriTor.Protocol;

/// <summary>The circuit-side operations a <see cref="TorStream"/> needs: sending relay cells for its stream id.</summary>
internal interface IRelayStreamController
{
    ValueTask SendDataAsync(ushort streamId, ReadOnlyMemory<byte> data, CancellationToken ct);
    ValueTask SendSendmeAsync(ushort streamId, CancellationToken ct);
    ValueTask SendEndAsync(ushort streamId, CancellationToken ct);
}

/// <summary>
/// A duplex <see cref="Stream"/> over a single Tor stream on a circuit. Writes are chunked into
/// RELAY_DATA cells with stream-level package-window flow control; incoming RELAY_DATA is buffered and
/// a RELAY_SENDME is emitted every deliver-window increment. The owning circuit feeds cells via the
/// <c>On…</c> methods. This type is transport-agnostic (it talks to an <see cref="IRelayStreamController"/>),
/// which makes it unit-testable without a real circuit.
/// </summary>
internal sealed class TorStream : Stream
{
    private readonly ushort _streamId;
    private readonly IRelayStreamController _controller;
    private readonly Channel<byte[]> _inbound = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions { SingleReader = true });
    private readonly FlowControlWindow _window = FlowControlWindow.Stream();
    private readonly SemaphoreSlim _packageAvailable = new(0);

    private byte[]? _leftover;
    private int _leftoverPos;
    private bool _closed;

    public TorStream(ushort streamId, IRelayStreamController controller)
    {
        _streamId = streamId;
        _controller = controller;
    }

    // ---- fed by the owning circuit ----

    public async ValueTask OnDataAsync(byte[] data, CancellationToken ct = default)
    {
        _inbound.Writer.TryWrite(data);
        if (_window.OnDeliver())
            await _controller.SendSendmeAsync(_streamId, ct).ConfigureAwait(false);
    }

    public void OnSendme()
    {
        _window.OnSendmeReceived();
        _packageAvailable.Release();
    }

    public void OnEnd() => _inbound.Writer.TryComplete();

    // ---- Stream ----

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_leftover is null)
        {
            if (!await _inbound.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
                return 0; // stream ended (RELAY_END)
            _inbound.Reader.TryRead(out _leftover);
            _leftoverPos = 0;
        }

        int available = _leftover!.Length - _leftoverPos;
        int n = Math.Min(available, buffer.Length);
        _leftover.AsSpan(_leftoverPos, n).CopyTo(buffer.Span);
        _leftoverPos += n;
        if (_leftoverPos >= _leftover.Length) _leftover = null;
        return n;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        while (!buffer.IsEmpty)
        {
            while (!_window.CanPackage)
                await _packageAvailable.WaitAsync(ct).ConfigureAwait(false);
            _window.TryPackage();

            int n = Math.Min(RelayCell.MaxDataLength, buffer.Length);
            await _controller.SendDataAsync(_streamId, buffer[..n], ct).ConfigureAwait(false);
            buffer = buffer[n..];
        }
    }

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_closed)
        {
            _closed = true;
            try { _controller.SendEndAsync(_streamId, CancellationToken.None).AsTask().GetAwaiter().GetResult(); } catch { /* best effort */ }
            _inbound.Writer.TryComplete();
            _packageAvailable.Dispose();
        }
        base.Dispose(disposing);
    }
}
