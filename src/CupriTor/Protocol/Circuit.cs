using System.Collections.Concurrent;
using System.Net;

namespace CupriTor.Protocol;

/// <summary>Raised when a circuit operation fails (DESTROY, TRUNCATED, unrecognized cell, digest mismatch).</summary>
internal sealed class CircuitException(string message) : Exception(message);

/// <summary>Everything a circuit needs to add a relay as a hop: its address, ntor key, and identities.</summary>
internal sealed record RelayHopInfo(IPAddress Address, ushort OrPort, byte[] RsaIdentityDigest, byte[] NtorOnionKey, byte[]? Ed25519Identity);

/// <summary>
/// A live Tor circuit over an established link connection: the ordered per-hop <see cref="RelayCrypto"/>,
/// the relay-cell send path (layered encryption + running forward digest), and — once <see cref="Start"/>
/// is called — a background receive loop that decrypts inbound cells, verifies the integrity digest at
/// the final hop, and multiplexes them to the owning <see cref="TorStream"/>s. Handles circuit-scope
/// flow control (SENDME at 1000/100) and serves as the <see cref="IRelayStreamController"/> for its streams.
///
/// Build the hops with <see cref="CreateFirstHopAsync"/> + <see cref="ExtendAsync"/> (synchronous
/// request/reply, before Start), then call <see cref="Start"/> and open streams.
/// </summary>
internal sealed class Circuit : IRelayStreamController, IAsyncDisposable
{
    private readonly Stream _link;
    private readonly CellCodec _codec;
    private readonly uint _circId;

    private const int KhLength = 20; // per-circuit nonce KH: the final 20 bytes of the ntor KDF output
    private readonly List<RelayCrypto> _hops = new();
    private readonly List<byte[]> _hopKh = new();  // KH of each ntor hop (for ESTABLISH_INTRO's HANDSHAKE_AUTH)
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<ushort, TorStream> _streams = new();
    private readonly ConcurrentDictionary<ushort, TaskCompletionSource<RelayCell>> _pendingOpens = new();
    private readonly ConcurrentDictionary<RelayCommand, TaskCompletionSource<RelayCell>> _pendingControl = new();
    private readonly object _hopsLock = new();

    private readonly FlowControlWindow _circuitPackage = FlowControlWindow.Circuit();
    private readonly FlowControlWindow _circuitDeliver = FlowControlWindow.Circuit();
    private readonly SemaphoreSlim _circuitPackageAvailable = new(0);

    private readonly CancellationTokenSource _shutdown = new();
    private Task? _receiveLoop;
    private int _nextStreamId;
    private volatile Exception? _fault;

    public Circuit(Stream link, CellCodec codec, uint circId)
    {
        _link = link;
        _codec = codec;
        _circId = circId;
    }

    public int HopCount => _hops.Count;

    // ---- building (call before Start) ----

    /// <summary>Establish the first hop with an ntor CREATE2/CREATED2 exchange.</summary>
    public async Task CreateFirstHopAsync(RelayHopInfo hop, CancellationToken ct)
    {
        (byte[] handshake, Ntor.ClientState state) = Ntor.CreateClient(hop.RsaIdentityDigest, hop.NtorOnionKey);
        byte[] create2 = new Create2Payload(HandshakeType.Ntor, handshake).Encode();
        await _codec.WriteAsync(_link, new Cell(_circId, CellCommand.Create2, create2), ct).ConfigureAwait(false);

        Cell reply = await _codec.ReadAsync(_link, ct).ConfigureAwait(false);
        if (reply.Command == CellCommand.Destroy)
            throw new CircuitException($"DESTROY at CREATE2 (reason {ReasonByte(reply.Payload)}).");
        if (reply.Command != CellCommand.Created2 || !Created2Payload.TryParse(reply.Payload.Span, out var created2))
            throw new CircuitException("Expected CREATED2.");

        byte[]? keySeed = Ntor.CompleteClient(state, created2.Data.ToArray());
        if (keySeed is null) throw new CircuitException("ntor AUTH verification failed for the first hop.");
        AddNtorHop(keySeed);
    }

    /// <summary>Derive the 92-byte ntor material, add the hop's RelayCrypto (first 72 bytes) and stash its KH (last 20).</summary>
    private void AddNtorHop(byte[] keySeed)
    {
        byte[] km = Ntor.DeriveKeys(keySeed, RelayCrypto.KeyMaterialLength + KhLength); // Df|Db|Kf|Kb|KH
        lock (_hopsLock)
        {
            _hops.Add(new RelayCrypto(km));
            _hopKh.Add(km[RelayCrypto.KeyMaterialLength..].ToArray());
        }
    }

    /// <summary>The KH (circuit nonce) of the last ntor hop — the MAC key for an ESTABLISH_INTRO on this circuit.</summary>
    public byte[] LastKh => _hopKh[^1];

    /// <summary>Extend the circuit to <paramref name="hop"/> with EXTEND2/EXTENDED2 through the current last hop.</summary>
    public Task ExtendAsync(RelayHopInfo hop, CancellationToken ct)
    {
        var specs = new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(hop.Address, hop.OrPort),
            LinkSpecifier.FromLegacyId(hop.RsaIdentityDigest),
        };
        if (hop.Ed25519Identity is { Length: 32 }) specs.Add(LinkSpecifier.FromEd25519Id(hop.Ed25519Identity));
        return ExtendCoreAsync(specs, hop.RsaIdentityDigest, hop.NtorOnionKey, ct);
    }

    /// <summary>
    /// Extend to a relay described by raw link specifiers and an ntor onion key (e.g. a descriptor's
    /// introduction point). The 20-byte legacy id inside the specifiers is used as the ntor node id.
    /// </summary>
    public Task ExtendToAsync(IReadOnlyList<LinkSpecifier> specifiers, byte[] ntorOnionKey, CancellationToken ct)
    {
        byte[] nodeId = LinkSpecifier.FindLegacyId(specifiers)
            ?? throw new CircuitException("Link specifiers have no legacy (RSA) identity to use as the ntor node id.");
        return ExtendCoreAsync(specifiers, nodeId, ntorOnionKey, ct);
    }

    private async Task ExtendCoreAsync(IReadOnlyList<LinkSpecifier> specifiers, byte[] nodeId, byte[] ntorOnionKey, CancellationToken ct)
    {
        (byte[] handshake, Ntor.ClientState state) = Ntor.CreateClient(nodeId, ntorOnionKey);
        byte[] extend2 = new Extend2Payload(specifiers, HandshakeType.Ntor, handshake).Encode();
        int lastHop = _hops.Count - 1;
        await SendRelayCellAsync(lastHop, RelayCommand.Extend2, 0, extend2, early: true, ct).ConfigureAwait(false);

        RelayCell reply = await ReceiveRelayCellDirectAsync(lastHop, ct).ConfigureAwait(false);
        if (reply.Command == RelayCommand.Truncated)
            throw new CircuitException($"TRUNCATED during EXTEND2 (reason {ReasonByte(reply.Data)}).");
        if (reply.Command != RelayCommand.Extended2 || !Created2Payload.TryParse(reply.Data.Span, out var created2))
            throw new CircuitException($"Expected EXTENDED2, got {reply.Command}.");

        byte[]? keySeed = Ntor.CompleteClient(state, created2.Data.ToArray());
        if (keySeed is null) throw new CircuitException("ntor AUTH verification failed while extending.");
        AddNtorHop(keySeed);
    }

    /// <summary>
    /// Append a virtual hop from externally-derived key material (the hs-ntor rendezvous keys). After a
    /// RENDEZVOUS2 handshake completes, this adds the onion layer for the hidden service so subsequent
    /// RELAY cells to the last hop are end-to-end encrypted to it (the rendezvous point just relays them).
    /// </summary>
    public void AppendHop(ReadOnlySpan<byte> keyMaterial)
    {
        var crypto = RelayCrypto.CreateV3Hs(keyMaterial); // v3 HS rendezvous, client side (SHA3-256 + AES-256)
        lock (_hopsLock) _hops.Add(crypto);
    }

    /// <summary>
    /// Append the spliced rendezvous hop from the SERVICE side (reversed forward/backward). The onion service
    /// is the far end of the rendezvous circuit, so its relay crypto mirrors the client's (tor's is_service_side).
    /// </summary>
    public void AppendHopReversed(ReadOnlySpan<byte> keyMaterial)
    {
        var crypto = RelayCrypto.CreateV3HsService(keyMaterial);
        lock (_hopsLock) _hops.Add(crypto);
    }

    // ---- operation (after Start) ----

    /// <summary>Start the background receive loop. Call once, after all hops are built.</summary>
    public void Start() => _receiveLoop ??= Task.Run(() => ReceiveLoopAsync(_shutdown.Token));

    /// <summary>Open a directory stream (BEGIN_DIR) to the last hop.</summary>
    public Task<TorStream> OpenDirectoryStreamAsync(CancellationToken ct = default) =>
        OpenStreamAsync(RelayCommand.BeginDir, Array.Empty<byte>(), ct);

    /// <summary>Open a stream to <paramref name="target"/> ("host:port") through the last hop with RELAY_BEGIN.</summary>
    public Task<TorStream> ConnectAsync(string target, CancellationToken ct = default) =>
        OpenStreamAsync(RelayCommand.Begin, new RelayBeginPayload(target).Encode(), ct);

    private async Task<TorStream> OpenStreamAsync(RelayCommand begin, byte[] payload, CancellationToken ct)
    {
        ThrowIfFaulted();
        if (_receiveLoop is null) throw new InvalidOperationException("Call Start() before opening streams.");

        ushort sid = NextStreamId();
        var opened = new TaskCompletionSource<RelayCell>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingOpens[sid] = opened;
        var stream = new TorStream(sid, this);
        _streams[sid] = stream;

        int last = _hops.Count - 1;
        await SendRelayCellAsync(last, begin, sid, payload, early: false, ct).ConfigureAwait(false);

        using var reg = ct.Register(() => opened.TrySetCanceled(ct));
        RelayCell reply = await opened.Task.ConfigureAwait(false);
        _pendingOpens.TryRemove(sid, out _);

        if (reply.Command != RelayCommand.Connected)
        {
            _streams.TryRemove(sid, out _);
            throw new CircuitException($"Stream not accepted (got {reply.Command}).");
        }
        return stream;
    }

    // ---- HS control cells (stream 0) ----

    /// <summary>Register interest in an inbound control relay command; completes when the receive loop dispatches it.</summary>
    public Task<RelayCell> WaitForAsync(RelayCommand expect, CancellationToken ct)
    {
        ThrowIfFaulted();
        var tcs = new TaskCompletionSource<RelayCell>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingControl[expect] = tcs;
        ct.Register(() => tcs.TrySetCanceled(ct));
        return tcs.Task;
    }

    /// <summary>Send a stream-0 control cell and await a specific reply command (e.g. ESTABLISH_RENDEZVOUS → RENDEZVOUS_ESTABLISHED).</summary>
    public async Task<RelayCell> SendControlAndAwaitAsync(RelayCommand send, byte[] payload, RelayCommand expect, bool early, CancellationToken ct)
    {
        Task<RelayCell> wait = WaitForAsync(expect, ct);
        await SendRelayCellAsync(_hops.Count - 1, send, 0, payload, early, ct).ConfigureAwait(false);
        return await wait.ConfigureAwait(false);
    }

    /// <summary>Send a stream-0 control cell without awaiting a reply.</summary>
    public Task SendControlAsync(RelayCommand send, byte[] payload, bool early, CancellationToken ct) =>
        SendRelayCellAsync(_hops.Count - 1, send, 0, payload, early, ct);

    // ---- IRelayStreamController (called by TorStream) ----

    public async ValueTask SendDataAsync(ushort streamId, ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        while (!_circuitPackage.CanPackage)
            await _circuitPackageAvailable.WaitAsync(ct).ConfigureAwait(false);
        _circuitPackage.TryPackage();
        await SendRelayCellAsync(_hops.Count - 1, RelayCommand.Data, streamId, data.ToArray(), early: false, ct).ConfigureAwait(false);
    }

    public ValueTask SendSendmeAsync(ushort streamId, CancellationToken ct) =>
        new(SendRelayCellAsync(_hops.Count - 1, RelayCommand.Sendme, streamId, RelaySendmePayload.Legacy().Encode(), early: false, ct));

    public async ValueTask SendEndAsync(ushort streamId, CancellationToken ct)
    {
        _streams.TryRemove(streamId, out _);
        await SendRelayCellAsync(_hops.Count - 1, RelayCommand.End, streamId, new RelayEndPayload(RelayEndReason.Done).Encode(), early: false, ct).ConfigureAwait(false);
    }

    // ---- relay-cell send/receive ----

    private async Task SendRelayCellAsync(int targetHop, RelayCommand command, ushort streamId, byte[] data, bool early, CancellationToken ct)
    {
        var relayCell = new RelayCell(command, streamId, data);
        var cell = new byte[RelayCell.CellLength];
        relayCell.EncodeTo(cell);

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            byte[] digest = _hops[targetHop].ForwardDigest(cell);
            digest.CopyTo(cell, RelayCell.DigestOffset);
            for (int i = targetHop; i >= 0; i--) _hops[i].CryptForward(cell);
            await _codec.WriteAsync(_link, new Cell(_circId, early ? CellCommand.RelayEarly : CellCommand.Relay, cell), ct).ConfigureAwait(false);
        }
        finally { _writeLock.Release(); }
    }

    /// <summary>Read a single relay cell inline (used during building, before the receive loop runs).</summary>
    private async Task<RelayCell> ReceiveRelayCellDirectAsync(int expectedHop, CancellationToken ct)
    {
        Cell cell = await _codec.ReadAsync(_link, ct).ConfigureAwait(false);
        if (cell.Command == CellCommand.Destroy)
            throw new CircuitException($"DESTROY (reason {ReasonByte(cell.Payload)}).");
        if (cell.Command is not (CellCommand.Relay or CellCommand.RelayEarly))
            throw new CircuitException($"Expected a RELAY cell, got {cell.Command}.");
        return DecryptAndVerify(cell.Payload.ToArray(), expectedHop);
    }

    /// <summary>Decrypt through hops 0..expectedHop, verify recognized + integrity digest, and parse.</summary>
    private RelayCell DecryptAndVerify(byte[] body, int expectedHop)
    {
        for (int i = 0; i <= expectedHop; i++) _hops[i].CryptBackward(body);

        if (body[RelayCell.RecognizedOffset] != 0 || body[RelayCell.RecognizedOffset + 1] != 0)
            throw new CircuitException("Relay cell not recognized at the expected hop.");

        byte[] received = body[RelayCell.DigestOffset..(RelayCell.DigestOffset + 4)];
        var zeroed = (byte[])body.Clone();
        Array.Clear(zeroed, RelayCell.DigestOffset, 4);
        byte[] expected = _hops[expectedHop].BackwardDigest(zeroed);
        if (!expected.AsSpan().SequenceEqual(received))
            throw new CircuitException("Relay cell integrity digest mismatch.");

        if (!RelayCell.TryParse(body, out RelayCell parsed))
            throw new CircuitException("Could not parse recognized relay cell.");
        return parsed;
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                Cell cell = await _codec.ReadAsync(_link, ct).ConfigureAwait(false);
                if (cell.Command == CellCommand.Destroy)
                    throw new CircuitException($"DESTROY (reason {ReasonByte(cell.Payload)}).");
                if (cell.Command is not (CellCommand.Relay or CellCommand.RelayEarly))
                    continue; // ignore non-relay cells (PADDING etc.)

                int last;
                lock (_hopsLock) last = _hops.Count - 1; // may grow after a RENDEZVOUS2 appends the service hop
                RelayCell parsed = DecryptAndVerify(cell.Payload.ToArray(), last);
                await DispatchAsync(parsed, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
        catch (Exception e)
        {
            Fault(e);
        }
    }

    private async Task DispatchAsync(RelayCell cell, CancellationToken ct)
    {
        switch (cell.Command)
        {
            case RelayCommand.Data:
                if (_circuitDeliver.OnDeliver())
                    await SendRelayCellAsync(_hops.Count - 1, RelayCommand.Sendme, 0, RelaySendmePayload.Legacy().Encode(), early: false, ct).ConfigureAwait(false);
                if (_streams.TryGetValue(cell.StreamId, out TorStream? s))
                    await s.OnDataAsync(cell.Data.ToArray(), ct).ConfigureAwait(false);
                break;

            case RelayCommand.Connected:
                if (_pendingOpens.TryGetValue(cell.StreamId, out var open)) open.TrySetResult(cell);
                break;

            case RelayCommand.End:
                if (_pendingOpens.TryGetValue(cell.StreamId, out var pend)) pend.TrySetResult(cell);
                if (_streams.TryRemove(cell.StreamId, out TorStream? ended)) ended.OnEnd();
                break;

            case RelayCommand.Sendme:
                if (cell.StreamId == 0)
                {
                    _circuitPackage.OnSendmeReceived();
                    _circuitPackageAvailable.Release();
                }
                else if (_streams.TryGetValue(cell.StreamId, out TorStream? fs))
                {
                    fs.OnSendme();
                }
                break;

            case RelayCommand.Truncated:
                throw new CircuitException($"TRUNCATED (reason {ReasonByte(cell.Data)}).");

            default:
                // Route HS control replies (RENDEZVOUS_ESTABLISHED, INTRODUCE_ACK, RENDEZVOUS2, …) to any waiter.
                if (_pendingControl.TryRemove(cell.Command, out TaskCompletionSource<RelayCell>? control))
                    control.TrySetResult(cell);
                break;
        }
    }

    private ushort NextStreamId()
    {
        int id = Interlocked.Increment(ref _nextStreamId);
        return (ushort)(((id - 1) % 65535) + 1); // 1..65535, never 0
    }

    private static int ReasonByte(ReadOnlyMemory<byte> payload) => payload.Length > 0 ? payload.Span[0] : 0;

    private void ThrowIfFaulted()
    {
        if (_fault is not null) throw new CircuitException($"Circuit faulted: {_fault.Message}");
    }

    private void Fault(Exception e)
    {
        _fault ??= e;
        foreach (var open in _pendingOpens.Values) open.TrySetException(e);
        foreach (var control in _pendingControl.Values) control.TrySetException(e);
        foreach (var s in _streams.Values) s.OnEnd();
    }

    public async ValueTask DisposeAsync()
    {
        _shutdown.Cancel();
        if (_receiveLoop is not null)
        {
            try { await _receiveLoop.ConfigureAwait(false); } catch { /* shutdown */ }
        }
        foreach (var s in _streams.Values) s.OnEnd();
        _shutdown.Dispose();
        _writeLock.Dispose();
        _circuitPackageAvailable.Dispose();
    }
}
