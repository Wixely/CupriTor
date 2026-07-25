using System.Buffers.Binary;
using CupriTor.Directory;
using CupriTor.Protocol;

namespace CupriTor.OnionService;

/// <summary>
/// Connects to a v3 onion service (rend-spec-v3 §3–4), the CupriNet capstone: fetch + decrypt the
/// descriptor, establish a rendezvous point, INTRODUCE1 to an introduction point (hs-ntor), receive
/// RENDEZVOUS2, complete the handshake, splice the service onion layer onto the rendezvous circuit, and
/// open an application stream to the service. Returns a <see cref="Stream"/> that owns the rendezvous
/// circuit and its connection.
/// </summary>
internal sealed class OnionConnector
{
    private readonly TorNetwork _network;
    private readonly int _middleCount;
    private readonly Action<string>? _trace;

    public OnionConnector(TorNetwork network, int middleCount = 1, Action<string>? trace = null)
    {
        _network = network;
        _middleCount = middleCount;
        _trace = trace;
    }

    public async Task<Stream> ConnectAsync(OnionAddress onion, int port, CancellationToken ct)
    {
        // 1. Fetch + decrypt the descriptor → introduction points.
        var descriptorClient = new HsDescriptorClient(_network);
        OnionDescriptorResult descriptor = await descriptorClient.FetchAsync(onion, ct).ConfigureAwait(false);
        if (descriptor.IntroductionPoints.Count == 0)
            throw new InvalidOperationException("The onion descriptor carries no introduction points.");
        _trace?.Invoke($"descriptor decrypted: {descriptor.IntroductionPoints.Count} intro points");

        // 2. Choose a rendezvous point and resolve its ntor key + ed25519 id.
        RouterStatusEntry rp = _network.SelectRelay(new[] { "Fast", "Stable" })
            ?? throw new InvalidOperationException("No suitable rendezvous point in the consensus.");
        Microdescriptor rpMd = await _network.ResolveMicrodescriptorAsync(rp, ct).ConfigureAwait(false);
        byte[] rpLinkSpecifiers = LinkSpecifier.EncodeList(RendezvousSpecifiers(rp, rpMd));
        _trace?.Invoke($"rendezvous point: {rp.Nickname} {rp.Address}:{rp.OrPort}");

        // 3. Build the rendezvous circuit and establish the rendezvous point.
        (OrConnection rendConn, Circuit rendCircuit) = await _network.BuildCircuitToAsync(rp, _middleCount, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        try
        {
            _trace?.Invoke("rendezvous circuit built; sending ESTABLISH_RENDEZVOUS");
            byte[] cookie = HsCells.NewRendezvousCookie();
            await rendCircuit.SendControlAndAwaitAsync(RelayCommand.EstablishRendezvous, cookie, RelayCommand.RendezvousEstablished, early: false, ct).ConfigureAwait(false);
            _trace?.Invoke("RENDEZVOUS_ESTABLISHED received");

            // Register the RENDEZVOUS2 waiter before introducing, so we can't miss the service's reply.
            Task<RelayCell> rendezvous2 = rendCircuit.WaitForAsync(RelayCommand.Rendezvous2, ct);

            // 4. INTRODUCE1 via an introduction point (hs-ntor); returns the client handshake state.
            HsNtor.ClientState hs = await IntroduceAsync(descriptor, rpMd.NtorOnionKey, rpLinkSpecifiers, cookie, ct).ConfigureAwait(false);
            _trace?.Invoke("INTRODUCE_ACK success; waiting for RENDEZVOUS2");

            // 5. Complete the rendezvous handshake and splice the service's onion layer onto the circuit.
            RelayCell reply = await rendezvous2.ConfigureAwait(false);
            _trace?.Invoke($"RENDEZVOUS2 received ({reply.Data.Length} bytes)");
            if (!HsCells.TryParseRendezvousHandshake(reply.Data.Span, out byte[] servicePublic, out byte[] auth))
                throw new InvalidOperationException("Malformed RENDEZVOUS2 handshake.");
            byte[]? keySeed = HsNtor.ClientRendezvous(hs, servicePublic, auth)
                ?? throw new InvalidOperationException("Rendezvous hs-ntor AUTH verification failed.");
            _trace?.Invoke("rendezvous AUTH verified; splicing service hop");
            rendCircuit.AppendHop(HsNtor.DeriveKeys(keySeed, RelayCrypto.KeyMaterialLengthV3Hs));

            // 6. Open the application stream to the service. For a hidden service the RELAY_BEGIN address
            //    is empty (just ":port") — the service knows its own identity; a non-empty host is rejected.
            _trace?.Invoke($"sending RELAY_BEGIN to :{port}");
            Stream inner = await rendCircuit.ConnectAsync($":{port}", ct).ConfigureAwait(false);
            _trace?.Invoke("stream CONNECTED");
            return new OwningStream(inner, rendCircuit, rendConn);
        }
        catch
        {
            await rendCircuit.DisposeAsync().ConfigureAwait(false);
            await rendConn.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<HsNtor.ClientState> IntroduceAsync(OnionDescriptorResult descriptor, byte[] rpNtorKey, byte[] rpLinkSpecifiers, byte[] cookie, CancellationToken ct)
    {
        Exception? last = null;
        foreach (IntroductionPoint ip in descriptor.IntroductionPoints)
        {
            if (!LinkSpecifier.TryParseList(ip.LinkSpecifiers.Span, out List<LinkSpecifier> introSpecifiers))
                continue;

            OrConnection? introConn = null;
            Circuit? introCircuit = null;
            try
            {
                _trace?.Invoke("building intro circuit to an introduction point");
                (introConn, introCircuit) = await _network.BuildCircuitToIntroAsync(introSpecifiers, ip.OnionKeyNtor, _middleCount, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);

                HsNtor.ClientState hs = HsNtor.ClientIntroduce(ip.EncKey, ip.AuthKey, descriptor.Subcredential);
                byte[] introduce1 = HsIntroduce.Build(hs, ip.AuthKey, cookie, rpNtorKey, rpLinkSpecifiers);

                _trace?.Invoke("sending INTRODUCE1");
                RelayCell ack = await introCircuit.SendControlAndAwaitAsync(RelayCommand.Introduce1, introduce1, RelayCommand.IntroduceAck, early: false, ct).ConfigureAwait(false);
                int status = ack.Data.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(ack.Data.Span) : -1;
                _trace?.Invoke($"INTRODUCE_ACK status {status}");

                await introCircuit.DisposeAsync().ConfigureAwait(false);
                await introConn.DisposeAsync().ConfigureAwait(false);
                introCircuit = null;
                introConn = null;

                if (status == 0) return hs; // ACK success — the service is now contacting our rendezvous point
                last = new InvalidOperationException($"INTRODUCE_ACK returned status {status}.");
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                last = e;
                if (introCircuit is not null) await introCircuit.DisposeAsync().ConfigureAwait(false);
                if (introConn is not null) await introConn.DisposeAsync().ConfigureAwait(false);
            }
        }
        throw new InvalidOperationException("No introduction point accepted the INTRODUCE1.", last);
    }

    private static List<LinkSpecifier> RendezvousSpecifiers(RouterStatusEntry rp, Microdescriptor md)
    {
        var specs = new List<LinkSpecifier>
        {
            LinkSpecifier.FromIPv4(rp.Address, (ushort)rp.OrPort),
            LinkSpecifier.FromLegacyId(rp.RsaIdentityDigest),
        };
        if (md.Ed25519Identity is { Length: 32 }) specs.Add(LinkSpecifier.FromEd25519Id(md.Ed25519Identity));
        return specs;
    }

    /// <summary>A stream that owns the rendezvous circuit and its OR connection, tearing them down on dispose.</summary>
    private sealed class OwningStream(Stream inner, Circuit circuit, OrConnection connection) : Stream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => await inner.ReadAsync(buffer, ct).ConfigureAwait(false);
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => await inner.WriteAsync(buffer, ct).ConfigureAwait(false);
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            await circuit.DisposeAsync().ConfigureAwait(false);
            await connection.DisposeAsync().ConfigureAwait(false);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) DisposeAsync().AsTask().GetAwaiter().GetResult();
            base.Dispose(disposing);
        }
    }
}
