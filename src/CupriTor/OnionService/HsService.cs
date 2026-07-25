using System.Text;
using CupriCurve;
using CupriTor.Directory;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriTor.OnionService;

/// <summary>
/// Hosts a v3 onion service (rend-spec-v3 §3–4), the mirror of <see cref="OnionConnector"/>: derive the
/// .onion identity, establish introduction points (ESTABLISH_INTRO), build + publish the descriptor to the
/// responsible HSDirs, then accept INTRODUCE2 → build a rendezvous circuit → RENDEZVOUS1 → splice the
/// reversed service hop → serve the client's RELAY_BEGIN from a local target. Returns a running handle.
/// </summary>
internal sealed class HsService
{
    private static readonly byte[] BlindPersonalization = Encoding.ASCII.GetBytes("Derive temporary signing key hash input");

    private readonly TorNetwork _network;
    private readonly int _introCount;
    private readonly int _middleCount;
    private readonly Action<string>? _trace;

    public HsService(TorNetwork network, int introCount = 3, int middleCount = 1, Action<string>? trace = null)
    {
        _network = network;
        _introCount = introCount;
        _middleCount = middleCount;
        _trace = trace;
    }

    /// <summary>Per-intro-point state: the relay it lives on, our keys there, and the intro circuit kept open.</summary>
    private sealed record IntroPoint(
        RouterStatusEntry Relay, byte[] LinkSpecifierBlock, byte[] IntroRelayNtorKey,
        Ed25519ExpandedKey AuthKey, byte[] AuthKeyPublic,
        X25519PrivateKeyParameters EncKey, byte[] EncKeyPublic, byte[] EncKeyPrivate,
        OrConnection Connection, Circuit Circuit);

    /// <summary>
    /// Start hosting the onion service for <paramref name="identity"/>. Inbound streams are served by
    /// <paramref name="targetHandler"/> ("host:port" → local stream, or null to refuse). Returns the .onion
    /// address; the service keeps running until <paramref name="ct"/> is cancelled.
    /// </summary>
    public async Task<string> StartAsync(OnionServiceKey identity, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        Ed25519ExpandedKey identityKey = identity.ExpandedKey;
        byte[] identityPub = identity.PublicKey;
        string onion = identity.OnionAddress;
        _trace?.Invoke($"identity → {onion}");

        DateTimeOffset now = DateTimeOffset.UtcNow;
        int len = HsTimePeriod.DefaultLengthMinutes;
        long tp = HsTimePeriod.Number(now, len);

        // Per-period blinded key: private (to sign the descriptor) + public (for the ring/subcredential).
        byte[] factor = HsBlinding.BlindingFactor(identityPub, tp, len);
        var aPrime = new byte[32];
        var rhPrime = new byte[32];
        TorBlinding.BlindPrivateKey(identityKey, factor, BlindPersonalization, aPrime, rhPrime);
        var blindedKey = Ed25519ExpandedKey.FromParts(aPrime, rhPrime);
        var blindedPub = new byte[32];
        if (!HsBlinding.TryBlindPublicKey(identityPub, tp, len, blindedPub))
            throw new InvalidOperationException("Could not derive the blinded public key.");
        byte[] subcredential = HsBlinding.Subcredential(identityPub, blindedPub);

        // 1. Establish introduction points.
        List<IntroPoint> intros = await EstablishIntroPointsAsync(now, ct).ConfigureAwait(false);
        if (intros.Count == 0) throw new InvalidOperationException("Could not establish any introduction points.");
        _trace?.Invoke($"established {intros.Count} introduction points");

        // 2. Build + publish the descriptor.
        var publishIps = intros.Select(ip => new PublishIntroPoint(ip.LinkSpecifierBlock, ip.IntroRelayNtorKey, ip.AuthKeyPublic, ip.EncKeyPublic)).ToList();
        long revision = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string descriptor = HsDescriptorBuilder.Build(blindedKey, blindedPub, subcredential, revision, 180, now.AddHours(3), publishIps);
        int uploaded = await PublishAsync(blindedPub, tp, len, descriptor, ct).ConfigureAwait(false);
        _trace?.Invoke($"published descriptor to {uploaded} HSDir(s)");
        if (uploaded == 0) throw new InvalidOperationException("Descriptor upload failed to every responsible HSDir.");

        // 3. Accept introductions on each intro circuit.
        foreach (IntroPoint ip in intros)
            _ = AcceptLoopAsync(ip, subcredential, targetHandler, ct);

        return onion;
    }

    private async Task<List<IntroPoint>> EstablishIntroPointsAsync(DateTimeOffset now, CancellationToken ct)
    {
        var intros = new List<IntroPoint>();
        var used = new HashSet<string>();
        var rng = new SecureRandom();

        for (int attempt = 0; attempt < _introCount * 4 && intros.Count < _introCount; attempt++)
        {
            RouterStatusEntry? relay = _network.SelectRelay(new[] { "Fast", "Stable" });
            if (relay is null) break;
            string fp = Convert.ToHexString(relay.RsaIdentityDigest);
            if (!used.Add(fp)) continue;

            OrConnection? conn = null;
            try
            {
                Microdescriptor md = await _network.ResolveMicrodescriptorAsync(relay, ct).ConfigureAwait(false);
                if (md.NtorOnionKey.Length != 32 || md.Ed25519Identity is not { Length: 32 }) continue;

                var authSeed = new byte[32];
                rng.NextBytes(authSeed);
                var authKey = Ed25519ExpandedKey.FromSeed(authSeed);
                var authPub = new byte[32];
                authKey.GetPublicKey(authPub);

                var encPriv = new X25519PrivateKeyParameters(rng);
                byte[] encPub = encPriv.GeneratePublicKey().GetEncoded();
                byte[] encPrivRaw = encPriv.GetEncoded();

                byte[] linkSpecs = LinkSpecifier.EncodeList(new List<LinkSpecifier>
                {
                    LinkSpecifier.FromIPv4(relay.Address, (ushort)relay.OrPort),
                    LinkSpecifier.FromLegacyId(relay.RsaIdentityDigest),
                    LinkSpecifier.FromEd25519Id(md.Ed25519Identity),
                });

                (OrConnection c, Circuit circuit) = await _network.BuildCircuitToAsync(relay, _middleCount, now, ct).ConfigureAwait(false);
                conn = c;

                byte[] establish = HsEstablishIntro.Build(authPub, authKey, circuit.LastKh);
                RelayCell reply = await circuit.SendControlAndAwaitAsync(RelayCommand.EstablishIntro, establish, RelayCommand.IntroEstablished, early: false, ct).ConfigureAwait(false);
                if (!HsEstablishIntro.ParseEstablished(reply.Data.Span)) { await c.DisposeAsync().ConfigureAwait(false); continue; }

                intros.Add(new IntroPoint(relay, linkSpecs, md.NtorOnionKey, authKey, authPub, encPriv, encPub, encPrivRaw, c, circuit));
                _trace?.Invoke($"intro point established: {relay.Nickname} {relay.Address}:{relay.OrPort}");
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                _trace?.Invoke($"intro point {relay.Nickname} failed: {e.Message}");
                if (conn is not null) await conn.DisposeAsync().ConfigureAwait(false);
            }
        }
        return intros;
    }

    private async Task<int> PublishAsync(byte[] blindedPub, long tp, int len, string descriptor, CancellationToken ct)
    {
        (List<RouterStatusEntry> hsdirs, Dictionary<string, byte[]> edById) = await _network.ResolveHsDirsAsync(ct).ConfigureAwait(false);
        byte[] srv = _network.Consensus.SharedRandomCurrentValue
            ?? throw new InvalidOperationException("Consensus has no shared-random value for the HSDir ring.");

        byte[] EdOf(RouterStatusEntry r) => edById[Convert.ToHexString(r.RsaIdentityDigest)];
        List<RouterStatusEntry> responsible = HsDirRing.Responsible(hsdirs, EdOf, blindedPub, srv, tp, len, HsDirRing.DefaultReplicas, HsDirRing.DefaultSpreadStore);

        int ok = 0;
        foreach (RouterStatusEntry hsdir in responsible)
        {
            try
            {
                if (await UploadAsync(hsdir, descriptor, ct).ConfigureAwait(false)) ok++;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                _trace?.Invoke($"upload to {hsdir.Nickname} failed: {e.Message}");
            }
        }
        return ok;
    }

    private async Task<bool> UploadAsync(RouterStatusEntry hsdir, string descriptor, CancellationToken ct)
    {
        (OrConnection conn, Circuit circuit) = await _network.BuildCircuitToAsync(hsdir, _middleCount, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await using (conn)
        {
            await using Stream stream = await circuit.OpenDirectoryStreamAsync(ct).ConfigureAwait(false);
            byte[] body = Encoding.ASCII.GetBytes(descriptor);
            string header = $"POST /tor/hs/3/publish HTTP/1.0\r\nHost: \r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(header), ct).ConfigureAwait(false);
            await stream.WriteAsync(body, ct).ConfigureAwait(false);

            using var response = new MemoryStream();
            var buffer = new byte[2048];
            int n;
            while ((n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                response.Write(buffer, 0, n);
                if (response.Length > 8192) break;
            }
            string statusLine = Encoding.ASCII.GetString(response.ToArray()).Split('\n').FirstOrDefault()?.Trim() ?? "";
            bool success = statusLine.Contains("200");
            _trace?.Invoke($"upload to {hsdir.Nickname}: {statusLine}");
            return success;
        }
    }

    private async Task AcceptLoopAsync(IntroPoint ip, byte[] subcredential, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            RelayCell cell;
            try { cell = await ip.Circuit.WaitForAsync(RelayCommand.Introduce2, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (Exception) { break; }
            _ = HandleIntroduce2Async(ip, subcredential, cell, targetHandler, ct);
        }
    }

    private async Task HandleIntroduce2Async(IntroPoint ip, byte[] subcredential, RelayCell introduce2, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        try
        {
            if (!HsIntroduce.TryOpen(introduce2.Data.ToArray(), ip.EncKeyPrivate, ip.EncKeyPublic, subcredential, out IntroduceRequest req))
            {
                _trace?.Invoke("INTRODUCE2 failed to decrypt/verify");
                return;
            }
            _trace?.Invoke("INTRODUCE2 decrypted; completing hs-ntor rendezvous");

            (byte[] ServicePublic, byte[] NtorKeySeed, byte[] Auth)? rend =
                HsNtor.ServiceRendezvous(ip.EncKeyPrivate, ip.EncKeyPublic, ip.AuthKeyPublic, req.ClientPublic);
            if (rend is null) { _trace?.Invoke("hs-ntor ServiceRendezvous failed"); return; }

            (OrConnection rpConn, Circuit rpCircuit) = await _network.BuildCircuitToIntroAsync(
                req.RendezvousLinkSpecifiers, req.RendezvousNtorKey, _middleCount, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);

            // RENDEZVOUS1 goes to the RP (normal last-hop crypto) BEFORE we splice the reversed service hop.
            byte[] handshake = HsCells.BuildRendezvousHandshake(rend.Value.ServicePublic, rend.Value.Auth);
            byte[] rend1 = HsCells.BuildRendezvous1Padded(req.RendezvousCookie, handshake);
            await rpCircuit.SendControlAsync(RelayCommand.Rendezvous1, rend1, early: false, ct).ConfigureAwait(false);

            rpCircuit.AppendHopReversed(HsNtor.DeriveKeys(rend.Value.NtorKeySeed, RelayCrypto.KeyMaterialLengthV3Hs));
            rpCircuit.OnIncomingStream(targetHandler); // now accept the client's RELAY_BEGIN
            _trace?.Invoke("rendezvous spliced; serving client");
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _trace?.Invoke($"introduce/rendezvous failed: {e.Message}");
        }
    }
}
