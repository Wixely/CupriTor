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

    private static readonly TimeSpan HealthInterval = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan RepublishInterval = TimeSpan.FromMinutes(60);

    private readonly TorNetwork _network;
    private readonly int _introCount;
    private readonly int _middleCount;
    private readonly Action<string>? _trace;

    // Reactor state (set in StartAsync, used by the supervisor).
    private readonly List<IntroPoint> _intros = new();
    private readonly object _introLock = new();
    private Ed25519ExpandedKey _identityKey;
    private byte[] _identityPub = Array.Empty<byte>();
    private int _periodLength = HsTimePeriod.DefaultLengthMinutes;
    private volatile byte[][] _activeSubcredentials = Array.Empty<byte[]>(); // the current + adjacent period subcredentials
    private Func<string, CancellationToken, Task<Stream?>> _targetHandler = (_, _) => Task.FromResult<Stream?>(null);
    private CancellationTokenSource? _cts;
    private Task? _supervisor;
    private DateTimeOffset _lastPublish;

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
    /// <paramref name="targetHandler"/> ("host:port" → local stream, or null to refuse). Returns a durable
    /// <see cref="OnionServiceHost"/> that keeps the intro points healthy and re-publishes automatically until
    /// disposed (or <paramref name="ct"/> is cancelled).
    /// </summary>
    public async Task<OnionServiceHost> StartAsync(OnionServiceKey identity, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        _targetHandler = targetHandler;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        CancellationToken token = _cts.Token;

        _identityKey = identity.ExpandedKey;
        _identityPub = identity.PublicKey;
        _periodLength = HsTimePeriod.DefaultLengthMinutes;
        _trace?.Invoke($"identity → {identity.OnionAddress}");

        DateTimeOffset now = DateTimeOffset.UtcNow;

        // 1. Establish introduction points (subcredential-independent — shared by both period descriptors).
        List<IntroPoint> intros = await EstablishIntroPointsAsync(now, _introCount, new HashSet<string>(), token).ConfigureAwait(false);
        if (intros.Count == 0) throw new InvalidOperationException("Could not establish any introduction points.");
        lock (_introLock) _intros.AddRange(intros);
        _trace?.Invoke($"established {intros.Count} introduction points");

        // 2. Build + publish the descriptor.
        int uploaded = await PublishOnceAsync(token).ConfigureAwait(false);
        if (uploaded == 0) throw new InvalidOperationException("Descriptor upload failed to every responsible HSDir.");

        // 3. Accept introductions on each intro circuit + start the supervisor (health + re-publish).
        foreach (IntroPoint ip in intros) StartAcceptLoop(ip, token);
        _supervisor = Task.Run(() => SuperviseAsync(token));

        return new OnionServiceHost(identity.OnionAddress, this);
    }

    private void StartAcceptLoop(IntroPoint ip, CancellationToken ct) => _ = AcceptLoopAsync(ip, _targetHandler, ct);

    /// <summary>The two (time period, SRV) pairs a service publishes for right now (rend-spec-v3 §2.2.4).</summary>
    private List<(long Tp, byte[] Srv)> ComputePeriods(Consensus consensus)
    {
        long tp = HsTimePeriod.Number(DateTimeOffset.UtcNow, _periodLength);
        byte[] cur = consensus.SharedRandomCurrentValue
            ?? throw new InvalidOperationException("Consensus has no current shared-random value.");
        byte[] prev = consensus.SharedRandomPreviousValue ?? cur;

        return HsTimePeriod.IsBetweenTpAndSrv(consensus.ValidAfter)
            ? new List<(long, byte[])> { (tp - 1, prev), (tp, cur) }   // afternoon: prev-TP/prev-SRV, cur-TP/cur-SRV
            : new List<(long, byte[])> { (tp, prev), (tp + 1, cur) };  // morning: cur-TP/prev-SRV, next-TP/cur-SRV
    }

    /// <summary>Derive the per-period blinded signing key, blinded public key, and subcredential for a time period.</summary>
    private (Ed25519ExpandedKey Key, byte[] Pub, byte[] Subcred) DerivePeriodKeys(long tp)
    {
        byte[] factor = HsBlinding.BlindingFactor(_identityPub, tp, _periodLength);
        var a = new byte[32];
        var rh = new byte[32];
        TorBlinding.BlindPrivateKey(_identityKey, factor, BlindPersonalization, a, rh);
        var pub = new byte[32];
        if (!HsBlinding.TryBlindPublicKey(_identityPub, tp, _periodLength, pub))
            throw new InvalidOperationException("Could not derive the blinded public key.");
        return (Ed25519ExpandedKey.FromParts(a, rh), pub, HsBlinding.Subcredential(_identityPub, pub));
    }

    /// <summary>
    /// Publish BOTH period descriptors (current + adjacent) with the correct SRV pairing, and record their
    /// subcredentials so INTRODUCE2 from either period can be decrypted. Returns the total HSDir uploads.
    /// </summary>
    private async Task<int> PublishOnceAsync(CancellationToken ct)
    {
        List<IntroPoint> snapshot;
        lock (_introLock) snapshot = _intros.ToList();
        if (snapshot.Count == 0) return 0;

        var publishIps = snapshot.Select(ip => new PublishIntroPoint(ip.LinkSpecifierBlock, ip.IntroRelayNtorKey, ip.AuthKeyPublic, ip.EncKeyPublic)).ToList();
        List<(long Tp, byte[] Srv)> periods = ComputePeriods(_network.Consensus);

        var subcredentials = new List<byte[]>();
        int total = 0;
        foreach ((long tp, byte[] srv) in periods)
        {
            (Ed25519ExpandedKey blindedKey, byte[] blindedPub, byte[] subcred) = DerivePeriodKeys(tp);
            subcredentials.Add(subcred);
            long revision = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); // monotonic per blinded key
            string descriptor = HsDescriptorBuilder.Build(blindedKey, blindedPub, subcred, revision, 180, DateTimeOffset.UtcNow.AddHours(3), publishIps);
            int uploaded = await PublishToHsDirsAsync(blindedPub, tp, _periodLength, srv, descriptor, ct).ConfigureAwait(false);
            total += uploaded;
            _trace?.Invoke($"published TP {tp}: {uploaded} HSDir(s) ({snapshot.Count} intros)");
        }

        _activeSubcredentials = subcredentials.ToArray();
        _lastPublish = DateTimeOffset.UtcNow;
        return total;
    }

    /// <summary>Supervisor: replace dead intro points and re-publish periodically so the service stays reachable.</summary>
    private async Task SuperviseAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await Task.Delay(HealthInterval, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }

            try
            {
                bool changed = await EnsureIntroPointsAsync(ct).ConfigureAwait(false);
                if (changed || DateTimeOffset.UtcNow - _lastPublish >= RepublishInterval)
                    await PublishOnceAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { _trace?.Invoke($"supervisor: {e.Message}"); }
        }
    }

    /// <summary>Drop faulted intro points and top the set back up to the target count. Returns true if the set changed.</summary>
    private async Task<bool> EnsureIntroPointsAsync(CancellationToken ct)
    {
        List<IntroPoint> dead;
        lock (_introLock)
        {
            dead = _intros.Where(ip => ip.Circuit.IsFaulted).ToList();
            _intros.RemoveAll(ip => ip.Circuit.IsFaulted);
        }
        foreach (IntroPoint d in dead)
        {
            _trace?.Invoke($"intro point {d.Relay.Nickname} died; replacing");
            try { await d.Connection.DisposeAsync().ConfigureAwait(false); } catch { }
        }

        HashSet<string> have;
        int need;
        lock (_introLock)
        {
            have = _intros.Select(ip => Convert.ToHexString(ip.Relay.RsaIdentityDigest)).ToHashSet();
            need = _introCount - _intros.Count;
        }
        if (need <= 0) return dead.Count > 0;

        List<IntroPoint> fresh = await EstablishIntroPointsAsync(DateTimeOffset.UtcNow, need, have, ct).ConfigureAwait(false);
        lock (_introLock) _intros.AddRange(fresh);
        foreach (IntroPoint ip in fresh) StartAcceptLoop(ip, ct);
        return dead.Count > 0 || fresh.Count > 0;
    }

    /// <summary>Stop the service: cancel loops, tear down all intro circuits.</summary>
    public async ValueTask StopAsync()
    {
        _cts?.Cancel();
        if (_supervisor is not null)
        {
            try { await _supervisor.ConfigureAwait(false); } catch { }
        }
        List<IntroPoint> snapshot;
        lock (_introLock) { snapshot = _intros.ToList(); _intros.Clear(); }
        foreach (IntroPoint ip in snapshot)
        {
            try { await ip.Connection.DisposeAsync().ConfigureAwait(false); } catch { }
        }
        _cts?.Dispose();
    }

    private async Task<List<IntroPoint>> EstablishIntroPointsAsync(DateTimeOffset now, int count, HashSet<string> exclude, CancellationToken ct)
    {
        var intros = new List<IntroPoint>();
        var used = new HashSet<string>(exclude);
        var rng = new SecureRandom();

        for (int attempt = 0; attempt < count * 4 && intros.Count < count; attempt++)
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

    private async Task<int> PublishToHsDirsAsync(byte[] blindedPub, long tp, int len, byte[] srv, string descriptor, CancellationToken ct)
    {
        (List<RouterStatusEntry> hsdirs, Dictionary<string, byte[]> edById) = await _network.ResolveHsDirsAsync(ct).ConfigureAwait(false);

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

    private async Task AcceptLoopAsync(IntroPoint ip, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            RelayCell cell;
            try { cell = await ip.Circuit.WaitForAsync(RelayCommand.Introduce2, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            catch (Exception) { break; }
            _ = HandleIntroduce2Async(ip, cell, targetHandler, ct);
        }
    }

    private async Task HandleIntroduce2Async(IntroPoint ip, RelayCell introduce2, Func<string, CancellationToken, Task<Stream?>> targetHandler, CancellationToken ct)
    {
        try
        {
            // The client used one of our active period descriptors; try each subcredential until one decrypts.
            byte[] cell = introduce2.Data.ToArray();
            IntroduceRequest? request = null;
            foreach (byte[] subcred in _activeSubcredentials)
                if (HsIntroduce.TryOpen(cell, ip.EncKeyPrivate, ip.EncKeyPublic, subcred, out IntroduceRequest r)) { request = r; break; }
            if (request is not { } req)
            {
                _trace?.Invoke("INTRODUCE2 failed to decrypt/verify (no matching subcredential)");
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
