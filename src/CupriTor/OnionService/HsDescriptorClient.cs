using System.Text;
using CupriTor.Directory;
using CupriTor.Protocol;

namespace CupriTor.OnionService;

/// <summary>A fetched, verified, decrypted v3 onion-service descriptor: the keys and introduction points a client needs to connect.</summary>
internal sealed record OnionDescriptorResult(
    byte[] BlindedKey,
    byte[] Subcredential,
    long RevisionCounter,
    byte[] DescriptorSigningKey,
    IReadOnlyList<IntroductionPoint> IntroductionPoints);

/// <summary>
/// Client side of v3 onion-service descriptor lookup (rend-spec-v3 §2): derive the per-period blinded
/// key and subcredential from the .onion identity, compute the responsible HSDirs (the hash ring), fetch
/// the descriptor over a circuit (BEGIN_DIR to <c>/tor/hs/3/&lt;blinded&gt;</c>), then verify its signature
/// and decrypt both layers to recover the introduction points. Uses the live-confirmed parameters:
/// current time period, current shared-random value, padded base64. This is the first half of connecting
/// to an onion; the introduce/rendezvous handshake is the second.
/// </summary>
internal sealed class HsDescriptorClient
{
    private readonly TorNetwork _network;
    private readonly Action<string>? _trace;

    public HsDescriptorClient(TorNetwork network, Action<string>? trace = null)
    {
        _network = network;
        _trace = trace;
    }

    public async Task<OnionDescriptorResult> FetchAsync(OnionAddress address, CancellationToken ct)
    {
        byte[] identity = address.PublicKey.ToArray();
        int len = HsTimePeriod.DefaultLengthMinutes;
        long tp = HsTimePeriod.Number(DateTimeOffset.UtcNow, len);

        // The current time period is paired with the SRV that was current when that period BEGAN. In the afternoon
        // window [12:00-24:00) UTC that's the current SRV; in the morning window [00:00-12:00) the SRV rotated at
        // 00:00 while the period began at the previous noon, so the current descriptor uses the PREVIOUS SRV. Using
        // the wrong SRV computes the wrong HSDir ring and every responsible HSDir returns 404. This mirrors the
        // service's two-period publish (HsService.ComputePeriods).
        Consensus consensus = _network.Consensus;
        byte[] cur = consensus.SharedRandomCurrentValue
            ?? throw new InvalidOperationException("Consensus has no shared-random value; cannot compute the HSDir ring.");
        byte[] srv = HsTimePeriod.IsBetweenTpAndSrv(consensus.ValidAfter) ? cur : (consensus.SharedRandomPreviousValue ?? cur);

        var blinded = new byte[32];
        if (!HsBlinding.TryBlindPublicKey(identity, tp, len, blinded))
            throw new InvalidOperationException("The .onion identity is not a valid Ed25519 point.");
        byte[] subcredential = HsBlinding.Subcredential(identity, blinded);

        (List<RouterStatusEntry> hsdirs, Dictionary<string, byte[]> edById) = await _network.ResolveHsDirsAsync(ct).ConfigureAwait(false);
        if (hsdirs.Count == 0)
            throw new InvalidOperationException("Could not resolve any HSDir ed25519 identities.");

        byte[] EdOf(RouterStatusEntry r) => edById[Convert.ToHexString(r.RsaIdentityDigest)];
        List<RouterStatusEntry> responsible = HsDirRing.Responsible(
            hsdirs, EdOf, blinded, srv, tp, len, HsDirRing.DefaultReplicas, HsDirRing.DefaultSpreadFetch);
        _trace?.Invoke($"tp={tp}, {hsdirs.Count} HSDirs in ring, {responsible.Count} responsible; blinded={Convert.ToHexString(blinded)[..16]}… srv={Convert.ToHexString(srv)[..16]}…");

        Exception? last = null;
        int attempt = 0;
        foreach (RouterStatusEntry hsdir in responsible)
        {
            attempt++;
            try
            {
                _trace?.Invoke($"[{attempt}/{responsible.Count}] HSDir {hsdir.Nickname} {hsdir.Address}:{hsdir.OrPort} — building circuit + fetching");
                OnionDescriptorResult? result = await TryFetchFromAsync(hsdir, blinded, subcredential, ct).ConfigureAwait(false);
                if (result is not null) { _trace?.Invoke($"[{attempt}] descriptor OK ({result.IntroductionPoints.Count} intro points)"); return result; }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                last = e;
                _trace?.Invoke($"[{attempt}] error: {e.GetType().Name}: {e.Message}");
            }
        }
        throw new InvalidOperationException("No responsible HSDir served a valid descriptor.", last);
    }

    private async Task<OnionDescriptorResult?> TryFetchFromAsync(RouterStatusEntry hsdir, byte[] blinded, byte[] subcredential, CancellationToken ct)
    {
        (OrConnection conn, Circuit circuit) = await _network.BuildCircuitToAsync(hsdir, middleCount: 1, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        await using (conn)
        {
            string z = Convert.ToBase64String(blinded); // padded — confirmed live
            byte[] response = await DirFetchAsync(circuit, $"/tor/hs/3/{z}", ct).ConfigureAwait(false);
            if (response.Length == 0) { _trace?.Invoke("  empty response"); return null; }

            string text = Encoding.ASCII.GetString(response);
            int firstLineEnd = text.IndexOf('\n');
            string statusLine = firstLineEnd >= 0 ? text[..firstLineEnd] : text;
            _trace?.Invoke($"  HTTP: {statusLine.Trim()} ({response.Length} bytes)");
            if (!statusLine.Contains("200")) return null;

            int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string descriptorText = headerEnd >= 0 ? text[(headerEnd + 4)..] : text;

            if (!HsDescriptor.TryParse(descriptorText, out HsDescriptorView view)) { _trace?.Invoke("  descriptor parse FAILED"); return null; }
            if (!view.TryVerify(blinded, out byte[] signingKey)) { _trace?.Invoke("  signature verify FAILED"); return null; }

            byte[] secretInput = HsLayerCrypto.SecretInput(blinded, subcredential, view.RevisionCounter);
            if (!HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, secretInput, HsLayerCrypto.SuperencryptedConstant, out byte[] superPlain))
            { _trace?.Invoke("  superencrypted-layer decrypt FAILED"); return null; }
            if (!HsSuperencryptedLayer.TryExtractInner(superPlain, out byte[] innerBlob) ||
                !HsLayerCrypto.TryDecrypt(innerBlob, secretInput, HsLayerCrypto.EncryptedConstant, out byte[] innerPlain))
            { _trace?.Invoke("  inner-layer decrypt FAILED"); return null; }
            if (!HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> intros))
            { _trace?.Invoke("  intro-point parse FAILED"); return null; }

            return new OnionDescriptorResult(blinded, subcredential, view.RevisionCounter, signingKey, intros);
        }
    }

    /// <summary>Open a BEGIN_DIR stream on the circuit and fetch <paramref name="path"/> over HTTP/1.0.</summary>
    private static async Task<byte[]> DirFetchAsync(Circuit circuit, string path, CancellationToken ct)
    {
        await using Stream stream = await circuit.OpenDirectoryStreamAsync(ct).ConfigureAwait(false);
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET {path} HTTP/1.0\r\n\r\n"), ct).ConfigureAwait(false);

        using var body = new MemoryStream();
        var buffer = new byte[4096];
        int n;
        while ((n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            body.Write(buffer, 0, n);
        return body.ToArray();
    }
}
