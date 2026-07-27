using System.Text;
using CupriTor.Directory;
using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

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
    private readonly bool _useVanguards;

    public HsDescriptorClient(TorNetwork network, Action<string>? trace = null, bool useVanguards = false)
    {
        _network = network;
        _trace = trace;
        _useVanguards = useVanguards;
    }

    /// <summary>Fetch and decrypt a PUBLIC onion's descriptor (no client authorization).</summary>
    public Task<OnionDescriptorResult> FetchAsync(OnionAddress address, CancellationToken ct) =>
        FetchAsync(address, default, ct);

    /// <summary>
    /// Fetch and decrypt an onion-service descriptor. For a private (client-authorized) service, pass the client's
    /// 32-byte x25519 authorization private key in <paramref name="clientAuthKey"/> so the inner layer's descriptor
    /// cookie can be recovered; pass an empty value for a public service. Throws
    /// <see cref="OnionClientAuthorizationRequiredException"/> if the service is private and the supplied key is
    /// missing or not authorized.
    /// </summary>
    public async Task<OnionDescriptorResult> FetchAsync(OnionAddress address, ReadOnlyMemory<byte> clientAuthKey, CancellationToken ct)
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
                OnionDescriptorResult? result = await TryFetchFromAsync(hsdir, blinded, subcredential, clientAuthKey, ct).ConfigureAwait(false);
                if (result is not null) { _trace?.Invoke($"[{attempt}] descriptor OK ({result.IntroductionPoints.Count} intro points)"); return result; }
            }
            // An authorization failure is the same at every HSDir (they serve the same descriptor), so let it
            // propagate immediately rather than fruitlessly retrying the rest of the ring.
            catch (Exception e) when (e is not OperationCanceledException and not OnionClientAuthorizationRequiredException)
            {
                last = e;
                _trace?.Invoke($"[{attempt}] error: {e.GetType().Name}: {e.Message}");
            }
        }
        throw new InvalidOperationException("No responsible HSDir served a valid descriptor.", last);
    }

    private async Task<OnionDescriptorResult?> TryFetchFromAsync(RouterStatusEntry hsdir, byte[] blinded, byte[] subcredential, ReadOnlyMemory<byte> clientAuthKey, CancellationToken ct)
    {
        (OrConnection conn, Circuit circuit) = await _network.BuildCircuitToAsync(hsdir, middleCount: 1, DateTimeOffset.UtcNow, ct, vanguards: _useVanguards).ConfigureAwait(false);
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

            // Decrypt both layers to intro points (recovering the client-auth cookie for a private onion). An
            // authorization failure throws (propagated); a corrupt/mismatched descriptor returns null (try next HSDir).
            List<IntroductionPoint>? intros = DecryptIntroPoints(view, blinded, subcredential, clientAuthKey.Span, _trace);
            if (intros is null) return null;

            return new OnionDescriptorResult(blinded, subcredential, view.RevisionCounter, signingKey, intros);
        }
    }

    /// <summary>
    /// Decrypt a verified descriptor's superencrypted + encrypted layers down to its introduction points. The outer
    /// layer never uses the descriptor cookie; the inner layer does only for a private (client-authorized) service.
    /// We first try the inner layer without a cookie (public service); if that fails the service is private, so we
    /// recover the descriptor cookie from the client's x25519 auth key (rend-spec-v3 §2.5.1.3) and retry. Returns
    /// null for a corrupt/mismatched descriptor; throws <see cref="OnionClientAuthorizationRequiredException"/> when
    /// the service is private and <paramref name="clientAuthKey"/> is missing or not authorized. Pure (no I/O), so
    /// the client-auth crypto round-trips offline against <c>HsDescriptorBuilder</c>.
    /// </summary>
    internal static List<IntroductionPoint>? DecryptIntroPoints(
        HsDescriptorView view, byte[] blinded, byte[] subcredential, ReadOnlySpan<byte> clientAuthKey, Action<string>? trace = null)
    {
        byte[] outerSecret = HsLayerCrypto.SecretInput(blinded, subcredential, view.RevisionCounter);
        if (!HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, outerSecret, HsLayerCrypto.SuperencryptedConstant, out byte[] superPlain))
        { trace?.Invoke("  superencrypted-layer decrypt FAILED"); return null; }
        if (!HsSuperencryptedLayer.TryExtractInner(superPlain, out byte[] innerBlob))
        { trace?.Invoke("  inner-layer extract FAILED"); return null; }

        byte[] innerPlain;
        if (HsLayerCrypto.TryDecrypt(innerBlob, outerSecret, HsLayerCrypto.EncryptedConstant, out byte[] publicInner))
        {
            innerPlain = publicInner; // public service: inner layer decrypts with the same cookie-less secret input
        }
        else
        {
            // Private service: recover the descriptor cookie from the client's auth key and decrypt with it.
            byte[]? cookie = clientAuthKey.IsEmpty ? null : RecoverCookie(superPlain, clientAuthKey, subcredential);
            if (cookie is null)
                throw new OnionClientAuthorizationRequiredException(noKeySupplied: clientAuthKey.IsEmpty);
            byte[] innerSecret = HsLayerCrypto.SecretInput(blinded, subcredential, view.RevisionCounter, cookie);
            if (!HsLayerCrypto.TryDecrypt(innerBlob, innerSecret, HsLayerCrypto.EncryptedConstant, out innerPlain))
                throw new OnionClientAuthorizationRequiredException(noKeySupplied: false); // cookie recovered but decrypt failed → not authorized
        }

        if (!HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> intros))
        { trace?.Invoke("  intro-point parse FAILED"); return null; }
        return intros;
    }

    // Recover the 16-byte descriptor cookie from the decrypted superencrypted layer using the client's x25519 private
    // key (rend-spec-v3 §2.5.1.3): x25519(client, ephemeral) → SHAKE-256(subcredential ‖ seed) → CLIENT-ID(8) +
    // COOKIE-KEY(32); find the auth-client entry matching CLIENT-ID and AES-256-CTR-decrypt its cookie. Mirrors the
    // service's HsDescriptorBuilder.AuthClientEntry. Null when this key matches no entry (not an authorized client).
    private static byte[]? RecoverCookie(ReadOnlySpan<byte> outerPlain, ReadOnlySpan<byte> clientPrivate, byte[] subcredential)
    {
        byte[]? ephemeralPub = null;
        var entries = new List<(byte[] Id, byte[] Iv, byte[] Enc)>();
        foreach (DirectoryItem item in DirectoryReader.Parse(Encoding.ASCII.GetString(outerPlain)))
        {
            if (item.Keyword == "desc-auth-ephemeral-key") ephemeralPub = DirectoryReader.Base64(item.Arguments[0]);
            else if (item.Keyword == "auth-client" && item.Arguments.Length >= 3)
                entries.Add((DirectoryReader.Base64(item.Arguments[0]), DirectoryReader.Base64(item.Arguments[1]), DirectoryReader.Base64(item.Arguments[2])));
        }
        if (ephemeralPub is not { Length: 32 }) return null;

        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(clientPrivate.ToArray(), 0));
        var seed = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(new X25519PublicKeyParameters(ephemeralPub, 0), seed, 0);

        var shake = new ShakeDigest(256);
        shake.BlockUpdate(subcredential, 0, subcredential.Length);
        shake.BlockUpdate(seed, 0, seed.Length);
        var keys = new byte[40];
        shake.OutputFinal(keys, 0, keys.Length);
        byte[] clientId = keys[..8];
        byte[] cookieKey = keys[8..40];

        foreach ((byte[] id, byte[] iv, byte[] enc) in entries)
            if (id.AsSpan().SequenceEqual(clientId))
            {
                byte[] cookie = (byte[])enc.Clone();
                new AesCtrKeystream(cookieKey, iv).XorInPlace(cookie);
                return cookie;
            }
        return null;
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
