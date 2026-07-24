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

    public HsDescriptorClient(TorNetwork network) => _network = network;

    public async Task<OnionDescriptorResult> FetchAsync(OnionAddress address, CancellationToken ct)
    {
        byte[] identity = address.PublicKey.ToArray();
        int len = HsTimePeriod.DefaultLengthMinutes;
        long tp = HsTimePeriod.Number(DateTimeOffset.UtcNow, len);
        byte[] srv = _network.Consensus.SharedRandomCurrentValue
            ?? throw new InvalidOperationException("Consensus has no shared-random value; cannot compute the HSDir ring.");

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

        Exception? last = null;
        foreach (RouterStatusEntry hsdir in responsible)
        {
            try
            {
                OnionDescriptorResult? result = await TryFetchFromAsync(hsdir, blinded, subcredential, ct).ConfigureAwait(false);
                if (result is not null) return result;
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                last = e;
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
            if (response.Length == 0) return null;

            string text = Encoding.ASCII.GetString(response);
            int firstLineEnd = text.IndexOf('\n');
            string statusLine = firstLineEnd >= 0 ? text[..firstLineEnd] : text;
            if (!statusLine.Contains("200")) return null;

            int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            string descriptorText = headerEnd >= 0 ? text[(headerEnd + 4)..] : text;

            if (!HsDescriptor.TryParse(descriptorText, out HsDescriptorView view)) return null;
            if (!view.TryVerify(blinded, out byte[] signingKey)) return null;

            byte[] secretInput = HsLayerCrypto.SecretInput(blinded, subcredential, view.RevisionCounter);
            if (!HsLayerCrypto.TryDecrypt(view.SuperencryptedBlob.Span, secretInput, HsLayerCrypto.SuperencryptedConstant, out byte[] superPlain))
                return null;
            if (!HsSuperencryptedLayer.TryExtractInner(superPlain, out byte[] innerBlob) ||
                !HsLayerCrypto.TryDecrypt(innerBlob, secretInput, HsLayerCrypto.EncryptedConstant, out byte[] innerPlain))
                return null;
            if (!HsInnerLayer.TryParse(innerPlain, out List<IntroductionPoint> intros))
                return null;

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
