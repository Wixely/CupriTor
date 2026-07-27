using CupriTor.Protocol;

namespace CupriTor.Directory;

/// <summary>
/// An <see cref="IDirectorySource"/> that fetches directory documents over a Tor circuit (BEGIN_DIR to a V2Dir
/// cache) instead of over clearnet, falling back to <c>fallback</c> if the over-circuit fetch fails (e.g. the
/// microdescriptor cache is too cold to build a circuit yet). Used for consensus refreshes after bootstrap so an
/// on-path observer stops seeing "this IP fetches Tor directory documents" on every refresh.
/// </summary>
internal sealed class CircuitDirectorySource(TorNetwork network, IDirectorySource fallback) : IDirectorySource
{
    public Task<string> FetchConsensusAsync(CancellationToken ct = default) =>
        GetOrFallbackAsync("/tor/status-vote/current/consensus-microdesc", () => fallback.FetchConsensusAsync(ct), ct);

    public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) =>
        GetOrFallbackAsync("/tor/keys/all", () => fallback.FetchAuthorityKeysAsync(ct), ct);

    public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default) =>
        base64Digests.Count == 0
            ? Task.FromResult(string.Empty)
            : GetOrFallbackAsync($"/tor/micro/d/{string.Join('-', base64Digests)}", () => fallback.FetchMicrodescriptorsAsync(base64Digests, ct), ct);

    private async Task<string> GetOrFallbackAsync(string path, Func<Task<string>> fallbackFetch, CancellationToken ct)
    {
        try { return await network.DirectoryGetOverCircuitAsync(path, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch { return await fallbackFetch().ConfigureAwait(false); }
    }
}
