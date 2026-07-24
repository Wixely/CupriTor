namespace CupriTor.Directory;

/// <summary>
/// Source of raw directory documents for bootstrapping a client: the microdescriptor consensus, the
/// authority key certificates (to verify it), and microdescriptors by digest (for per-hop ntor keys).
/// Returns raw document text; parsing and verification are done by the client. This is the seam that
/// lets bootstrap traffic go over plain directory ports today and over a circuit later.
/// </summary>
public interface IDirectorySource
{
    Task<string> FetchConsensusAsync(CancellationToken ct = default);
    Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default);

    /// <summary>Fetch concatenated microdescriptors for the given base64 (unpadded) SHA-256 digests.</summary>
    Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default);
}

/// <summary>
/// An <see cref="IDirectorySource"/> that fetches over HTTP from one or more directory caches
/// ("host:dirport"), trying each in turn until one answers. Suitable for the initial consensus fetch;
/// the documents it returns are still cryptographically verified by the client, so a compromised cache
/// cannot forge a consensus.
/// </summary>
public sealed class HttpDirectorySource : IDirectorySource
{
    private readonly IReadOnlyList<string> _endpoints;
    private readonly TimeSpan _timeout;

    public HttpDirectorySource(IReadOnlyList<string> dirCacheEndpoints, TimeSpan? timeout = null)
    {
        if (dirCacheEndpoints.Count == 0) throw new ArgumentException("At least one directory endpoint is required.", nameof(dirCacheEndpoints));
        _endpoints = dirCacheEndpoints;
        _timeout = timeout ?? TimeSpan.FromSeconds(30);
    }

    public Task<string> FetchConsensusAsync(CancellationToken ct = default) =>
        GetWithFailoverAsync("/tor/status-vote/current/consensus-microdesc", ct);

    public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) =>
        GetWithFailoverAsync("/tor/keys/all", ct);

    public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default)
    {
        if (base64Digests.Count == 0) return Task.FromResult(string.Empty);
        return GetWithFailoverAsync($"/tor/micro/d/{string.Join('-', base64Digests)}", ct);
    }

    private async Task<string> GetWithFailoverAsync(string path, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = _timeout };
        http.DefaultRequestHeaders.Add("User-Agent", "CupriTor/0.1");

        Exception? last = null;
        foreach (string endpoint in _endpoints)
        {
            try { return await http.GetStringAsync($"http://{endpoint}{path}", ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { last = e; }
        }
        throw new InvalidOperationException($"All directory endpoints failed for {path}.", last);
    }
}
