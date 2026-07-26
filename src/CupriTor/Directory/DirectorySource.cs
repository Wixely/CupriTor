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
    private readonly HttpClient _http;

    public HttpDirectorySource(IReadOnlyList<string> dirCacheEndpoints, TimeSpan? timeout = null)
    {
        if (dirCacheEndpoints.Count == 0) throw new ArgumentException("At least one directory endpoint is required.", nameof(dirCacheEndpoints));
        _endpoints = dirCacheEndpoints;
        // One shared client. No redirects — a hostile cache must not steer the fetch elsewhere. Cap the response
        // size so a hostile cache can't OOM us before the document is even verified (real consensus ≈ a few MB).
        _http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = 48 * 1024 * 1024,
        };
        _http.DefaultRequestHeaders.Add("User-Agent", "CupriTor/0.1");
    }

    /// <summary>
    /// Directory-authority DirPorts used to bootstrap when no source is configured (<see cref="CreateDefault"/>).
    /// Public information; these can change over time — override with your own list if needed.
    /// </summary>
    public static IReadOnlyList<string> DefaultDirectoryCaches { get; } = new[]
    {
        "128.31.0.39:9131", "86.59.21.38:80", "45.66.33.45:80", "131.188.40.189:80",
        "193.23.244.244:80", "171.25.193.9:443", "199.58.81.140:80", "204.13.164.118:80",
    };

    /// <summary>An <see cref="HttpDirectorySource"/> over the built-in <see cref="DefaultDirectoryCaches"/>.</summary>
    public static HttpDirectorySource CreateDefault(TimeSpan? timeout = null) => new(DefaultDirectoryCaches, timeout);

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
        Exception? last = null;
        foreach (string endpoint in _endpoints)
        {
            try { return await _http.GetStringAsync($"http://{endpoint}{path}", ct).ConfigureAwait(false); }
            catch (Exception e) when (e is not OperationCanceledException) { last = e; }
        }
        throw new InvalidOperationException($"All directory endpoints failed for {path}.", last);
    }
}
