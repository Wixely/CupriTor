using CupriTor;
using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

public class TorStatusTests
{
    [Fact]
    public async Task Bootstrap_Reports_Phases_Then_Failure_When_The_Directory_Is_Unreachable()
    {
        var seen = new List<TorStatus>();
        await using var client = new TorClient(new TorClientOptions { DirectorySource = new UnreachableDirectory() });
        client.StatusChanged += (_, s) => seen.Add(s);

        Assert.Equal(TorPhase.Idle, client.CurrentStatus.Phase);

        await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());

        Assert.Contains(seen, s => s.Phase == TorPhase.FetchingConsensus); // progress was reported before the failure
        Assert.Equal(TorPhase.Failed, client.CurrentStatus.Phase);         // and the final status is Failed
    }

    private sealed class UnreachableDirectory : IDirectorySource
    {
        public Task<string> FetchConsensusAsync(CancellationToken ct = default) => Task.FromException<string>(new IOException("no network"));
        public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) => Task.FromException<string>(new IOException("no network"));
        public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default) => Task.FromResult(string.Empty);
    }
}
