using CupriTor;
using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

public class TorClientTests
{
    private sealed class FakeDirectorySource(string consensus, string keys) : IDirectorySource
    {
        public Task<string> FetchConsensusAsync(CancellationToken ct = default) => Task.FromResult(consensus);
        public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) => Task.FromResult(keys);
        public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default) => Task.FromResult("");
    }

    [Fact]
    public async Task StartAsync_Without_DirectorySource_Throws()
    {
        var client = new TorClient();
        await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());
        Assert.False(client.IsBootstrapped);
    }

    [Fact]
    public async Task StartAsync_With_Unparseable_Consensus_Throws()
    {
        var client = new TorClient(new TorClientOptions
        {
            DirectorySource = new FakeDirectorySource("not a consensus", ""),
        });
        var ex = await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());
        Assert.Contains("consensus", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(client.IsBootstrapped);
    }

    [Fact]
    public async Task BuildCircuit_Before_Bootstrap_Throws()
    {
        var client = new TorClient();
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.BuildCircuitAsync());
    }

    [Fact]
    public void Options_Have_Managed_Defaults()
    {
        var options = new TorClientOptions();
        Assert.IsType<CupriTor.Transport.BouncyCastleTlsTransport>(options.Transport);
        Assert.IsType<CupriTor.Protocol.InMemoryStateStore>(options.StateStore);
        Assert.Equal(3, options.DefaultCircuitLength);
    }

    [Fact]
    public void HttpDirectorySource_Requires_An_Endpoint()
    {
        Assert.Throws<ArgumentException>(() => new HttpDirectorySource(Array.Empty<string>()));
    }
}
