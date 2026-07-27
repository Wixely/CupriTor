using CupriTor;
using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

public class HardeningTests
{
    private sealed class FakeDirectorySource(string consensus, string keys) : IDirectorySource
    {
        public Task<string> FetchConsensusAsync(CancellationToken ct = default) => Task.FromResult(consensus);
        public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) => Task.FromResult(keys);
        public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> d, CancellationToken ct = default) => Task.FromResult("");
    }

    [Fact]
    public void TorClockSkewException_Is_A_TorBootstrapException_Carrying_The_Times()
    {
        var now = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var va = new DateTimeOffset(2026, 7, 27, 0, 0, 0, TimeSpan.Zero);
        var vu = va.AddHours(3);

        var ex = new TorClockSkewException(now, va, vu);

        Assert.IsAssignableFrom<TorBootstrapException>(ex); // existing catch (TorBootstrapException) still works
        Assert.Equal(now, ex.LocalTime);
        Assert.Equal(va, ex.ConsensusValidAfter);
        Assert.Equal(vu, ex.ConsensusValidUntil);
    }

    [Fact]
    public async Task StartAsync_Is_Recallable_After_A_Failure()
    {
        var client = new TorClient(new TorClientOptions { DirectorySource = new FakeDirectorySource("not a consensus", "") });

        // First call fails fast on the unparseable consensus...
        await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());
        Assert.False(client.IsBootstrapped);

        // ...and StartAsync is idempotent/re-callable — it retries rather than wedging.
        await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());
    }

    [Fact]
    public async Task RetryBootstrap_Loops_And_Reports_Reconnecting_Until_Cancelled()
    {
        bool sawReconnecting = false;
        var client = new TorClient(new TorClientOptions
        {
            DirectorySource = new FakeDirectorySource("not a consensus", ""),
            RetryBootstrap = true,
        });
        client.StatusChanged += (_, s) => { if (s.Phase == TorPhase.Reconnecting) sawReconnecting = true; };

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        // With RetryBootstrap, a failing bootstrap loops (emitting Reconnecting) instead of throwing — until ct fires.
        await Assert.ThrowsAsync<TaskCanceledException>(() => client.StartAsync(cts.Token));
        Assert.True(sawReconnecting);
    }

    [Fact]
    public void Microdescriptor_Parses_Separate_IPv4_And_IPv6_Exit_Policies()
    {
        string ntor = Convert.ToBase64String(new byte[32]);
        // IPv4 rejects everything; IPv6 accepts 443 — so the p6 line must be honoured independently.
        string md = $"ntor-onion-key {ntor}\np reject 1-65535\np6 accept 443\n";

        Assert.True(Microdescriptor.TryParse(md, out Microdescriptor parsed));
        Assert.False(parsed.ExitPolicyIPv4.Allows(443));
        Assert.True(parsed.ExitPolicyIPv6.Allows(443));
    }
}
