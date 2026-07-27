using CupriTor;
using CupriTor.Directory;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class OnionOnlyAndStateStoreTests
{
    private sealed class FakeDirectorySource(string consensus, string keys) : IDirectorySource
    {
        public Task<string> FetchConsensusAsync(CancellationToken ct = default) => Task.FromResult(consensus);
        public Task<string> FetchAuthorityKeysAsync(CancellationToken ct = default) => Task.FromResult(keys);
        public Task<string> FetchMicrodescriptorsAsync(IReadOnlyList<string> base64Digests, CancellationToken ct = default) => Task.FromResult("");
    }

    [Fact]
    public async Task ConnectToOnion_With_Malformed_Address_Throws_InvalidOnionAddress()
    {
        var client = new TorClient();
        var ex = await Assert.ThrowsAsync<InvalidOnionAddressException>(() => client.ConnectToOnionAsync("definitely-not-an-onion", 80));
        Assert.IsAssignableFrom<ArgumentException>(ex); // still catchable as ArgumentException for existing handlers
        Assert.Equal("definitely-not-an-onion", ex.Onion);
    }

    [Fact]
    public async Task OnionOnly_Blocks_Clearnet_Dials()
    {
        var client = new TorClient(new TorClientOptions { OnionOnly = true });

        var ex = await Assert.ThrowsAsync<ClearnetBlockedException>(() => client.ConnectAsync("example.com", 80));
        Assert.Equal("example.com", ex.Host);

        // Directly too, and before any network work (the client isn't even started).
        await Assert.ThrowsAsync<ClearnetBlockedException>(() => client.ConnectViaExitAsync("1.1.1.1", 443));
    }

    [Fact]
    public async Task OnionOnly_Does_Not_Block_Onion_Dials()
    {
        var client = new TorClient(new TorClientOptions { OnionOnly = true });
        string onion = OnionServiceKey.CreateRandom().OnionAddress; // a valid v3 .onion

        // Routed to the onion path (not blocked): fails only because the client isn't bootstrapped. ThrowsAsync is an
        // exact-type match, so this passing proves it is NOT the (derived) ClearnetBlockedException.
        await Assert.ThrowsAsync<InvalidOperationException>(() => client.ConnectAsync(onion, 80));
    }

    [Fact]
    public async Task RequirePersistentState_Refuses_The_InMemory_Default()
    {
        var client = new TorClient(new TorClientOptions { RequirePersistentState = true });
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => client.StartAsync());
        Assert.Contains("persistent", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RequirePersistentState_Is_Satisfied_By_FileStateStore()
    {
        string dir = NewTempDir();
        try
        {
            var client = new TorClient(new TorClientOptions
            {
                RequirePersistentState = true,
                StateStore = new FileStateStore(dir),
                DirectorySource = new FakeDirectorySource("not a consensus", ""),
            });
            // Gets past the persistent-state gate, then fails parsing the consensus — proving the gate accepted the store.
            await Assert.ThrowsAsync<TorBootstrapException>(() => client.StartAsync());
        }
        finally { System.IO.Directory.Delete(dir, recursive: true); }
    }

    [Fact]
    public void FileStateStore_Roundtrips_And_Persists()
    {
        string dir = NewTempDir();
        try
        {
            var store = new FileStateStore(dir);
            Assert.Null(store.Read("entry-guards"));

            store.Write("entry-guards", new byte[] { 1, 2, 3 });
            Assert.Equal(new byte[] { 1, 2, 3 }, store.Read("entry-guards"));

            store.Write("entry-guards", new byte[] { 9 }); // atomic overwrite
            Assert.Equal(new byte[] { 9 }, store.Read("entry-guards"));

            // A fresh instance over the same directory sees the persisted value (survives "restart").
            Assert.Equal(new byte[] { 9 }, new FileStateStore(dir).Read("entry-guards"));
        }
        finally { System.IO.Directory.Delete(dir, recursive: true); }
    }

    private static string NewTempDir()
    {
        string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cupritor-test-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(dir);
        return dir;
    }
}
