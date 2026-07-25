using CupriTor.OnionService;

namespace CupriTor;

/// <summary>
/// A running v3 onion service. Returned by <see cref="TorClient.PublishOnionAsync"/>. It keeps its
/// introduction points healthy (replacing dead ones) and re-publishes its descriptor automatically for as
/// long as it is alive. Dispose it to stop hosting and tear down all its circuits.
/// </summary>
public sealed class OnionServiceHost : IAsyncDisposable
{
    private readonly HsService _service;

    /// <summary>The .onion address this service is reachable at.</summary>
    public string OnionAddress { get; }

    internal OnionServiceHost(string onionAddress, HsService service)
    {
        OnionAddress = onionAddress;
        _service = service;
    }

    /// <summary>Stop hosting: cancel the supervisor + accept loops and tear down every introduction circuit.</summary>
    public ValueTask DisposeAsync() => _service.StopAsync();
}
