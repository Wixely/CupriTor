namespace CupriTor;

/// <summary>
/// A phase of connecting to / using the Tor network, for progress reporting (e.g. a loading bar). The bootstrap
/// phases (fetch → verify → guards → bootstrapped) are the multi-second part worth a progress indicator.
/// </summary>
public enum TorPhase
{
    Idle,

    // Bootstrap (TorClient.StartAsync)
    FetchingConsensus,
    VerifyingConsensus,
    LoadingGuards,
    Bootstrapped,

    // Per-connection (ConnectAsync / ConnectToOnionAsync / ConnectViaExitAsync)
    BuildingCircuit,
    Connecting,
    Connected,

    /// <summary>
    /// Background connectivity to the Tor network was lost (a consensus refresh or an opt-in bootstrap retry failed)
    /// and is being re-established. Recovery is signalled by a return to <see cref="Bootstrapped"/>.
    /// </summary>
    Reconnecting,

    Failed,
}

/// <summary>
/// A point-in-time status update: the current <see cref="Phase"/>, a human-readable <see cref="Message"/>, and a
/// rough <see cref="Progress"/> from 0 to 1 (best-effort; 1.0 at Bootstrapped/Connected).
/// </summary>
public sealed record TorStatus(TorPhase Phase, string Message, double Progress);
