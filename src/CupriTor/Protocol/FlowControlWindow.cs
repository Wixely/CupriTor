namespace CupriTor.Protocol;

/// <summary>
/// Legacy Tor flow-control windows (tor-spec §7.3). A package window bounds how many RELAY_DATA cells
/// we may send before the peer acknowledges them with a SENDME; a deliver window tracks how many we
/// have received and signals when to send a SENDME back. Used at both circuit (1000/100) and stream
/// (500/50) scope.
/// </summary>
internal sealed class FlowControlWindow
{
    private readonly int _start;
    private readonly int _increment;

    public int PackageWindow { get; private set; }
    public int DeliverWindow { get; private set; }

    public FlowControlWindow(int start, int increment)
    {
        _start = start;
        _increment = increment;
        PackageWindow = start;
        DeliverWindow = start;
    }

    public static FlowControlWindow Circuit() => new(1000, 100);
    public static FlowControlWindow Stream() => new(500, 50);

    /// <summary>True if we are currently allowed to send a data cell.</summary>
    public bool CanPackage => PackageWindow > 0;

    /// <summary>Account for sending a data cell; returns false (without decrementing) if the window is exhausted.</summary>
    public bool TryPackage()
    {
        if (PackageWindow <= 0) return false;
        PackageWindow--;
        return true;
    }

    /// <summary>A SENDME arrived from the peer: we may send another increment of data cells.</summary>
    public void OnSendmeReceived() => PackageWindow += _increment;

    /// <summary>
    /// Account for receiving a data cell. Returns true when the caller should send a SENDME to the peer
    /// (the deliver window is replenished in that case).
    /// </summary>
    public bool OnDeliver()
    {
        DeliverWindow--;
        if (DeliverWindow <= _start - _increment)
        {
            DeliverWindow += _increment;
            return true;
        }
        return false;
    }
}
