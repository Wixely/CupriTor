using System.Net;
using System.Net.Sockets;

namespace CupriTor.AspNetCore;

/// <summary>
/// The Kestrel endpoint that means "listen on this onion service". Kestrel routes it to the CupriTor connection
/// transport (via <c>CanBind</c>); IP endpoints still go to the default socket transport, so clearnet and onion
/// bind side by side in one server.
/// </summary>
public sealed class CupriTorEndPoint : EndPoint
{
    public CupriTorEndPoint(CupriTorOnionOptions options) => Options = options;

    /// <summary>The onion configuration this endpoint serves.</summary>
    public CupriTorOnionOptions Options { get; }

    /// <summary>The .onion address this endpoint serves.</summary>
    public string OnionAddress => Options.Identity.OnionAddress;

    public override AddressFamily AddressFamily => AddressFamily.Unspecified;

    public override string ToString() => OnionAddress;
}
