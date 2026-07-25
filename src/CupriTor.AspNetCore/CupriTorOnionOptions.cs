using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace CupriTor.AspNetCore;

/// <summary>
/// Configures the in-process onion transport added by
/// <see cref="CupriTorOnionWebHostExtensions.UseCupriTorOnion(Microsoft.AspNetCore.Hosting.IWebHostBuilder, System.Action{CupriTorOnionOptions})"/>.
/// The onion is served by feeding each inbound Tor stream straight to Kestrel as a connection — no loopback socket.
/// </summary>
public sealed class CupriTorOnionOptions
{
    /// <summary>
    /// The onion service identity (its long-term key <b>is</b> its address). Required. Create a fresh one with
    /// <see cref="OnionServiceKey.CreateRandom"/>, restore a persistent one with
    /// <see cref="OnionServiceKey.FromTorSecretKey"/>, or import a vanity key.
    /// </summary>
    public OnionServiceKey Identity { get; set; } = null!;

    /// <summary>Number of introduction points to maintain. Tor's default is 3.</summary>
    public int IntroPoints { get; set; } = 3;

    /// <summary>
    /// x25519 public keys of authorized clients. When non-empty the onion is <b>private</b>: only these clients can
    /// fetch the descriptor and connect. Parse tor-format "descriptor:x25519:BASE32" keys with
    /// <see cref="OnionClientAuthorization.ParsePublicKey"/>.
    /// </summary>
    public IList<byte[]> AuthorizedClients { get; } = new List<byte[]>();

    /// <summary>Application protocols to serve over the onion. Defaults to HTTP/1.1 (what Tor clients speak).</summary>
    public HttpProtocols Protocols { get; set; } = HttpProtocols.Http1;

    /// <summary>
    /// Directory authorities / fallback directories used to bootstrap the shared Tor client, as "host:port".
    /// Defaults to the built-in authority list when left empty.
    /// </summary>
    public IList<string> DirectorySources { get; } = new List<string>();
}
