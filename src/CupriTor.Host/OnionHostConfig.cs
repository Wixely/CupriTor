using CupriTor;

namespace CupriTor.Host;

/// <summary>
/// Configuration for the CupriTor host sidecar. The one switch that matters is <see cref="Mode"/>: flip it
/// between clearnet, Tor, or both, and the sidecar opens the corresponding front door(s) to the same
/// <see cref="Backend"/> app — no other change required.
/// </summary>
public sealed class OnionHostConfig
{
    /// <summary>Which front door(s) to open: clearnet only, Tor onion only, or both. The central switch.</summary>
    public BindingMode Mode { get; set; } = BindingMode.Both;

    /// <summary>The local app to expose, as "host:port" (e.g. a Kestrel/IIS site bound to loopback).</summary>
    public string Backend { get; set; } = "127.0.0.1:8080";

    /// <summary>Public TCP endpoint to serve clearnet on ("host:port"), used in Clearnet/Both modes.</summary>
    public string ClearnetBind { get; set; } = "0.0.0.0:80";

    /// <summary>Onion (Tor) settings, used in Tor/Both modes.</summary>
    public OnionConfig Onion { get; set; } = new();

    /// <summary>Outbound SOCKS5 proxy settings. Independent of <see cref="Mode"/> — enable it to also run a local Tor SOCKS port.</summary>
    public Socks5Config Socks5 { get; set; } = new();

    /// <summary>Directory caches ("ip:dirport") to bootstrap the Tor consensus from. Empty ⇒ built-in authorities.</summary>
    public List<string> DirectorySources { get; set; } = new();

    public (string Host, int Port) BackendEndpoint() => Split(Backend, 8080);
    public (string Host, int Port) ClearnetEndpoint() => Split(ClearnetBind, 80);
    public (string Host, int Port) Socks5Endpoint() => Split(Socks5.Bind, 9050);

    /// <summary>True when Tor must be bootstrapped: any onion front door, or the outbound SOCKS5 proxy.</summary>
    public bool NeedsTor => Mode is BindingMode.TorOnly or BindingMode.Both || Socks5.Enabled;

    private static (string, int) Split(string value, int defaultPort)
    {
        int colon = value.LastIndexOf(':');
        return colon < 0 ? (value, defaultPort) : (value[..colon], int.Parse(value[(colon + 1)..]));
    }
}

/// <summary>The Tor onion identity + introduction settings.</summary>
public sealed class OnionConfig
{
    /// <summary>How the identity is obtained: <c>Random</c> (ephemeral), <c>Persistent</c> (create once/reuse), or <c>Vanity</c> (pre-generated).</summary>
    public OnionIdentityMode IdentityMode { get; set; } = OnionIdentityMode.Persistent;

    /// <summary>Path to the identity key file (tor <c>hs_ed25519_secret_key</c> format). Created for Persistent; must exist for Vanity.</summary>
    public string IdentityFile { get; set; } = "onion.key";

    /// <summary>Number of introduction points to maintain.</summary>
    public int IntroPoints { get; set; } = 3;

    /// <summary>Authorized client public keys (base32 x25519) for a private/authenticated onion. Empty ⇒ public onion.</summary>
    public List<string> AuthorizedClients { get; set; } = new();
}

/// <summary>Outbound SOCKS5 proxy: a local Tor SOCKS port any app can point at (like a managed <c>tor</c>).</summary>
public sealed class Socks5Config
{
    /// <summary>Run the SOCKS5 proxy. Works with any <see cref="BindingMode"/>, including <see cref="BindingMode.None"/> (SOCKS-only).</summary>
    public bool Enabled { get; set; } = false;

    /// <summary>Address to listen on ("host:port"). Defaults to loopback 127.0.0.1:9050 (Tor's conventional SOCKS port).</summary>
    public string Bind { get; set; } = "127.0.0.1:9050";
}

/// <summary>How the onion identity is sourced.</summary>
public enum OnionIdentityMode
{
    Random,      // fresh address every run
    Persistent,  // created once, reused
    Vanity,      // pre-generated key (e.g. mkp224o)
}
