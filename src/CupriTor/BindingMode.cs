namespace CupriTor;

/// <summary>
/// How an application is exposed to the network. The central config switch: flip it to move an app between
/// the public internet, Tor, or both — without any other code change. Consumed by the CupriTor host sidecar
/// (which front doors it opens) and, later, by the in-process Kestrel transport (which listeners it adds).
/// </summary>
public enum BindingMode
{
    /// <summary>Serve on the public internet only (Tor disabled).</summary>
    ClearnetOnly,

    /// <summary>Serve over a Tor onion address only (no public clearnet exposure).</summary>
    TorOnly,

    /// <summary>Serve on both the public internet and a Tor onion address simultaneously.</summary>
    Both,

    /// <summary>No reverse-proxy front door (e.g. the sidecar runs only its outbound SOCKS5 proxy).</summary>
    None,
}
