using CupriTor;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  CupriTor sample — a local SOCKS5 proxy over Tor
//
//  Starts a 100%-managed Tor client (no tor.exe) and a SOCKS5 proxy on 127.0.0.1:9050. Point any
//  SOCKS5-aware app at it and its traffic rides Tor — onion targets via rendezvous, clearnet via
//  an exit relay. Loopback-bound (do not expose it: it is an unauthenticated proxy).
//
//    Then, from another terminal:
//      curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/
// ─────────────────────────────────────────────────────────────────────────────────────────────

Console.WriteLine("CupriTor sample — SOCKS5 proxy over Tor");

try
{
    await using var tor = new TorClient(); // no config needed — uses the built-in directory authorities
    tor.StatusChanged += (_, s) => Console.WriteLine($"  [{s.Progress,4:P0}] {s.Message}"); // live progress → loading bar

    Console.WriteLine("Bootstrapping Tor (fetching + verifying the consensus)…");
    await tor.StartAsync();

    await using var socks = new Socks5ProxyServer(tor);
    await socks.StartAsync();

    Console.WriteLine($"\nSOCKS5 proxy listening on {socks.ListenEndPoint}");
    Console.WriteLine($"Try:  curl --socks5-hostname {socks.ListenEndPoint} https://check.torproject.org/");
    Console.WriteLine("Press Ctrl+C to stop.\n");

    var stop = new TaskCompletionSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.TrySetResult(); };
    await stop.Task;
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine($"\nFailed: {e.GetType().Name}: {e.Message}");
    Console.Error.WriteLine("(Bootstrapping Tor needs outbound access to the directory authorities and relays.)");
    return 1;
}
