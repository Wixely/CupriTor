using CupriTor;

// ─────────────────────────────────────────────────────────────────────────────────────────────
//  CupriTor sample — fetch over Tor with HttpClient
//
//  Bootstraps a 100%-managed Tor client (no tor.exe) and fetches a URL over Tor. Onion URLs go
//  through the v3 rendezvous protocol; clearnet URLs go out through a Tor exit relay.
//
//    Usage:  cupritor-httpclient-sample [url]
//    Default: the DuckDuckGo onion service.
// ─────────────────────────────────────────────────────────────────────────────────────────────

string url = args.Length > 0
    ? args[0]
    : "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/";

Console.WriteLine("CupriTor sample — HttpClient over Tor");
Console.WriteLine($"Target: {url}\n");

try
{
    await using var tor = new TorClient(); // no config needed — uses the built-in directory authorities
    tor.StatusChanged += (_, s) => Console.WriteLine($"  [{s.Progress,4:P0}] {s.Message}"); // live progress → loading bar

    Console.WriteLine("Bootstrapping Tor (fetching + verifying the consensus)…");
    await tor.StartAsync();
    Console.WriteLine("Bootstrapped. Fetching over Tor…\n");

    using HttpClient http = tor.CreateTorHttpClient();
    http.Timeout = TimeSpan.FromMinutes(2);

    HttpResponseMessage response = await http.GetAsync(url);
    string body = await response.Content.ReadAsStringAsync();

    Console.WriteLine($"HTTP {(int)response.StatusCode} {response.ReasonPhrase} — {body.Length} bytes\n");
    Console.WriteLine(body.Length > 800 ? body[..800] + "\n… (truncated)" : body);
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine($"\nFailed: {e.GetType().Name}: {e.Message}");
    Console.Error.WriteLine("(Bootstrapping Tor needs outbound access to the directory authorities and relays.)");
    return 1;
}
