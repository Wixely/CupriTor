using CupriTor;
using CupriTor.Directory;

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

// Directory-authority DirPorts used only to bootstrap the (cryptographically verified) consensus.
string[] directoryCaches =
{
    "128.31.0.39:9131", "86.59.21.38:80", "45.66.33.45:80", "131.188.40.189:80",
    "193.23.244.244:80", "171.25.193.9:443", "199.58.81.140:80", "204.13.164.118:80",
};

Console.WriteLine("CupriTor sample — HttpClient over Tor");
Console.WriteLine($"Target: {url}\n");

try
{
    await using var tor = new TorClient(new TorClientOptions { DirectorySource = new HttpDirectorySource(directoryCaches) });

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
