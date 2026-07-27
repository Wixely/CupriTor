# CupriTor

**A 100% managed Tor stack for .NET.** Connect to onion services, reach the clearnet through exit relays, host v3
onion services, and run a SOCKS5 proxy — all from C#, with **no `tor.exe`, no SOCKS hop, and no OS crypto on the
critical path** (managed crypto via BouncyCastle + [CupriCurve](https://github.com/Wixely/CupriCurve)). MIT-licensed,
.NET 10.

```csharp
await using var tor = new TorClient();
await tor.StartAsync();                                   // bootstraps + verifies the consensus

using HttpClient http = tor.CreateTorHttpClient();        // a normal HttpClient, over Tor
string page = await http.GetStringAsync("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/");
```

## What it does

- **Connect to onion services** — `tor.ConnectToOnionAsync("addr.onion", port)` → a `Stream`; or a real `HttpClient`
  via `tor.CreateTorHttpClient()`. Supports **client authorization** (private onions).
- **Reach the clearnet through Tor** — `tor.ConnectAsync("example.com", 443)` routes through an **exit relay**
  (exit-policy aware, remote DNS at the exit — no local leak).
- **Host v3 onion services** — `tor.PublishOnionAsync(identity, "127.0.0.1", 8080)` reverse-proxies a local app to a
  durable `.onion` (self-healing intro points, two-period publishing), public or private.
- **SOCKS5 proxy** — `new Socks5ProxyServer(tor)` exposes a local Tor SOCKS port any app can use.
- **Host ASP.NET Core on an onion, in-process** — `builder.WebHost.UseCupriTorOnion(...)` (no loopback proxy;
  binds clearnet + onion at once). See [`CupriTor.AspNetCore`](src/CupriTor.AspNetCore).
- **Sidecar** — [`CupriTor.Host`](src/CupriTor.Host): a config-driven front door (`ClearnetOnly` / `TorOnly` / `Both`)
  for any app on a local port (IIS, Kestrel, non-.NET), plus an optional SOCKS5 port.
- **Progress reporting** — `tor.StatusChanged` drives a loading bar for the bootstrap/connect phases.

Everything is byte-exact with real Tor and **live-validated** end to end (onion client, onion service, and exit).

Built first for [CupriNet](https://github.com/Wixely/CupriNet), but the API is generic and takes no dependency on any
consumer.

## Install

Packages are published to **GitHub Packages** (`nuget.pkg.github.com/Wixely`):

| Package | Purpose |
|---|---|
| `CupriTor` | The core library (client, onion service, exit, SOCKS5, HttpClient). |
| `CupriTor.AspNetCore` | Host ASP.NET Core apps on an onion, in-process. |
| `CupriTor.Host` | The cross-platform sidecar (`dotnet tool install --global CupriTor.Host`). |

GitHub Packages requires authentication even for public packages, so a consumer needs the feed configured plus a
GitHub token with `read:packages`. Add the source to your solution's `nuget.config` — **credentials are supplied out
of band, never committed:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <add key="wixely-github" value="https://nuget.pkg.github.com/Wixely/index.json" />
  </packageSources>
</configuration>
```

Supply the token via your machine or CI (it lands in the user-level NuGet config, not the repo):

```bash
dotnet nuget add source https://nuget.pkg.github.com/Wixely/index.json \
  --name wixely-github --username <your-github-user> --password <PAT-with-read:packages> --store-password-in-clear-text
```

then reference the latest package (see [Releases](https://github.com/Wixely/CupriTor/releases) for the current version):

```xml
<PackageReference Include="CupriTor" Version="0.1.4" />
```

## More examples

```csharp
// Host an onion service that reverse-proxies a local app, with a stable address:
var identity = File.Exists("onion.key")
    ? OnionServiceKey.FromTorSecretKey(File.ReadAllBytes("onion.key"))
    : OnionServiceKey.CreateRandom();
File.WriteAllBytes("onion.key", identity.ToTorSecretKey());
await tor.PublishOnionAsync(identity, "127.0.0.1", 8080);
Console.WriteLine(identity.OnionAddress);

// Run a local SOCKS5 proxy over Tor (127.0.0.1:9050):
await using var socks = new Socks5ProxyServer(tor);
await socks.StartAsync();
//   curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/
```

Runnable versions of each are in [`samples/`](samples) (also built into standalone Windows/Ubuntu zips on each release).

## Maturity & security

CupriTor is **pre-1.0** and has **not had an independent security audit**. The onion client, onion service, and exit
paths are live-validated against the real Tor network.

> **Important:** CupriTor gives you Tor's **network-layer** anonymity, not Tor Browser's **application/browser**
> anonymity. A normal browser or default `HttpClient` sent through it is still fingerprintable at the application
> layer. See **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** and **[SECURITY.md](SECURITY.md)**.

## Build from source

Requires the .NET 10 SDK.

```bash
dotnet build CupriTor.slnx -c Release
dotnet test  CupriTor.slnx -c Release
dotnet run --project samples/TorHttpClient          # fetch over Tor
```

## Links

- [Roadmap](ROADMAP.md) · [Threat model](docs/THREAT-MODEL.md) · [Security policy](SECURITY.md) · [Samples](samples)
- [CupriCurve](https://github.com/Wixely/CupriCurve) — the managed Ed25519/Curve25519 library CupriTor builds on.

## License

MIT.
