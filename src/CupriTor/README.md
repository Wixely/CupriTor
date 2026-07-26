# CupriTor

A **100% managed** Tor client and v3 onion-service library for .NET — no `tor.exe`, no OS crypto on the critical path.

```csharp
await using var tor = new TorClient();
await tor.StartAsync();

// Reach a .onion (or clearnet via an exit) with a normal HttpClient:
using HttpClient http = tor.CreateTorHttpClient();
string page = await http.GetStringAsync("http://xxxxx.onion/");

// Or dial any TCP port and get a Stream:
await using Stream s = await tor.ConnectAsync("xxxxx.onion", 9735);

// Host a v3 onion service that reverse-proxies a local app:
var id = OnionServiceKey.CreateRandom();
await tor.PublishOnionAsync(id, "127.0.0.1", 8080);
Console.WriteLine(id.OnionAddress);

// Run a local SOCKS5 proxy over Tor:
await using var socks = new Socks5ProxyServer(tor);
await socks.StartAsync(); // 127.0.0.1:9050
```

Connect to onion services (incl. private/client-authorized), reach the clearnet through **exit relays**, host durable
v3 onion services, and run a SOCKS5 proxy — with a verified consensus, family/​/16 path diversity, and persistent
guards. Companion packages: **CupriTor.AspNetCore** (host ASP.NET Core on an onion in-process) and **CupriTor.Host**
(cross-platform sidecar).

> CupriTor provides Tor's **network-layer** anonymity, not Tor Browser's **application/browser** anonymity. Pre-1.0;
> not independently audited. See the [repository](https://github.com/Wixely/CupriTor) for the threat model and roadmap.

MIT-licensed.
