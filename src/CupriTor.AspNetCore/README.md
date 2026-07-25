# CupriTor.AspNetCore

Host any **ASP.NET Core (Kestrel)** app directly on a Tor v3 onion service — **in-process, no loopback proxy**.
Inbound onion streams are fed straight to Kestrel as connections, so your middleware, routing, auth, DI, and
`HttpContext` all work exactly as they do on clearnet. Clearnet and onion bind **side by side** in one server.

Built on CupriTor: a 100% managed, MIT-licensed Tor stack (no `tor.exe`, no SOCKS hop, no OS crypto on the path).

## How it differs from the sidecar

| | `CupriTor.Host` (sidecar) | `CupriTor.AspNetCore` (in-process) |
|---|---|---|
| Integration | Reverse proxy over loopback | Onion stream → Kestrel connection directly |
| Extra hop | One loopback TCP connection | **None** |
| Client IP | Loopback (`127.0.0.1`) | No socket; `Connection.LocalIpAddress` is `null` |
| Backend | Any app (IIS, Kestrel, …) | Your ASP.NET Core app itself |
| Config switch | `Mode: ClearnetOnly \| TorOnly \| Both` | Additive: onion + whatever clearnet URLs you bind |

## Usage

```csharp
using CupriTor;
using CupriTor.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Stable address across restarts: persist the key (or drop in a tor hs_ed25519_secret_key / vanity key).
const string keyPath = "hs_ed25519_secret_key";
OnionServiceKey identity = File.Exists(keyPath)
    ? OnionServiceKey.FromTorSecretKey(File.ReadAllBytes(keyPath))
    : OnionServiceKey.CreateRandom();
File.WriteAllBytes(keyPath, identity.ToTorSecretKey());

builder.WebHost.UseCupriTorOnion(o => o.Identity = identity);   // in-process onion transport

var app = builder.Build();
app.MapGet("/", () => $"Hello from {identity.OnionAddress} — served in-process by Kestrel over Tor.");
app.Run();
```

- **Dual-bind (clearnet + onion):** just keep your normal clearnet config (`ASPNETCORE_URLS`, `--urls`,
  `UseUrls`, Kestrel `Listen`). The onion is additive — both serve the same pipeline at once.
- **Onion only:** configure no clearnet URLs.

## Private onions (client authorization)

Only holders of an authorized key can resolve or connect:

```csharp
builder.WebHost.UseCupriTorOnion(o =>
{
    o.Identity = identity;
    o.AuthorizedClients.Add(OnionClientAuthorization.ParsePublicKey("descriptor:x25519:BASE32PUBKEY"));
});
```

Generate a client keypair with `OnionClientAuthorization.GenerateClientKeyPair()` (tor-format, interoperable with
Tor Browser's `onion-auth`).

## Options (`CupriTorOnionOptions`)

| Property | Default | Notes |
|---|---|---|
| `Identity` | — (required) | The onion key = the address. |
| `IntroPoints` | `3` | Introduction points to maintain. |
| `AuthorizedClients` | empty (public) | Non-empty ⇒ private onion. |
| `Protocols` | `Http1` | Tor clients speak HTTP/1.1; set `Http1AndHttp2` for h2c/gRPC. |
| `DirectorySources` | built-in authorities | `host:port` bootstrap dirs. |

## Notes

- **Plaintext by design.** Serve HTTP (not HTTPS) on the onion endpoint — Tor already encrypts and authenticates
  the connection to your onion key. Don't call `UseHttps` on it.
- **Startup is non-blocking.** Publishing (bootstrap → intro points → descriptor) runs in the background, so it
  never delays your clearnet endpoints; the onion simply starts accepting once its descriptor is live. It then
  self-heals (replacing dead intro points, re-publishing) for as long as the app runs.
- **Cross-platform.** Windows, Linux, macOS, containers — it's the same managed transport everywhere.

See [`samples/OnionWebApp`](../../samples/OnionWebApp) for a runnable dual-bound app.
