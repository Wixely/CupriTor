# CupriTor.Host

A cross-platform **sidecar** that exposes any local app over **Tor (onion)**, **clearnet**, or **both** —
flip one config setting to change how it's reachable, with no change to the app itself. Built on the
100%-managed CupriTor stack (no Tor daemon required).

Works with anything that listens on a local port: **Kestrel / ASP.NET Core, IIS (incl. classic ASP.NET)**,
node, PHP, etc. The app binds to loopback; the sidecar is its front door(s).

> **ASP.NET Core?** If your app is Kestrel-based you can skip the loopback hop entirely and serve the onion
> **in-process** with [`CupriTor.AspNetCore`](../CupriTor.AspNetCore) (`builder.WebHost.UseCupriTorOnion(...)`) —
> onion streams feed straight into Kestrel. Use this sidecar for everything else (IIS, non-.NET apps) or when you
> want the onion decoupled from the app process.

## The one switch

```jsonc
// appsettings.json  (or env vars / CLI)
{
  "CupriTor": {
    "Mode": "Both",                 // ClearnetOnly | TorOnly | Both  ← the switch
    "Backend": "127.0.0.1:8080",    // your app (IIS/Kestrel on loopback)
    "ClearnetBind": "0.0.0.0:80",   // public listener (Clearnet/Both)
    "Onion": {
      "IdentityMode": "Persistent", // Random | Persistent | Vanity
      "IdentityFile": "onion.key",  // tor hs_ed25519_secret_key format
      "IntroPoints": 3
    }
  }
}
```

- `ClearnetOnly` — public internet only (Tor off).
- `TorOnly` — onion only; keep the app on loopback and it's not publicly reachable.
- `Both` — served on the public internet **and** a `.onion` at the same time, same backend.
- `None` — no reverse-proxy front door (pair with SOCKS5 below for an outbound-only proxy).

Every source overrides the previous: `appsettings.json` → environment variables (`CupriTor__Mode=TorOnly`) →
command line (`--CupriTor:Mode=TorOnly`).

> **⚠️ `Both` mode is dual-bind.** Serving identical content on clearnet and an onion at once can let an observer
> link the two identities. If that matters, don't serve identical content on both. See the
> [threat model](../../docs/THREAT-MODEL.md) — and note CupriTor gives *network* anonymity, not *browser* anonymity.

## Outbound SOCKS5 proxy

Independently of `Mode`, the sidecar can run a local **SOCKS5** proxy — a managed Tor SOCKS port any app can use:

```jsonc
"Socks5": { "Enabled": true, "Bind": "127.0.0.1:9050" }
```

```bash
curl --socks5-hostname 127.0.0.1:9050 http://xxxxx.onion/     # onion service
curl --socks5-hostname 127.0.0.1:9050 https://example.com/    # clearnet, via a Tor exit
```

Onion targets are dialed through the rendezvous protocol; clearnet targets go through a Tor exit relay (the exit
does the DNS, so use `--socks5-hostname` to avoid a local lookup). Run it **alongside** a reverse proxy, or on its
own with `"Mode": "None"` for a SOCKS-only service. Keep the bind on loopback — anyone who can reach it can use the tunnel.

## Run

```bash
# .NET tool (Windows / Linux / macOS)
dotnet tool install --global CupriTor.Host
cupritor-host                                  # reads ./appsettings.json + env + args

# Windows Service / Linux systemd — auto-detected (see cupritor-host.service)
# Docker
docker build -t cupritor-host .
docker run -v cupritor-data:/data -e CupriTor__Backend=host.docker.internal:8080 cupritor-host
```

On start it prints the `.onion` address (and writes `onion.hostname` next to the key for Persistent mode).
