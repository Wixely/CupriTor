# Feature matrix

Verified 2026-08-28. `—` = not applicable. OrNET is included only for completeness; it is a consumer app vendor,
not a library ([03-ornet.md](03-ornet.md)).

## Architecture

| | TorSharp | Tor.NET | OrNET | CupriTor |
|---|---|---|---|---|
| Tor protocol implemented in-project | ✗ | ✗ | — | **✓** |
| Requires a native `tor` binary | ✓ (auto-downloaded) | ✓ (user supplies Expert Bundle) | — | **✗** |
| Spawns a child process | ✓ (`tor`, + Privoxy pre-.NET 6) | ✓ (`tor.exe`) | — | **✗** |
| Traffic path | app → localhost proxy → `tor` | app → localhost proxy → `tor` | — | app → managed circuit |
| Control-port / circuit steering | `NEWNYM` only | **✓ full** (build, extend, close, attach) | — | ✓ (native, in-process) |
| Live Tor events (bandwidth, circuits, streams) | ✗ | **✓** | — | ✓ (`StatusChanged`, connectivity events) |
| Can drive a *remote* Tor daemon | ✗ | **✓** (`ClientRemoteParams`) | — | — (is the daemon) |
| Managed crypto (no OS crypto on critical path) | — | — | — | **✓** (BouncyCastle + CupriCurve) |

## Capabilities

| | TorSharp | Tor.NET | OrNET | CupriTor |
|---|---|---|---|---|
| HTTP through Tor (`HttpClient`) | ✓ | ✓ | — | ✓ |
| Raw `Stream` / arbitrary TCP | via SOCKS port | **✓** (`GetStream`) | — | ✓ (`ConnectAsync`) |
| Clearnet via exit relay | ✓ | ✓ | — | ✓ (exit-policy aware, remote DNS) |
| Connect to v3 onion **client** | via SOCKS port | via SOCKS port | ✓ (in-app) | **✓ native** |
| Private / client-authorized onions | ✗ | ✗ | — | **✓** (`OnionClientAuth`) |
| **Host** a v3 onion service | ✗ | ✗ | ✗ | **✓** (durable, self-healing intro points) |
| ASP.NET Core bound to an onion in-process | ✗ | ✗ | — | **✓** (`UseCupriTorOnion`) |
| Local SOCKS5 proxy server for other apps | ✓ (it *is* `tor`'s) | ✓ (middle-man HTTP proxy) | — | **✓** (`Socks5ProxyServer`, managed) |
| Sidecar / standalone host process | ✗ | ✗ | — | **✓** (`CupriTor.Host` dotnet tool) |
| Circuit rotation / new identity | ✓ | ✓ | — | ✓ |
| Guard-discovery defense (vanguards) | ✗ (needs upstream addon) | ✗ | — | **✓** (vanguards-lite, default on) |
| Run a Tor **relay** | ✗ | ✗ | ✗ | ✗ |
| Full IPv6 reach | via `tor` | via `tor` | — | ✗ (roadmap) |

## Platform & packaging

| | TorSharp | Tor.NET | OrNET | CupriTor |
|---|---|---|---|---|
| Windows | ✓ | ✓ | ✗ | ✓ |
| Linux | ✓ | ✗ | ✗ | ✓ |
| macOS | **✗** | ✗ | ✗ | ✓ |
| iOS / Android | ✗ | ✗ | ✓ | untested |
| Target framework | netstandard2.0, net462 | **net40** | — | **net10.0** |
| .NET Framework support | **✓ (4.6.2+)** | ✓ (4.0) | — | ✗ |
| AOT / single-file friendly | ✗ | ✗ | — | **✓** (`IsAotCompatible`) |
| Works with no filesystem write of executables | ✗ | ✗ | — | **✓** |
| Public NuGet.org package | **✓** `Knapcode.TorSharp` | ✗ | — | ✗ (GitHub Packages, auth required) |
| Frictionless `dotnet add package` | **✓** | ✗ | — | ✗ (needs feed + PAT) |
| Thread-safe / concurrent use | **✗** (instance per task) | partial | — | ✓ (`MaxConcurrentDials`) |

## Project health

| | TorSharp | Tor.NET | OrNET | CupriTor |
|---|---|---|---|---|
| Stars / forks | **343 / 68** | 55 / 18 | — | new |
| Open issues | 13 | 3 | — | — |
| Last code push | 2023-10-24 | **2017-05-29** | active (apps) | 2026-07-29 |
| Latest version | 2.15.0 (2023-10-24) | untagged | rolling | v0.1.5 |
| Downloads | ~155k | n/a (no package) | — | n/a |
| Library size | ~50 files / 150 KB | 82 files / 375 KB | — | 76 files / ~8.5k lines |
| Automated tests | ✓ (`test/`, CI) | WinForms manual harness (`Tor.Tests`) | — | ✓ 173 methods + live validation |
| CI | GitHub Actions | ✗ | — | GitHub Actions |
| License | MIT | MIT | proprietary | MIT |
| Security posture | inherits audited C `tor` | inherits audited C `tor` (2017-era wrapper) | unknown | **own implementation, unaudited** |

## Decision cheat-sheet

| If you need… | Pick |
|---|---|
| HTTP over Tor, easiest possible path, mainstream | **TorSharp** |
| .NET Framework support | **TorSharp** (or Tor.NET if you must go to 4.0) |
| Circuit/stream-level control on legacy Windows | **Tor.NET** (accept the fork-and-port cost) |
| Audited upstream crypto & free security updates | **TorSharp** |
| To *host* an onion service from .NET | **CupriTor** (only option) |
| No subprocess / no native binary / AOT / restricted container | **CupriTor** (only option) |
| macOS | **CupriTor** (only option) |
| A Tor SDK from ornet.io | doesn't exist — see [03-ornet.md](03-ornet.md) |
