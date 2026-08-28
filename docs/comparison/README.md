# .NET Tor libraries — comparison

Comparison of the three projects asked about, plus **CupriTor** (this workspace) as the baseline.

Researched **2026-08-28**. Every stat below was pulled from the GitHub API, NuGet, the project READMEs, or the local
CupriTor working tree on that date — see each dossier for the source of a given claim.

## The dossiers

| File | Project |
|---|---|
| [01-torsharp.md](01-torsharp.md) | [joelverhagen/TorSharp](https://github.com/joelverhagen/TorSharp) — process supervisor around the real `tor` + Privoxy |
| [02-tor-dotnet.md](02-tor-dotnet.md) | [sharpbrowser/Tor.NET](https://github.com/sharpbrowser/Tor.NET) — control-port client for the Tor Expert Bundle |
| [03-ornet.md](03-ornet.md) | [ornet.io](https://ornet.io/) — **not a .NET library.** Consumer VPN / Tor-browser apps. See the file for what was actually found |
| [04-cupritor.md](04-cupritor.md) | CupriTor — native managed implementation of the Tor protocol |
| [05-feature-matrix.md](05-feature-matrix.md) | Full side-by-side feature matrix |

## TL;DR

The three .NET projects are not three implementations of the same thing. They sit at **three different layers**, and
only one of them actually speaks the Tor protocol:

```
          ┌──────────────────────────────────────────────────────────────┐
CupriTor  │ C# speaks the Tor protocol itself.                           │
          │ TLS link v5 → ntor → CREATE2/EXTEND2 → RELAY cells → HSv3.   │
          │ No tor binary. No localhost hop. No subprocess.              │
          └──────────────────────────────────────────────────────────────┘
          ┌──────────────────────────────────────────────────────────────┐
Tor.NET   │ C# drives the real tor.exe over its CONTROL PORT (9051).     │
          │ Circuits/streams/events are C tor's; C# issues commands.     │
          │ + its own SOCKS5 client and HTTP proxy front end.            │
          └──────────────────────────────────────────────────────────────┘
          ┌──────────────────────────────────────────────────────────────┐
TorSharp  │ C# downloads, configures and babysits tor + Privoxy as       │
          │ child processes, then hands you a localhost proxy URI.       │
          │ You then use a plain HttpClient pointed at that port.        │
          └──────────────────────────────────────────────────────────────┘
          ┌──────────────────────────────────────────────────────────────┐
OrNET     │ Not a library at all — iOS/Android consumer apps.            │
          └──────────────────────────────────────────────────────────────┘
```

## Headline table

| | **TorSharp** | **Tor.NET** | **OrNET** | **CupriTor** |
|---|---|---|---|---|
| What it is | Process manager for `tor` + Privoxy | Control-port wrapper for `tor` | Consumer VPN / browser apps | Native managed Tor client |
| Needs `tor` binary | **Yes** (auto-downloaded) | **Yes** (you supply Expert Bundle) | n/a | **No** |
| Protocol implemented in C# | No | No (control protocol only) | n/a | **Yes** |
| Onion **client** | Via the SOCKS port | Via the SOCKS port | n/a | **Native** (`ConnectToOnionAsync`) |
| Onion **service hosting** | No | No | n/a | **Yes** (v3, durable) |
| Clearnet via exit | Yes (via proxy port) | Yes (via proxy port) | n/a | **Yes** (native, exit-policy aware) |
| Stars / forks | 343 / 68 | 55 / 18 | n/a | private-adjacent (public repo, new) |
| Last code push | **2023-10-24** | **2017-05-29** | n/a | 2026-07-29 |
| License | MIT | MIT | Proprietary | MIT |
| Platforms | Windows, Linux (no macOS) | **Windows only** | iOS / Android | Anywhere .NET 10 runs |
| TFM | netstandard2.0, net462 | **.NET Framework 4.0** | n/a | net10.0 |
| On NuGet | `Knapcode.TorSharp` (155k dl) | **No package** | n/a | GitHub Packages |
| Maintained | Dormant (~3 yrs) | **Abandoned (~9 yrs)** | Actively sold | Active |

## How to choose

- **You just want `HttpClient` to come out of a Tor exit, on Windows/Linux, on an old TFM, and you don't mind
  shipping a `tor.exe` next to your app** → **TorSharp**. It is the most-used and most conventional option.
- **You want fine-grained control over circuits/streams and live Tor events, on .NET Framework, on Windows, and you
  can live with a 2017 codebase** → **Tor.NET**. Its control-port surface is genuinely richer than TorSharp's, but
  it is unmaintained and unpackaged.
- **You want a Tor SDK from ornet.io** → there isn't one. See [03-ornet.md](03-ornet.md).
- **You want no external process, no bundled C binary, onion-service *hosting*, AOT/container-friendly single-binary
  deployment, or Tor inside an environment where you cannot spawn a subprocess** → **CupriTor** is the only one of
  the four that can do it, at the cost of being the newest and least battle-tested.

## Where CupriTor leads

Things CupriTor does that **neither** TorSharp nor Tor.NET can, at any version, because of how they are built:

| | Why the wrappers can't |
|---|---|
| **Host a v3 onion service** — durable address, self-healing intro points, two-period publishing, public or private | Both are proxy *consumers*; neither publishes descriptors or runs intro points |
| **Run with no native binary and no child process** — hardened containers, sandboxes, exec-forbidden hosts | Both *are* a wrapper around a `tor` process |
| **AOT / single-file deploy** — one self-contained binary that speaks Tor | Shipping and exec'ing `tor` defeats it |
| **In-process ASP.NET Core on an onion** (`UseCupriTorOnion`), no loopback hop | Requires being the transport, not proxying to a local port |
| **macOS, and every RID .NET supports** | TorSharp: Windows+Linux. Tor.NET: Windows only |
| **Private, client-authorized onions**, client and service | Not exposed by either |
| **Vanguards-lite by default** (layer-2 guard-discovery defense, 4-hop onion circuits) | Needs the separate upstream vanguards addon; neither surfaces it |
| **No executable downloaded at runtime**, no loopback proxy port other local processes can reach | Their whole mechanism is a fetched binary plus a localhost port |
| **Safe concurrent use** (`MaxConcurrentDials`) | TorSharp is explicitly not thread-safe — one `tor` process per parallel task |
| **Diagnosable failures** — typed `TorClockSkewException`, connectivity events, retryable bootstrap, progress events | Failures surface as a dead port or a control-port string |

Full detail in [04-cupritor.md](04-cupritor.md); the complete side-by-side is in
[05-feature-matrix.md](05-feature-matrix.md).

## The honest caveat about CupriTor

TorSharp and Tor.NET both delegate the actual anonymity-critical work to the C `tor` implementation, which is
audited, is what the Tor Project ships, and inherits every upstream security fix for free. CupriTor reimplements
that work. That is what makes it capable of things the other two structurally cannot do — and it is also the risk:
a reimplementation carries its own bugs and does not inherit upstream fixes automatically. That trade-off is the
single most important line in this whole comparison and it is expanded in [04-cupritor.md](04-cupritor.md).
