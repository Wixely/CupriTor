# Tor.NET (sharpbrowser/Tor.NET)

> "A managed library to use the Tor network for SOCKS5 communications."

- Repo: https://github.com/sharpbrowser/Tor.NET
- Original author: **Chris Copeland**, first published as a CodeProject article
  ("Tor.NET — A managed Tor network library"); `sharpbrowser` republished it to GitHub in 2016.
- License: MIT (`Copyright (c) 2016 sharpbrowser`)

## Facts (verified 2026-08-28)

| | |
|---|---|
| Stars / forks | 55 / 18 |
| Open issues | 3 |
| Default branch | `master` |
| Last code push | **2017-05-29** (~9 years stale) |
| Commits on master | 6 |
| NuGet package | **None.** No package under the `sharpbrowser` owner; you consume it as source or a project reference |
| Target framework | **.NET Framework 4.0** (`<TargetFrameworkVersion>v4.0`) — not .NET Standard, not .NET Core |
| Library source | 82 `.cs` files, ~375 KB under `src/Tor/` |
| OS support | **Windows only** — README states Vista / 7 / 8 / 10, may need elevation on Vista+ |
| External requirement | **Tor Expert Bundle**, downloaded separately by the user; the repo vendors `libeay32.dll`, `libevent*.dll`, `ssleay32.dll`, `zlib1.dll` and `geoip` files in its test project |

## What it actually is

A **control-port client**. Like TorSharp it does not implement the Tor protocol — but it sits one layer *higher* on
the control side and one layer *lower* on the data side:

- It launches (or attaches to) an external `tor.exe` and opens a persistent connection to the **control port**
  (default 9051).
- It keeps that connection open to receive **live asynchronous events** — circuit build/status changes, stream
  activity, connection state, bandwidth counters.
- It exposes a **SOCKS5 client of its own** via `GetStream()`, so you get a raw `Stream` to an arbitrary host
  rather than only an HTTP proxy port.
- It can also stand up a **middle-man HTTP proxy** for code that only knows how to speak to an HTTP proxy.

### API surface

The entry point is `Client`, which exposes four sub-objects:

| Member | Purpose |
|---|---|
| `Client.Controller` | Create / extend / close circuits, attach streams, `NEWNYM`, clear the DNS cache |
| `Client.Status` | Events + queries for service state, bandwidth, circuits, connections, streams |
| `Client.Proxy` | HTTP operations through the managed proxy |
| `Client.GetStream(host, port)` | SOCKS5 socket-style connection |
| Router registry | Enumerate the routers/relays `tor` currently knows about |

The source tree is organised the way that surface implies — `src/Tor/Circuits/`, `Configuration/`, plus
`Client.cs`, `ClientCreateParams.cs`, `ClientRemoteParams.cs`. The `ClientRemoteParams` type means it can also
attach to a **remote** Tor instance's control port, not just a locally-spawned one.

## Strengths

- **Richest control surface of the two wrapper libraries.** TorSharp gives you a port and `NEWNYM`. Tor.NET gives
  you circuit construction, stream attachment, router enumeration, and an event stream. If your problem is
  "I need to know *which* relays my traffic is on, and steer it", this is the only one of the two that answers it.
- Raw `Stream` access (SOCKS5) rather than HTTP-only — usable for non-HTTP protocols.
- Can drive a **remote** Tor daemon over its control port.
- Real Tor does the anonymity work, so the same "audited C implementation" argument as TorSharp applies.
- MIT, self-contained, easy to read.

## Weaknesses / constraints

- **Effectively abandoned.** Last push 2017-05-29. Six commits total. For a library that talks to a protocol the
  Tor Project actively evolves, nine years of drift is the headline risk: control-protocol replies, `torrc`
  options, and the Expert Bundle layout have all moved since.
- **.NET Framework 4.0 only.** No .NET Standard, no .NET Core, no .NET 5+. Consuming it from a modern .NET app
  means retargeting the source yourself. This is the single largest practical blocker.
- **Windows only**, and the README's OS list stops at Windows 10.
- **Not on NuGet.** No package, no versioning, no restore story — vendoring source is the only path.
- **No onion-service hosting**, and no v3 onion support in any first-class form (v3 onions post-date the last
  commit; v2 onions were removed from the network entirely in 2021, so anything v2-shaped in here is dead code).
- User must obtain and place the Tor Expert Bundle themselves — no fetcher, unlike TorSharp.

## Note on derivatives

There is a NuGet package **`Tor4NET`** (1.3.1, ~8,900 downloads, "an all-in-one solution to fulfill your .NET dark
web needs") which appears to be a descendant of this codebase and is packaged, unlike the original. Not researched
in depth here — flagging it because if the Tor.NET *API shape* is what appeals, that may be a more consumable
route than vendoring a 2017 .NET 4.0 project. **Unverified** — confirm provenance and TFM before relying on it.

## Verdict

Interesting for its control-port API, which is more capable than TorSharp's, and worth reading if you ever want to
model circuit control in a modern library. But as a dependency in 2026 it is not viable without a fork-and-port:
.NET Framework 4.0, Windows-only, unpackaged, and untouched since 2017.
