# CupriTor (this workspace)

> "A 100% managed Tor stack for .NET." — no `tor.exe`, no SOCKS hop, no OS crypto on the critical path.

- Repo: https://github.com/Wixely/CupriTor · License: MIT
- Included here as the **baseline** the other three are being compared against.

## Facts (from the local working tree, 2026-08-28)

| | |
|---|---|
| Latest release | v0.1.5; `main` at 0.1.6-dev (`c32d032`, 2026-07-29) |
| Target framework | `net10.0`, `IsAotCompatible=true`, nullable + warnings-as-errors |
| Library source | 65 `.cs` / ~7,860 lines (`CupriTor`) + 7 / 337 (`AspNetCore`) + 4 / 280 (`Host`) = **76 files, ~8,480 lines** |
| Tests | ~4,200 lines, 173 `[Fact]`/`[Theory]` methods |
| Runtime deps | `BouncyCastle.Cryptography` 2.4.0, `CupriCurve` 0.2.0 (+ `Microsoft.Extensions.Hosting*` for the sidecar only) |
| Native binaries | **None** |
| Distribution | GitHub Packages (`nuget.pkg.github.com/Wixely`) — `CupriTor`, `CupriTor.AspNetCore`, `CupriTor.Host` |

## What it actually is

The only one of the four that **implements the Tor protocol in C#**. The source layout tells the story —
`Protocol/TorNetwork.cs`, `Protocol/Circuit.cs`, `Protocol/CircuitCells.cs`, `Protocol/EntryGuards.cs`,
`Directory/Consensus.cs`, `OnionService/HsService.cs`, `OnionService/HsDescriptor{,Builder,Client}.cs`,
`Socks5/Socks5ProxyServer.cs`. Link handshake, ntor, CREATE2/EXTEND2, RELAY cells, consensus/microdescriptor
fetching, entry guards, and v3 hidden-service descriptors are all managed code.

```csharp
await using var tor = new TorClient();
await tor.StartAsync();
using HttpClient http = tor.CreateTorHttpClient();
string page = await http.GetStringAsync("http://…onion/");
```

## Capabilities the other two structurally cannot have

| Capability | Why TorSharp / Tor.NET can't |
|---|---|
| **Host a v3 onion service** | Both are proxy-consumers. Neither publishes descriptors or runs intro points. TorSharp has no HS support at all; Tor.NET predates v3 |
| **No subprocess / no native binary** | Both *are* a wrapper around a native `tor` process, by definition |
| **In-process ASP.NET Core on an onion** (`UseCupriTorOnion`) | Requires being the transport, not proxying to a loopback port |
| **Single-file / AOT / locked-down container deploy** | Shipping and exec'ing `tor` defeats it |
| **macOS, or any RID .NET supports** | TorSharp is Windows+Linux; Tor.NET is Windows-only |
| **Private (client-authorized) onions**, `OnionClientAuth` | Not exposed by either |
| **Vanguards-lite** (layer-2 guard-discovery defense, 4-hop onion circuits, default-on since v0.1.4) | Upstream `tor` needs the separate vanguards addon; neither wrapper surfaces it |

Also present and absent elsewhere: `TorClockSkewException` with tolerance, connectivity events, re-callable /
opt-in-retry bootstrap, exit policy p6 handling, `MaxConcurrentDials`, durable self-healing onion publishing with
two-period descriptors, and `tor.StatusChanged` progress reporting for bootstrap UI.

## The trade-off, stated plainly

This is the part that matters more than any feature table.

**TorSharp and Tor.NET delegate every anonymity-critical decision to the C `tor` implementation.** That code is
what the Tor Project ships and audits; it receives upstream security fixes, and consumers of those two libraries
inherit those fixes by re-downloading a binary. The wrapper being buggy costs you convenience, not anonymity.

**CupriTor reimplements that code.** The upside is everything in the table above. The downsides are real and
should be written down:

1. **No free upstream security fixes.** When the Tor Project patches a protocol-level issue, CupriTor must port it.
2. **A reimplementation has its own bugs**, including ones with anonymity consequences rather than merely
   functional ones — path selection, guard rotation, and side channels are exactly where subtle mistakes hide.
3. **Not independently audited.** ~8.5k lines and 173 test methods, live-validated end to end against the real
   network (onion client, onion service, exit, both UTC time windows) — which is meaningful engineering evidence,
   and is *not* the same thing as a security audit by people trying to deanonymize its users.
4. **Known gap:** full IPv6 reach is a flagged roadmap item, not built.
5. **Youngest and least-deployed** of the three by a wide margin.

The correct framing is: CupriTor is the right choice when the deployment constraint (no subprocess) or the
capability (onion hosting, in-process Kestrel) makes the other two *impossible*, and when the threat model can
absorb "newer, unaudited implementation." It is the wrong choice if your only need is "HTTP through an exit" and
you can happily run a child process — TorSharp does that with a fraction of the risk surface.

## Where CupriTor is weaker

- **TFM floor.** `net10.0` only. TorSharp reaches .NET Framework 4.6.2. Anything legacy cannot consume CupriTor.
- **Distribution friction.** GitHub Packages requires auth even for public packages, so consumers need a feed +
  PAT with `read:packages`. TorSharp is `dotnet add package Knapcode.TorSharp` and done. Publishing to nuget.org
  is already on the optional-work list and would close most of this gap.
- **Adoption / battle-testing.** 343 stars and 155k downloads of real-world use is a bug-finding machine CupriTor
  does not yet have.
- **No relay mode** (also true of the other two, but worth stating: none of these four let you *run* a relay).
