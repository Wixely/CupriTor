# CupriTor roadmap

Legend: ✅ done · 🔜 planned/requested · 💤 deferred · 🔬 investigate/decide

## Requested (2026-07-25)

1. ✅ **Sample apps + cross-platform bundles** (AOT deferred). Clearly-labeled runnable samples in `samples/`:
   `OnionWebApp` (in-process onion hosting, dual-bind), `TorHttpClient` (HttpClient over Tor → onion/clearnet),
   `TorSocks5Proxy` (local SOCKS5 over Tor). `.github/workflows/samples.yml` builds each into **self-contained
   single-file** zips for **Windows** and **Ubuntu** and attaches them to releases. Still open: **NativeAOT** —
   deferred pending a BouncyCastle AOT/trim audit (the CLI samples could AOT; the ASP.NET one ships self-contained).
   Not-yet-built samples: node/relay (once #2 lands) and a connection-status/progress demo (#3).

2. 🔜 **Node / relay / client roles — explicit developer control (relay is opt-in, default OFF).**
   Support running as a **relay/node** that routes others' traffic, in addition to client + onion-service.
   **Hard rule: a client must NEVER act as a relay unless the developer explicitly enables it** — separate,
   clearly-named API; default off; no implicit/secret relaying, ever. Primitives already exist (ntor responder
   `Ntor.Respond`, relay-role crypto both directions, cell framing); gap = server-side link handshake responder,
   server TLS + relay identity/cert issuance, the circ-id-mapped forwarding engine (CREATE2 accept, EXTEND2 →
   next-hop dial + relay, DESTROY propagation), and discovery. Two flavours: public Tor relay (big + operational:
   authorities must measure/vote it in) vs **CupriNet peer-relay** (self-contained mesh, you own the trust —
   the tractable, on-mission one).

3. ✅ **Async connection / bootstrap status (for loading bars).** `TorClient.StatusChanged` event + `CurrentStatus`
   property emit a `TorStatus(TorPhase, Message, Progress 0..1)`. Bootstrap is richly instrumented (FetchingConsensus →
   VerifyingConsensus → LoadingGuards → Bootstrapped, moving %); connect is coarse (BuildingCircuit → Connecting →
   Connected). The console samples subscribe and print a live progress line. Follow-up: finer per-onion-connect phases
   (fetch-descriptor / rendezvous / introduce) would need threading a reporter into `OnionConnector`.

4. ✅ **Tor-Browser-style mitigations — decision + threat-model doc.** Written up in
   **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** + a short **SECURITY.md**, with dual-bind warnings added to the
   AspNetCore/Host READMEs. Decision: browser/content-layer mitigations are **out of scope** (no browser); the
   in-scope network-layer items are **TLS ClientHello fingerprint** (priority, for censored networks), a
   **stream-isolation policy**, and **traffic-analysis padding** — all deferred and tracked below. Headline caveat
   stated everywhere: **network-layer anonymity, not application/browser anonymity**, plus the onion↔clearnet
   dual-bind correlation warning.

5. 🔜 **Whole-system code review.**
   A comprehensive pass to surface issues across correctness, security/anonymity, concurrency, resource lifetime,
   API design, and spec-conformance. Best done as a structured multi-perspective review (per-subsystem, with
   adversarial verification of findings).

## Code review (2026-07-26)

Whole-system review done (6 parallel subsystem reviewers + verification against the code). **No crypto/trust
breaks** — consensus verification, TLS→link binding, MACs/signatures, ntor, and HS crypto all verified sound.

**High findings — FIXED:** circuit-lifetime leaks (`OrConnection` now disposes the circuits it opens; idempotent
`Circuit.DisposeAsync`; `HsService` tracks/reaps served rendezvous circuits — was an unbounded per-connection leak);
forced-final-hop path distinctness (HSDir/intro/rendezvous now kept distinct — relay + /16 — from guard+middles);
SOCKS5 handshake timeout + concurrency cap (anti-Slowloris); secure-by-default (warn on a non-loopback / open SOCKS
proxy). Family-distinctness doc corrected to not over-promise.

**Review items — FIXED (medium batches A/B/C):**
- ✅ **Relay-family distinctness** — parse the microdescriptor `family` line; mutual-family check across the fetched
  path hops; reselect on conflict (batch C).
- ✅ INTRODUCE2 replay cache; `_pendingControl` → per-command buffered channel (no dropped introductions); `_hops` → lock-free volatile snapshot.
- ✅ Bounded inbound buffering (`TorStream` + AspNetCore accept channel); capped directory HTTP reads; redirect-follow disabled; shared `HttpClient`.
- ✅ `TryParse` hardening (malformed consensus/descriptor can't crash a parser); consensus-method arg guard.
- ✅ EntryGuards locking; per-build consensus snapshot; link-cert `CertType`/`KeyType` assertion; BouncyCastle TLS cancellation; `TorClient.DisposeAsync` idempotency.
- ✅ Consensus-method floor (reject ancient consensuses); `dir-key-published` not-yet-valid authority-cert check; stale-guard pruning (count only listed guards, drop long-unlisted); clearnet front-door concurrency cap.

**Review items — deliberately deferred (low value and/or regression risk):**
- 💤 **Authenticated (v1) SENDME** — v0 works against the live network; switching without live re-validation risks breaking flow control.
- 💤 **Revision-counter rollback check** — needs cross-lookup client state; marginal value (a rollback only yields stale-but-signed intro points).
- 💤 **Secret-key zeroing** — moderate use-after-zero risk for low value (GC reclaims the buffers; defends only against heap dumps / paging).
- 💤 **Reverse-proxy full-duplex half-close** — needs `Socket.Shutdown`; a generic Stream pump can't, and `WhenAll` deadlocks HTTP (left as `WhenAny`).

## Capabilities

- 💤 **Relay/node** — see requested #2 (opt-in only).
- ✅ **Client connect to PRIVATE onions** — `ConnectToOnionAsync(onion, port, OnionClientAuth, …)` recovers the
  descriptor cookie from the client's x25519 auth key and decrypts the inner layer (0.1.6). Round-tripped offline
  against the service builder (`HsDescriptorClient.DecryptIntroPoints`); end-to-end connect to a live private onion
  is owed under "Live validation".
- 🔜 **Full IPv6 reach (priority — flagged by an integrating consumer).** Effectively IPv4-only today: the client
  connects to relays via the primary IPv4 OR address and bootstraps from IPv4 authority literals, so it **won't
  bootstrap or build circuits on an IPv6-only network** (increasingly common on mobile carriers / some cloud). Needs:
  use `ExtraOrAddresses` (IPv6) for OR connections, IPv6 directory mirrors, an IPv6/dual-stack preference option, and
  IPv6-aware relay diversity. Bigger lift. (Exit-side `p6` policy check: ✅ 0.1.5; IPv6 `RELAY_CONNECTED` /
  `RELAY_RESOLVE` still pending.)
- ✅ **Exit (clearnet) support** — done, live-validated (example.com 200, check.torproject.org 301).

## Observability / DX

- 🔜 **Connection status / progress** — requested #3. *(Connectivity drop/recovery events via `StatusChanged`
  `Reconnecting`→`Bootstrapped`, re-callable `StartAsync` + opt-in `RetryBootstrap`, and a clear `TorClockSkewException`:
  ✅ 0.1.5.)*
- ✅ **Optional concurrent-dial cap** — `TorClientOptions.MaxConcurrentDials` (default 0 = unlimited) caps in-flight
  dials; the excess wait for a free slot (bounded by the per-call timeout + cancellation) rather than exhausting
  sockets / file descriptors (0.1.6). The deeper **OR-connection multiplexing** (sharing one socket per guard across
  circuits, instead of one socket per dial) remains 💤.

## Anonymity / hardening

- 🔬 **TLS ClientHello fingerprint** — how distinguishable is our handshake from the real Tor client to a
  guard/censor? Biggest "do we stand out" question; folds into the managed-TLS validation.
- 💤 **Traffic-analysis padding** (padding-spec: connection + circuit padding machines).
- 💤 **Stream isolation** — per-destination / per-credential circuit isolation (our SOCKS is NO-AUTH today; note we
  currently build a fresh circuit per connection, which over-isolates but is unusual + slow).
- 💤 **Threat-model / SECURITY doc** — see requested #4.
- ✅ **Managed-TLS live-validated** (2026-07-26) — `BouncyCastleTlsTransport` (the library default) built a live 3-hop
  circuit + onion connect + exit connect via the collector's `--managed-tls`. The "100% managed on the critical path"
  claim is confirmed against real relays; `new TorClient()` is release-ready as-is.
- 💤 **OPE revision counter** and **intro-point rotation policy** (onion-service hardening). *(INTRODUCE2 replay cache: done.)*
- 💤 **Congestion control** (prop324 / Vegas) — legacy fixed flow-control windows today.
- 💤 **RSA cross-cert (type 2/7) anchoring**; **guard prop-271 full sampling**; **consensus fetch over a circuit**.

## Live validation owed (user runs; no Tor from the dev machine)

- 💤 Durable/private **onion soak across a 12:00-UTC boundary** (two-period + morning-window fix).
- 💤 **In-process ASP.NET Core transport** end-to-end.
- 💤 **Native `HttpClient` + SOCKS5** against a real onion.
- 💤 **Connect to a live PRIVATE onion** (0.1.6 client-auth descriptor-cookie path; crypto round-trips offline).
- ✅ **Exit path** — done, first try.

## Ops / packaging

- Grant the CI **read access to the CupriCurve GitHub Package** (or make it public) for a clean restore.
- Tag **CupriCurve 1.0** after its constant-time audit; keep CupriTor consuming it as a PackageReference.
