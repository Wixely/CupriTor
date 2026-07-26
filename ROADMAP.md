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

3. 🔜 **Async connection / bootstrap status (for loading bars).**
   An observable status stream so a UI can render progress for every element of connecting: bootstrap phases
   (fetching consensus → verifying signatures → priming guards → building circuit hop k/n → ready) and per-connect
   phases (onion: fetch descriptor → rendezvous → introduce → stream; exit: select exit → build → begin → stream).
   Shape: a structured `TorStatus`/progress model surfaced via `IProgress<T>` / event / `IAsyncEnumerable<T>`.

4. 🔬 **Tor-Browser-style mitigations — decide scope.**
   Most Tor Browser hardening is **browser/content-layer** (canvas, WebGL, fonts, UA, screen size, timezone) and
   does **not** apply to a library — there's no DOM/device. What *does* apply is network/protocol fingerprinting
   (see Anonymity/hardening below). Deliverable: a decision + a threat-model doc stating clearly that CupriTor
   provides **network-layer anonymity, not application/browser anonymity** (so integrators don't get a false sense
   of security), plus the dual-bind onion↔clearnet correlation warning.

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
- 💤 **Client connect to PRIVATE onions** — authorized-client auth on the connect path. Cookie-recovery logic
  already exists in a test; not wired into `ConnectToOnionAsync`.
- 💤 **IPv6 exit** (`p6` policy + IPv6 `RELAY_CONNECTED`) and **`RELAY_RESOLVE`** (DNS-only). IPv4 clearnet works.
- ✅ **Exit (clearnet) support** — done, live-validated (example.com 200, check.torproject.org 301).

## Observability / DX

- 🔜 **Connection status / progress** — requested #3.

## Anonymity / hardening

- 🔬 **TLS ClientHello fingerprint** — how distinguishable is our handshake from the real Tor client to a
  guard/censor? Biggest "do we stand out" question; folds into the managed-TLS validation.
- 💤 **Traffic-analysis padding** (padding-spec: connection + circuit padding machines).
- 💤 **Stream isolation** — per-destination / per-credential circuit isolation (our SOCKS is NO-AUTH today; note we
  currently build a fresh circuit per connection, which over-isolates but is unusual + slow).
- 💤 **Threat-model / SECURITY doc** — see requested #4.
- 💤 **OPE revision counter**, **INTRODUCE2 replay cache**, **intro-point rotation policy** (onion-service hardening).
- 💤 **Congestion control** (prop324 / Vegas) — legacy fixed flow-control windows today.
- 💤 **Managed-TLS live test** — `BouncyCastleTlsTransport` has never been exercised live (live runs used OS SslStream);
  a `--managed-tls` toggle to validate the 100%-managed path.
- 💤 **RSA cross-cert (type 2/7) anchoring**; **guard prop-271 full sampling**; **consensus fetch over a circuit**.

## Live validation owed (user runs; no Tor from the dev machine)

- 💤 Durable/private **onion soak across a 12:00-UTC boundary** (two-period + morning-window fix).
- 💤 **In-process ASP.NET Core transport** end-to-end.
- 💤 **Native `HttpClient` + SOCKS5** against a real onion.
- ✅ **Exit path** — done, first try.

## Ops / packaging

- Grant the CI **read access to the CupriCurve GitHub Package** (or make it public) for a clean restore.
- Tag **CupriCurve 1.0** after its constant-time audit; keep CupriTor consuming it as a PackageReference.
