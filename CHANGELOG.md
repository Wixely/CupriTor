# Changelog

All notable changes to CupriTor are recorded here. This project adheres to [Semantic Versioning](https://semver.org).

## 0.1.6

Throttling for high-fan-out consumers. No breaking changes (additive; default behaviour unchanged).

### Reliability / DX
- **Optional concurrent-dial cap.** `TorClientOptions.MaxConcurrentDials` (default 0 = unlimited) bounds how many
  outbound dials run at once. Each `ConnectToOnionAsync` / `ConnectViaExitAsync` builds a fresh circuit — one TLS
  socket to an entry guard — so a consumer dialing many peers concurrently (e.g. a P2P node) could exhaust sockets /
  file descriptors. With a cap set, the excess dials wait for a free slot (bounded by the per-call timeout and the
  cancellation token) instead of opening unbounded connections. Purely a throttle — an individual dial's behaviour is
  unchanged. Answers the "no built-in dial limit → self-limit" note raised by an integrating consumer.

## 0.1.5

Reliability and clear-error hygiene for long-running / embedded consumers. No breaking changes (all additive).

### Reliability
- **Clear clock-skew error.** A device clock too far outside a fetched consensus's validity window now throws
  `TorClockSkewException` (reporting local vs consensus time) instead of an opaque "signature verification failed" —
  the common failure on mobile/embedded/fresh installs. `TorClientOptions.ClockSkewTolerance` (default 0) accepts
  modest skew.
- **Connectivity events.** The background refresh now emits `StatusChanged` `Reconnecting` when it loses the network
  and `Bootstrapped` again on recovery (polling faster while reconnecting), so a long-running app can surface
  "reconnecting / recovered".
- **Re-callable + opt-in retrying bootstrap.** `StartAsync` is now idempotent and safe to call again after a failure;
  `TorClientOptions.RetryBootstrap` (default off) makes it retry with backoff until connectivity arrives, for
  daemon-style consumers. The default stays fail-fast (throws).

### Correctness
- **Exit selection honours the IPv6 (`p6`) exit policy** for IPv6-literal destinations, not only the IPv4 (`p`)
  summary — parsed from the microdescriptor.

## 0.1.4

Vanguards-lite (guard-spec / proposal 333) — guard-discovery defense for onion-service circuits.

### Anonymity
- **Layer-2 vanguards.** Onion-service circuits (both client and service — rendezvous, introduction, HSDir) now
  route through a small, stable, slowly-rotating **layer-2 guard set** inserted as the second hop
  (`guard → L2 → middle → destination`), so an adversary who can induce many circuits can't enumerate random
  middles to work back toward the entry guard. Per spec: **4 vanguards**, `max(X,X)` lifetime with X uniform in
  [1, 12] days, bandwidth-weighted + /16-distinct selection, replaced when a vanguard leaves the consensus or
  loses Fast/Stable; persisted in the `IStateStore` like the entry guards.
- **Behavior change:** onion circuits are now **4 hops** by default (was 3). Configure via
  `TorClientOptions.Vanguards` — `All` (client + service, the default, matching Tor), `OnionServiceOnly`, or
  `Off`. Exit and directory circuits are unaffected.

## 0.1.3

Tunnelled directory fetches — closes the largest remaining anonymity gap (per-circuit relay selection leaking
over the clearnet directory channel). No breaking changes.

### Anonymity
- **Download-all microdescriptor warm at bootstrap.** After verifying the consensus, every listed relay's
  microdescriptor is fetched once (over the clearnet bootstrap source) into the cache, so subsequent circuit
  builds hit the cache and never fetch per-hop descriptors over the directory channel. Fetching *all* of them
  also means an observer of the bootstrap can't infer which relays a circuit uses (including the guard).
- **Over-circuit directory refreshes.** After bootstrap, consensus refreshes go over a Tor circuit (BEGIN_DIR
  to a V2Dir cache) via the new internal `CircuitDirectorySource`, with a clearnet fallback — so directory
  traffic stops signalling "Tor user" to an on-path observer on every refresh. Each refresh re-warms the cache
  over a circuit for the new consensus.
- Net effect: the only clearnet directory traffic is the one-time bootstrap (consensus + keys + all
  microdescriptors), which reveals that a Tor client is bootstrapping but not its path selection. Build-time
  microdescriptor resolution stays cache-first (clearnet only as a rare fallback for a brand-new relay).

### Correctness
- **PADDING keepalives no longer break circuit builds.** Build-time CREATE2/EXTEND2 reads now drop PADDING/VPADDING
  cells (matching the receive loop and tor-spec) instead of failing — a relay with connection padding can send a
  keepalive mid-handshake, which previously aborted the build. Surfaced live by the long over-circuit consensus
  transfer; hardens every circuit build (onion + exit included).
- **Onion descriptor lookup fixed in the morning UTC window.** The client computed the HSDir ring with the current
  shared-random value unconditionally; in the `[00:00–12:00)` UTC window the current time period pairs with the
  *previous* SRV (now selected via `IsBetweenTpAndSrv`, mirroring the service's two-period publish). Previously,
  onion lookups in that window fetched from the wrong HSDirs and got a 404 from every one — a pre-existing latent
  bug that made onion connect fail all morning and succeed in the afternoon.

## 0.1.2

Hardening and DX for onion-only, high-fan-out transports. No breaking changes (all new members are additive).

### Anonymity / correctness
- **Microdescriptor cache** — per-hop microdescriptors are cached by content digest and pruned on consensus
  refresh, so building a circuit no longer re-fetches (over the clearnet directory channel) the descriptors of
  relays already seen. Reduces the repeated on-path leak of relay selection and cuts per-dial latency.
- **Cancellation cleanup** — fixed two paths that could leak an `OrConnection` until GC when a dial was cancelled
  mid-handshake (the guard first hop in `BuildOverPathAsync`, and INTRODUCE1 in the onion connector); partially
  built circuits are now always disposed, including on cancellation.

### Safety / API
- **`TorClientOptions.OnionOnly`** — when set, any clearnet/exit dial (including a malformed address) throws
  `ClearnetBlockedException` instead of routing through a Tor exit, so an onion-only transport can't silently
  leave Tor. Covers `ConnectAsync`, the SOCKS5 server (replies "connection not allowed by ruleset"), and the
  HttpClient integration, since all dial through the same seam.
- **`FileStateStore`** — a durable, atomically-written (`temp` + rename) `IStateStore` so entry guards persist
  across restarts. The in-memory default now emits a one-time `StatusChanged` warning; set
  `TorClientOptions.RequirePersistentState` to refuse to start without a persistent store.
- **`InvalidOnionAddressException`** (derives from `ArgumentException`) is now thrown for malformed onion
  addresses by `ConnectToOnionAsync`/`LookupOnionAsync`.
- **Per-call timeouts** — `ConnectToOnionAsync`/`ConnectAsync`/`ConnectViaExitAsync` gained overloads taking an
  explicit `TimeSpan` timeout (overriding `TorClientOptions.Timeout`), convenient for a racing dialer.

## 0.1.1

Licensing and packaging only — no code or API changes; the library is identical to 0.1.0.

- Add a repository `LICENSE` (MIT) and `THIRD-PARTY-NOTICES.md` attributing the redistributed
  dependencies (BouncyCastle, CupriCurve, and the .NET runtime bundled into the sample apps).
- The self-contained sample bundles now include `LICENSE` and `THIRD-PARTY-NOTICES.md`.

## 0.1.0

First feature-complete release: a 100%-managed Tor client, v3 onion service, exit-capable dialer, and SOCKS5 proxy.
Live-validated end to end against the real Tor network (onion client, onion service, exit — over the default managed
TLS transport). 175 tests.

### Client (use Tor)
- `TorClient` — bootstraps and **verifies** the microdescriptor consensus against the 9 hard-coded directory
  authorities (strict 5-of-9 majority) before trusting it; maintains entry guards; auto-refreshes the consensus.
  `new TorClient()` works with no configuration (built-in directory authorities).
- **Onion client** — `ConnectToOnionAsync` (descriptor lookup → rendezvous → introduce → `Stream`), including
  connecting to **private** (client-authorized) onions.
- **Exit / clearnet** — `ConnectViaExitAsync` / `ConnectAsync` route non-onion hosts through exit relays
  (exit-policy aware, remote DNS at the exit).
- **`HttpClient` integration** — `ITorDialer.CreateTorHttpClient()` / `CreateTorHttpHandler()`.
- **SOCKS5 proxy** — `Socks5ProxyServer` (NO-AUTH, CONNECT; onion + clearnet), with a handshake timeout and a
  connection cap.
- **Progress** — `TorClient.StatusChanged` / `CurrentStatus` for bootstrap + connect phases.

### Onion services (host on Tor)
- `PublishOnionAsync` — durable v3 onion service: establishes intro points, publishes descriptors (two-period),
  self-heals, and serves inbound streams (raw handler or reverse proxy to a local TCP app).
- **Private onions** — `OnionClientAuthorization` (tor-format `descriptor:x25519:…` keys).
- **Persistent / vanity identities** — `OnionServiceKey` (tor `hs_ed25519_secret_key` interop).

### Hosting integrations
- **`CupriTor.AspNetCore`** — `UseCupriTorOnion(...)` hosts an ASP.NET Core app on an onion **in-process** (no
  loopback), binding clearnet + onion side by side.
- **`CupriTor.Host`** — cross-platform sidecar (dotnet tool / Windows Service / systemd / Docker): config-driven
  `ClearnetOnly` / `TorOnly` / `Both` front door for any local app, plus an optional SOCKS5 port.

### Path selection & anonymity
- Bandwidth-weighted path selection with **/16 subnet** and **relay-family** distinctness (mutual), and persistent
  **entry guards** with correct up/down attribution.
- See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what CupriTor does and does not protect.

### Managed crypto
- No `tor.exe` and no OS crypto on the critical path: SHA3/SHAKE/AES/X25519/Ed25519-verify via BouncyCastle,
  Ed25519 signing / key blinding via [CupriCurve](https://github.com/Wixely/CupriCurve).

### Known limitations
- Not independently audited; pre-1.0. No relay/node support, IPv6 exit, `RELAY_RESOLVE`, or traffic-analysis
  padding yet — see the [roadmap](ROADMAP.md).
