# Changelog

All notable changes to CupriTor are recorded here. This project adheres to [Semantic Versioning](https://semver.org).

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
