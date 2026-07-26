# CupriTor threat model & anonymity notes

CupriTor is a 100%-managed Tor client, v3 onion service, exit-capable dialer, and SOCKS5 proxy for embedding
in .NET applications. This document states plainly **what it protects, what it does not, and which Tor-Browser-style
mitigations are — and are not — in scope**, so integrators don't build on a false sense of security.

## The one sentence to internalize

> **CupriTor gives you Tor's *network-layer* anonymity, not Tor Browser's *application/browser* anonymity.**

It hides the network path (who is talking to whom, at the IP level) using onion routing, entry guards, and path
diversity. It does **nothing** about how your *application's own traffic* fingerprints you. If you point a normal
browser or a default `HttpClient` at CupriTor's SOCKS/dialer, that browser or client is still fully identifiable
(User-Agent, headers, cookies, JavaScript, canvas, TLS-to-the-destination, timing) **even over a perfect circuit.**
For anonymous *browsing*, use Tor Browser. CupriTor is for **programmatic** access (app↔onion, app↔clearnet-via-exit,
and hosting onion services), where you control the client and can avoid application-layer leaks.

## What CupriTor protects (in scope, implemented)

- **Network path anonymity** — 3-hop onion-routed circuits; the destination doesn't learn your IP, and no single
  relay sees both ends.
- **Verified network view** — the consensus is fetched and verified against the 9 hard-coded directory authorities
  (strict 5-of-9 majority) before it is trusted; a malicious directory cache can't forge the network view, and
  microdescriptors are digest-matched so ntor keys can't be substituted.
- **Path diversity** — no relay appears twice in a circuit; no two hops share a /16 subnet or a declared **family**;
  entry guards are persistent (kept stable rather than reselected per circuit).
- **No local DNS leaks** — clearnet names are resolved **at the exit** (the SOCKS server expects remote-DNS,
  i.e. `--socks5-hostname`).
- **Onion-service crypto** — v3 descriptors, hs-ntor, client authorization (private onions), all byte-exact with Tor.

## What CupriTor does NOT protect (out of scope — the caller's responsibility)

- **Application-layer fingerprinting.** Anything your app sends — User-Agent, `Server`/`Date` headers, cookies,
  account identifiers, unique request ordering/timing — identifies you regardless of Tor. This is the big one.
- **Exit-visible plaintext.** For clearnet-via-exit, the exit relay can read and tamper with plaintext. Use TLS to
  the destination (`https://…`). The exit is untrusted.
- **Browser/device fingerprint** — see the next section.

## Tor Browser mitigations: which apply here (the decision)

Most of Tor Browser's hardening lives at the **browser/content layer** and has no meaning in a library — there is no
DOM, no JavaScript, no rendering surface, no user device. These are **out of scope** and will not be implemented:

> canvas / WebGL fingerprint resistance · font-enumeration limits · screen-size quantization & letterboxing ·
> timezone→UTC · locale spoofing · uniform User-Agent · `navigator.*` normalization · `performance.now()` precision
> reduction · WebRTC disabled (IP-leak) · first-party/state isolation · NoScript.

What *does* apply to CupriTor is **network/protocol-layer** fingerprinting and traffic analysis. Our position on each:

| Concern | Status & decision |
|---|---|
| **TLS ClientHello fingerprint** | ⚠️ **Deferred (highest-priority mitigation).** Our TLS handshake (BouncyCastle, or the OS `SslStream` baseline) is **not** Tor's mimicked ClientHello, so a guard or an on-path censor could distinguish CupriTor traffic from the tor reference client. Matters most for **censored-environment** use. Mitigating it needs a uTLS-style ClientHello study and a custom ClientHello — a real workstream, tracked in ROADMAP. |
| **Traffic-analysis padding** (padding-spec) | ⚠️ **Deferred.** No connection- or circuit-level padding machines are implemented; the traffic *shape* and timing are unobscured. Relevant only if your adversary performs traffic analysis. |
| **Stream isolation** | ℹ️ **Documented.** CupriTor currently builds a **fresh circuit per connection** and tears it down after — so no two destinations share a circuit. This *over-isolates* (good for linkability) but is unusual and slower than Tor's ~10-minute circuit reuse, and is itself a mild behavioral tell. There is no SOCKS-auth-based isolation knob. A configurable isolation / circuit-reuse policy is a possible future addition. |
| **Client-behaviour conformance** | ⚠️ **Deferred.** Circuit build/rotation cadence (per-connection, no preemptive spare circuits) and the exact protocol-version handshake differ from the tor client and are, in principle, distinguishable. |
| **DNS / guard behaviour** | ✅ Remote DNS at the exit; persistent guards with /16 diversity and correct up/down attribution. |

## Dual-bind (onion + clearnet) correlation warning

`CupriTor.AspNetCore` (in-process) and `CupriTor.Host` (`Mode: Both`) let one app serve the **same content on
clearnet and on an onion at the same time**. An observer can then often **link the onion service to the clearnet
identity** via identical response bytes, `Server`/`Date` headers, TLS certificates, `ETag`s, error pages, or timing
correlation. **If unlinkability between your onion and your clearnet identity matters, do not dual-bind identical
content**, or strip/vary the correlating signals.

## Guidance for integrators

1. Treat CupriTor as **IP-layer anonymity for your app's traffic**, not anonymous browsing.
2. Don't send identifying data over the circuit (accounts, cookies, unique headers) unless you intend to.
3. Assume the **exit is hostile** on clearnet — always use TLS to the destination.
4. For per-activity unlinkability, use separate circuits (today, every `ConnectAsync` already gets its own circuit)
   or separate `TorClient` instances; don't reuse an onion identity across contexts you want unlinkable.
5. If you need **browsing** anonymity, use Tor Browser — not a general HTTP client over CupriTor.

## Summary of the decision

- **Out of scope:** all browser/content-layer mitigations (there is no browser).
- **In scope, prioritized (tracked in [ROADMAP](../ROADMAP.md)):** (1) TLS ClientHello fingerprint mitigation for
  censored networks, (2) a stream-isolation / circuit-reuse policy, (3) traffic-analysis padding.
- **Documented limitations (this file):** application-layer fingerprinting is the caller's responsibility; the exit
  sees clearnet plaintext; dual-bind onion↔clearnet content can be correlated.
