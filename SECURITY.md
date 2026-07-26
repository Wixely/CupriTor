# Security policy

## Reporting a vulnerability

Please report security issues **privately** — open a [GitHub security advisory](https://github.com/Wixely/CupriTor/security/advisories/new)
for this repository rather than a public issue. Include a description, affected version/commit, and a reproduction if
you have one. We'll acknowledge and work a fix before any public disclosure.

CupriTor is pre-1.0 and has **not** had an independent security audit. Treat it accordingly.

## What CupriTor does and does not protect

> **CupriTor provides Tor's *network-layer* anonymity, not Tor Browser's *application/browser* anonymity.**

It hides the network path (who talks to whom, at the IP level). It does **not** make your application's own traffic
unfingerprintable — a normal browser or default `HttpClient` sent through CupriTor is still fully identifiable at the
application layer, even over a perfect circuit. For anonymous *browsing*, use Tor Browser.

See **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** for the full threat model: what's protected, what isn't, which
Tor-Browser-style mitigations are in scope, and the dual-bind onion↔clearnet correlation warning.

## Reminder for operators

- The **exit relay sees clearnet plaintext** — always use TLS (`https://…`) to the destination.
- **Don't dual-bind identical content** on clearnet and an onion if you need those identities to stay unlinkable.
- Keep the SOCKS proxy on **loopback** — it is unauthenticated.
