# ornet.io (OrNET) — not a .NET library

**Bottom line: there is no OrNET Tor library for .NET, and no OrNET developer SDK of any kind that I could find.**
ornet.io is the web presence for a set of **consumer mobile privacy apps**. It does not belong in a comparison of
.NET libraries except as a "this is not what you thought it was" entry.

## What OrNET actually is

| | |
|---|---|
| Products | **OrNET VPN** (iOS + Android), **TOR Browser: OrNET Onion + VPN** / "Dark Web Browser: OrNET" (iOS + Android) |
| Publisher | **Stronger Apps** (Android package IDs `sa.ornetvpn`, `com.ornet.torbrowser`) |
| Platforms | iOS and Android only |
| What it does | Consumer Tor browser + commercial VPN, protocols advertised as Vless / Vmess / Shadowsocks / Trojan, kill switch, no-logs claim |
| Model | Proprietary, app-store distributed, commercial |
| Source | Closed. No public repository found |
| Role of ornet.io | Marketing site + privacy policy / terms pages linked from the app-store listings |

## What I checked, and what I could not

Searched and checked on 2026-08-28:

- **`ornet.io` direct fetch — BLOCKED.** The site sits behind a Cloudflare "managed challenge" (JS/cookie
  interstitial). Every request, with and without a browser user-agent, across `/`, `/privacy`, `/terms`, `/en`,
  `/docs`, returned the challenge page rather than content. **So I could not read the site itself.** Everything
  below is from sources outside ornet.io.
- **Web search for `ornet.io`** → only app-store listings (Apple App Store, Google Play, AppBrain) and the
  unrelated German medical-tech association `ornet.org`. No SDK, no docs portal, no developer section.
- **Web search for an OrNET / Stronger Apps developer SDK** → nothing. Results are consumer app listings only.
- **GitHub org/user search for `ornet`** → the accounts named `ornet*` are unrelated; the only Tor-adjacent hits
  are `nusenu/OrNetStats` and `nusenu/OrNetRadar`, which are **Tor network statistics websites by a different
  author (nusenu)** and have nothing to do with ornet.io.
- **NuGet search** → no OrNET package. The .NET Tor packages that exist are `Knapcode.TorSharp`, `DotNetTor`
  (deprecated/legacy), `Tor4NET`, `TorHiddenServiceHelper`, `TorHttpClientExecutor`.

## Caveat

Because Cloudflare blocked me from reading ornet.io directly, I cannot state with certainty that no developer
offering exists behind that domain — only that **nothing about one is discoverable from anywhere else**, which for
a real SDK would be very unusual. If you have a specific link, page, or package name from them, hand it over and
I will evaluate it properly.

## Why it matters for the comparison anyway

The likely reason OrNET came up: they ship a *working, popular, mobile* Tor client. If the interest is
**"how do these guys do Tor on mobile"** rather than "can I reference their library", the answer is almost
certainly the standard Android approach — bundling the C `tor` binary or embedding
[Orbot](https://github.com/guardianproject/orbot) / the Guardian Project's Tor Android libraries — which is
architecturally the **same category as TorSharp**: supervise a native `tor` process, expose a local SOCKS port.
That is *not* something you can consume from .NET, and it is precisely the architecture CupriTor exists to avoid.

**This paragraph is inference, not verified fact** — I could not read their site or decompile their apps.
