# CupriTor

A **100% managed**, **MIT-licensed**, **.NET 10** Tor client and v3 onion-service library — no external `tor`
process, AOT-friendly. Exposes a small `Stream`-based API: dial a `.onion`, publish an onion service, accept
inbound connections.

Built first for [CupriNet](https://github.com/Wixely/CupriNet); the API is generic and takes no dependency on any
consumer. Depends on [CupriCurve](https://github.com/Wixely/CupriCurve) for Tor-style Ed25519 key blinding.

> Status: early / planning. See the local `plan/` folder (git-ignored) for the build plan.

## License

MIT.
