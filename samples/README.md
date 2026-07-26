# CupriTor samples

Runnable, self-contained example apps — one per scenario. Pre-built **Windows** and **Ubuntu** zips
are produced by GitHub Actions (`.github/workflows/samples.yml`) and attached to each release; you can
also run any of them from source with `dotnet run --project samples/<name>`.

| Sample | What it shows | Type |
|---|---|---|
| **[OnionWebApp](OnionWebApp)** | Host an ASP.NET Core site **directly on a Tor onion service, in-process** (no loopback proxy), bound to loopback **and** the onion at once. | Web app |
| **[TorHttpClient](TorHttpClient)** | Reach the Tor network with a standard **`HttpClient`** — fetch a `.onion` (or a clearnet URL via a Tor exit). | Console |
| **[TorSocks5Proxy](TorSocks5Proxy)** | Run a local **SOCKS5 proxy** over Tor (`127.0.0.1:9050`) so any SOCKS-aware app rides Tor. | Console |

All are 100% managed (no `tor.exe`). The console samples take a moment on first run to bootstrap and
verify the Tor consensus. Each prints a clear banner describing what it does.

## Downloading the pre-built bundles

Each release has `<Sample>-windows.zip` and `<Sample>-ubuntu.zip` — self-contained single-file builds
that need no .NET runtime installed. Unzip and run the executable inside.

```bash
# Windows:  unzip TorHttpClient-windows.zip  → cupritor-httpclient-sample.exe
# Ubuntu:   unzip TorHttpClient-ubuntu.zip    → ./cupritor-httpclient-sample
```

> These samples make real Tor connections, so run them where outbound Tor traffic is allowed.
