# TorSharp (joelverhagen/TorSharp)

> "Use Tor for your C# HTTP clients. Use Privoxy or .NET 6+ SOCKS support to proxy HTTP traffic."

- Repo: https://github.com/joelverhagen/TorSharp
- NuGet: `Knapcode.TorSharp`
- License: MIT

## Facts (verified 2026-08-28)

| | |
|---|---|
| Stars / forks | 343 / 68 |
| Open issues | 13 |
| Default branch | `release` |
| Last code push | **2023-10-24** |
| Latest NuGet | 2.15.0, published 2023-10-24 |
| Total downloads | ~155,400 (42,200 on 2.15.0) |
| Package size | 272 KB |
| Target frameworks | .NET Standard 2.0+, .NET Framework 4.6.2+ |
| Dependencies | SharpCompress ≥ 0.32.2; System.ServiceModel.Syndication ≥ 6.0.0 (netstandard2.0) |
| Library source | ~50 `.cs` files, ~150 KB under `src/` |
| OS support | Windows 10 1903+/11 21H2+, Linux (Ubuntu 16/18/20, Debian 10). **macOS not supported.** |

## What it actually is

A **supervisor for two external native processes**. TorSharp itself contains no Tor protocol code. Its job is:

1. `TorSharpToolFetcher` downloads the current official Tor and Privoxy builds (or you point it at
   locally-installed binaries).
2. `TorSharpProxy` writes `torrc` / Privoxy config, starts both processes, and manages their lifecycle.
3. You point a normal `HttpClientHandler.Proxy` at the resulting **localhost port** and make ordinary HTTP calls.
4. `GetNewIdentityAsync()` signals `NEWNYM` to rotate the circuit.

On .NET 6+ Privoxy can be switched off entirely, because `SocketsHttpHandler` gained native SOCKS5 support — so
the modern shape is *one* child process (`tor`) plus a `socks5://127.0.0.1:port` proxy URI.

```csharp
var settings = new TorSharpSettings { PrivoxySettings = { Enabled = false } };
await new TorSharpToolFetcher(settings, new HttpClient()).FetchAsync();
var proxy = new TorSharpProxy(settings);
await proxy.ConfigureAndStartAsync();

var handler = new HttpClientHandler
{
    Proxy = new WebProxy($"socks5://localhost:{settings.TorSettings.SocksPort}")
};
using var http = new HttpClient(handler);
```

## Strengths

- **By far the most adopted** of the three .NET options: 343 stars, 155k NuGet downloads, 68 forks.
- **Real Tor.** The anonymity-critical code is the audited C implementation the Tor Project ships. TorSharp is a
  thin, low-risk shell around it.
- **Broad TFM reach** — works all the way back to .NET Framework 4.6.2, which CupriTor (net10.0) does not.
- Genuinely low-effort: fetch, start, point an `HttpClient` at a port. Two files of setup.
- Ships samples including a Docker/Alpine sample; CI on GitHub Actions.

## Weaknesses / constraints

- **Requires shipping or downloading native binaries at runtime.** That is a hard blocker in locked-down
  environments, in single-file/AOT deployments, in restricted containers, and anywhere outbound downloads of
  executables are policy-forbidden.
- **The tool fetcher is a supply-chain and fragility surface.** The README itself notes fetcher URLs can break when
  upstream distribution file names change — and the *last commit in the repo* is exactly such a fix
  ("Update Tor file pattern due to change in distribution file name format"). Since the repo has not been pushed
  to since 2023-10-24, a future upstream rename would break fetching with no maintainer response so far.
- **Not thread-safe.** The README states you need a separate instance per parallel task, so parallel scraping means
  N `tor` processes and N port pairs.
- **No macOS.**
- **Client-only.** No onion-service hosting, no circuit introspection, no per-stream control. You get a proxy port,
  and that is the entire abstraction.
- **Privoxy dependency on old TFMs** has known missing-shared-library problems on non-Debian Linux (CentOS 7,
  Alpine), requiring a system-installed Privoxy as a workaround.
- Dormant: ~3 years without a push as of this comparison. Not dead-dead (it works), but nobody is steering it.

## Verdict

The safe default for the common case. If your requirement is literally *"make HTTP requests through Tor from C#"*
and you can tolerate a child process, TorSharp is the correct answer and the rest of this folder is academic. It
stops being the answer the moment you need onion-service hosting, no-subprocess deployment, or macOS.
