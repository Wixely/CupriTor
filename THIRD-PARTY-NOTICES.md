# Third-party notices

CupriTor is licensed under the MIT License — see [LICENSE](LICENSE).

CupriTor depends on the third-party components listed below. They are referenced
as NuGet packages and are redistributed in binary form inside the self-contained
sample bundles (attached to each GitHub release) and the `cupritor-host` dotnet
tool. Each component is used under its own license.

Every component listed here is licensed under the MIT License. The MIT permission
and warranty text is identical for each, so it is reproduced once at the end of
this file; only the copyright notice differs, and those are listed per component.

## Components

- **BouncyCastle.Cryptography** 2.4.0 — cryptographic primitives and managed TLS.
  <https://www.bouncycastle.org/csharp/>
  Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc. (<https://www.bouncycastle.org>)

- **CupriCurve** 0.1.0 — managed Ed25519 / Curve25519 group arithmetic (key blinding).
  <https://github.com/Wixely/CupriCurve>
  Copyright (c) 2026 Wixely

- **Microsoft.Extensions.Hosting**, **Microsoft.Extensions.Hosting.WindowsServices**,
  **Microsoft.Extensions.Hosting.Systemd** 10.0.0 — the generic host used by the
  `CupriTor.Host` sidecar — together with the **.NET runtime and base class
  libraries**, which are bundled into the self-contained sample bundles.
  <https://github.com/dotnet/runtime>
  Copyright (c) .NET Foundation and Contributors

Test-only dependencies (xUnit, Microsoft.NET.Test.Sdk) are not distributed and are
therefore not listed here.

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
