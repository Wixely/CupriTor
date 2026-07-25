using CupriTor;
using CupriTor.AspNetCore;

// A minimal ASP.NET Core app served DIRECTLY on a Tor v3 onion service — no loopback proxy. The same Kestrel
// server and middleware pipeline ALSO serve clearnet on loopback, so this is a dual-bound app: reachable on
// http://localhost:5000 AND http://<address>.onion at the same time.
//
// Note: UseCupriTorOnion adds the onion via Kestrel's Listen() API, which overrides ASPNETCORE_URLS / UseUrls.
// Multiple Listen() calls are additive, so configure clearnet with Kestrel Listen* too (below) to bind both.
// (Drop the ConfigureKestrel line and it becomes onion-only; swap ListenLocalhost → ListenAnyIP for public clearnet.)

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(k => k.ListenLocalhost(5000)); // clearnet front door on loopback

// Persist the identity so the .onion address is stable across restarts. Delete the file for a fresh address; drop
// in a tor `hs_ed25519_secret_key` (or a pre-generated vanity key) to adopt an existing one.
const string keyPath = "hs_ed25519_secret_key";
OnionServiceKey identity = File.Exists(keyPath)
    ? OnionServiceKey.FromTorSecretKey(File.ReadAllBytes(keyPath))
    : OnionServiceKey.CreateRandom();
File.WriteAllBytes(keyPath, identity.ToTorSecretKey());

builder.WebHost.UseCupriTorOnion(o =>
{
    o.Identity = identity;
    o.IntroPoints = 3;
    // Make it a PRIVATE onion by authorizing specific clients (Tor Browser client-auth keys):
    // o.AuthorizedClients.Add(OnionClientAuthorization.ParsePublicKey("descriptor:x25519:BASE32PUBKEY"));
});

var app = builder.Build();

app.MapGet("/", () => $"Hello from {identity.OnionAddress}\nServed in-process by Kestrel over Tor — no loopback.\n");
app.MapGet("/whoami", (HttpContext ctx) => new
{
    onion = identity.OnionAddress,
    // Clearnet connections carry a local IP; onion connections don't (there's no socket) — a simple way to tell them apart.
    transport = ctx.Connection.LocalIpAddress is null ? "tor" : "clearnet",
    protocol = ctx.Request.Protocol,
});

Console.WriteLine($"Clearnet:  http://localhost:5000/");
Console.WriteLine($"Onion:     http://{identity.OnionAddress}/");
app.Run();
