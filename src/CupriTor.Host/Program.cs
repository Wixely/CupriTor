using CupriTor.Host;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// CupriTor host — expose a local app over Tor (onion), clearnet, or both, driven by config.
// Config sources (later wins): appsettings.json → environment variables (e.g. CupriTor__Mode=TorOnly) →
// command line (e.g. --CupriTor:Mode=TorOnly). Runs as a console app, a Windows Service, or a Linux
// systemd daemon (auto-detected).

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(o => o.ServiceName = "CupriTor Host");
builder.Services.AddSystemd();

// Bind the "CupriTor" configuration section to the strongly-typed config.
var config = new OnionHostConfig();
builder.Configuration.GetSection("CupriTor").Bind(config);
builder.Services.AddSingleton(config);
builder.Services.AddHostedService<OnionHostService>();

await builder.Build().RunAsync();
