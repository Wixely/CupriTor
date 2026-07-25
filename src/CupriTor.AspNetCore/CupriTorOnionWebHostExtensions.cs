using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CupriTor.AspNetCore;

/// <summary>Extensions that add an in-process Tor onion endpoint to a Kestrel server.</summary>
public static class CupriTorOnionWebHostExtensions
{
    /// <summary>
    /// Serve this app on a Tor v3 onion service, <b>in-process</b>: inbound onion streams are fed straight to Kestrel
    /// as connections — no loopback proxy, no extra socket. This is <b>additive</b>: any clearnet endpoints the app
    /// already binds (ASPNETCORE_URLS, <c>UseUrls</c>, Kestrel config) keep working, so you get clearnet + onion in
    /// one server sharing the same middleware pipeline. For "onion only", simply configure no clearnet URLs.
    /// Call once per onion; call again to host several onions behind one shared Tor client.
    /// </summary>
    public static IWebHostBuilder UseCupriTorOnion(this IWebHostBuilder builder, Action<CupriTorOnionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new CupriTorOnionOptions();
        configure(options);
        if (options.Identity is null)
            throw new InvalidOperationException($"{nameof(CupriTorOnionOptions)}.{nameof(CupriTorOnionOptions.Identity)} must be set (the onion service key).");

        return builder.ConfigureServices(services =>
        {
            // One shared transport factory (owns a single Tor client), registered alongside the default socket transport.
            services.TryAddSingleton<CupriTorConnectionListenerFactory>();
            services.AddSingleton<IConnectionListenerFactory>(sp => sp.GetRequiredService<CupriTorConnectionListenerFactory>());

            // Add the onion endpoint. Plaintext HTTP — Tor itself provides the encryption and authentication.
            services.Configure<KestrelServerOptions>(kestrel =>
                kestrel.Listen(new CupriTorEndPoint(options), listen => listen.Protocols = options.Protocols));
        });
    }

    /// <summary>
    /// Serve this app on a public onion service for <paramref name="identity"/> with default settings (3 intro points).
    /// </summary>
    public static IWebHostBuilder UseCupriTorOnion(this IWebHostBuilder builder, OnionServiceKey identity) =>
        builder.UseCupriTorOnion(o => o.Identity = identity);
}
