using CupriTor;
using Microsoft.Extensions.Logging;

namespace CupriTor.Host;

/// <summary>Loads or creates the onion identity per the configured <see cref="OnionIdentityMode"/>.</summary>
internal static class Identity
{
    public static OnionServiceKey Load(OnionConfig config, ILogger log)
    {
        switch (config.IdentityMode)
        {
            case OnionIdentityMode.Vanity:
                byte[] vanity = File.ReadAllBytes(config.IdentityFile);
                var vk = OnionServiceKey.FromTorSecretKey(vanity);
                log.LogInformation("Loaded vanity identity from {File}: {Onion}", config.IdentityFile, vk.OnionAddress);
                return vk;

            case OnionIdentityMode.Persistent:
                if (File.Exists(config.IdentityFile))
                {
                    var loaded = OnionServiceKey.FromTorSecretKey(File.ReadAllBytes(config.IdentityFile));
                    log.LogInformation("Loaded persistent identity from {File}: {Onion}", config.IdentityFile, loaded.OnionAddress);
                    return loaded;
                }
                var created = OnionServiceKey.CreateRandom();
                File.WriteAllBytes(config.IdentityFile, created.ToTorSecretKey());
                File.WriteAllText(Path.ChangeExtension(config.IdentityFile, ".hostname"), created.Hostname);
                log.LogInformation("Created persistent identity {Onion}; saved to {File} (reuse to keep this address).", created.OnionAddress, config.IdentityFile);
                return created;

            default:
                var random = OnionServiceKey.CreateRandom();
                log.LogInformation("Generated ephemeral identity: {Onion}", random.OnionAddress);
                return random;
        }
    }
}
