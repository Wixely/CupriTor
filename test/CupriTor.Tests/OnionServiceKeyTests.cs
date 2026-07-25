using System.Text;
using CupriTor;
using Xunit;

namespace CupriTor.Tests;

public class OnionServiceKeyTests
{
    [Fact]
    public void CreateRandom_Produces_Distinct_Valid_Addresses()
    {
        OnionServiceKey a = OnionServiceKey.CreateRandom();
        OnionServiceKey b = OnionServiceKey.CreateRandom();

        Assert.EndsWith(".onion", a.OnionAddress);
        Assert.Equal(62, a.OnionAddress.Length);              // 56 base32 chars + ".onion"
        Assert.True(OnionAddress.TryParse(a.OnionAddress, out OnionAddress parsed));
        Assert.Equal(a.PublicKey, parsed.PublicKey.ToArray());
        Assert.NotEqual(a.OnionAddress, b.OnionAddress);      // fresh identity each time
    }

    [Fact]
    public void FromSeed_Is_Deterministic()
    {
        var seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)i;

        Assert.Equal(OnionServiceKey.FromSeed(seed).OnionAddress, OnionServiceKey.FromSeed(seed).OnionAddress);
    }

    [Fact]
    public void Expanded_And_TorFile_RoundTrip_Preserve_The_Address()
    {
        OnionServiceKey original = OnionServiceKey.CreateRandom();

        // Raw 64-byte expanded key round-trip (the vanity-key import path).
        OnionServiceKey viaExpanded = OnionServiceKey.FromExpandedSecretKey(original.ExpandedSecretKey());
        Assert.Equal(original.OnionAddress, viaExpanded.OnionAddress);

        // tor hs_ed25519_secret_key file round-trip (persistence + ecosystem interop).
        byte[] torFile = original.ToTorSecretKey();
        Assert.Equal(96, torFile.Length);
        Assert.Equal("== ed25519v1-secret: type0 ==", Encoding.ASCII.GetString(torFile, 0, 29));
        OnionServiceKey viaTor = OnionServiceKey.FromTorSecretKey(torFile);
        Assert.Equal(original.OnionAddress, viaTor.OnionAddress);
        Assert.Equal(original.PublicKey, viaTor.PublicKey);
    }

    [Fact]
    public void ClientAuthorization_KeyPair_RoundTrips_Through_Tor_Format()
    {
        (string publicLine, string _, byte[] publicKey, byte[] privateKey) = OnionClientAuthorization.GenerateClientKeyPair();

        Assert.StartsWith("descriptor:x25519:", publicLine);
        Assert.Equal(32, publicKey.Length);
        Assert.Equal(32, privateKey.Length);

        // Parsing the formatted public line (with or without prefix) recovers the same key bytes.
        Assert.Equal(publicKey, OnionClientAuthorization.ParsePublicKey(publicLine));
        Assert.Equal(publicKey, OnionClientAuthorization.ParsePublicKey(publicLine["descriptor:x25519:".Length..]));
        Assert.Throws<FormatException>(() => OnionClientAuthorization.ParsePublicKey("not-valid-base32-!!"));
    }

    [Fact]
    public void Seed_And_Its_Expanded_Form_Agree()
    {
        var seed = new byte[32];
        for (int i = 0; i < 32; i++) seed[i] = (byte)(0xA0 + i);

        OnionServiceKey fromSeed = OnionServiceKey.FromSeed(seed);
        OnionServiceKey fromExpanded = OnionServiceKey.FromExpandedSecretKey(fromSeed.ExpandedSecretKey());
        Assert.Equal(fromSeed.OnionAddress, fromExpanded.OnionAddress);
    }
}
