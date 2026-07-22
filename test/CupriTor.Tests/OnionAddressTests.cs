using CupriCurve;
using Xunit;

namespace CupriTor.Tests;

public class OnionAddressTests
{
    private static byte[] ValidPublicKey(int seedByte)
    {
        var seed = new byte[32];
        Array.Fill(seed, (byte)seedByte);
        var pub = new byte[32];
        Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(pub);
        return pub;
    }

    [Fact]
    public void RoundTrips_Through_String()
    {
        for (int i = 1; i < 20; i++)
        {
            byte[] pub = ValidPublicKey(i);
            var addr = OnionAddress.FromPublicKey(pub);
            string s = addr.ToString();

            Assert.EndsWith(".onion", s);
            Assert.Equal(56 + ".onion".Length, s.Length);

            Assert.True(OnionAddress.TryParse(s, out var parsed));
            Assert.Equal(pub, parsed.PublicKey.ToArray());
            Assert.Equal(addr, parsed);
        }
    }

    [Fact]
    public void Parse_Is_Case_Insensitive_And_Tolerates_Whitespace()
    {
        string s = OnionAddress.FromPublicKey(ValidPublicKey(7)).ToString();
        Assert.True(OnionAddress.TryParse("  " + s.ToUpperInvariant() + "  ", out _));
    }

    [Fact]
    public void Rejects_Corrupted_Checksum()
    {
        string s = OnionAddress.FromPublicKey(ValidPublicKey(3)).ToString();
        // Flip a character in the middle (part of pubkey/checksum) -> checksum mismatch.
        char[] chars = s.ToCharArray();
        chars[10] = chars[10] == 'a' ? 'b' : 'a';
        Assert.False(OnionAddress.TryParse(new string(chars), out _));
    }

    [Fact]
    public void Rejects_Wrong_Length()
    {
        Assert.False(OnionAddress.TryParse("abc.onion", out _));
        Assert.False(OnionAddress.TryParse("", out _));
        Assert.False(OnionAddress.TryParse(null, out _));
    }

    [Fact]
    public void FromPublicKey_Rejects_Invalid_Point()
    {
        var notAPoint = new byte[32];
        Array.Fill(notAPoint, (byte)0xFF); // not a canonical/on-curve encoding
        Assert.Throws<ArgumentException>(() => OnionAddress.FromPublicKey(notAPoint));
    }
}
