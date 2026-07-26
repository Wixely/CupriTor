using CupriTor.Directory;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class FamilyTests
{
    [Fact]
    public void Family_Line_Normalizes_Tokens()
    {
        byte[] idA = new byte[20];
        for (int i = 0; i < 20; i++) idA[i] = (byte)i;
        string fpA = Convert.ToHexString(idA); // uppercase 40-hex

        string md = $"ntor-onion-key {Convert.ToBase64String(new byte[32])}\n" +
                    $"family $" + fpA.ToLowerInvariant() + "=SomeName MixedCaseNick\n";

        Assert.True(Microdescriptor.TryParse(md, out Microdescriptor parsed));
        Assert.Contains("$" + fpA, parsed.Family);       // fingerprint uppercased, "=name" suffix stripped
        Assert.Contains("mixedcasenick", parsed.Family);  // nickname lowercased
    }

    [Fact]
    public void InSameFamily_Requires_Mutual_Listing()
    {
        var a = new RouterStatusEntry { Nickname = "alice", RsaIdentityDigest = Id(0x11) };
        var b = new RouterStatusEntry { Nickname = "bob", RsaIdentityDigest = Id(0x22) };
        string fpA = "$" + Convert.ToHexString(a.RsaIdentityDigest);
        string fpB = "$" + Convert.ToHexString(b.RsaIdentityDigest);

        Microdescriptor listsA = Md($"family {fpA}");
        Microdescriptor listsB = Md($"family {fpB}");
        Microdescriptor listsNothing = Md("family");

        Assert.True(TorNetwork.InSameFamily(a, listsB, b, listsA));       // each lists the other → same family
        Assert.False(TorNetwork.InSameFamily(a, listsB, b, listsNothing)); // one-way only → not family
        Assert.False(TorNetwork.InSameFamily(a, listsNothing, b, listsNothing));
    }

    private static Microdescriptor Md(string familyLine)
    {
        string text = $"ntor-onion-key {Convert.ToBase64String(new byte[32])}\n{familyLine}\n";
        Assert.True(Microdescriptor.TryParse(text, out Microdescriptor md));
        return md;
    }

    private static byte[] Id(byte v)
    {
        var b = new byte[20];
        Array.Fill(b, v);
        return b;
    }
}
