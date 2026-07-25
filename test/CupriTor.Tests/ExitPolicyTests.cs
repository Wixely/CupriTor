using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

public class ExitPolicyTests
{
    [Theory]
    [InlineData("accept", "80,443", 80, true)]
    [InlineData("accept", "80,443", 443, true)]
    [InlineData("accept", "80,443", 22, false)]
    [InlineData("reject", "25,119", 25, false)]
    [InlineData("reject", "25,119", 80, true)]
    [InlineData("accept", "600-700", 650, true)]
    [InlineData("accept", "600-700", 700, true)]
    [InlineData("accept", "600-700", 701, false)]
    [InlineData("accept", "80,443,600-700", 700, true)]
    [InlineData("reject", "1-65535", 443, false)]
    public void PolicySummary_Allows_Honours_Verb_And_Ports(string verb, string ports, int port, bool allowed)
    {
        Assert.Equal(allowed, ExitPolicySummary.Parse(verb, ports).Allows(port));
    }

    [Fact]
    public void RejectAll_Denies_Everything()
    {
        Assert.False(ExitPolicySummary.RejectAll.Allows(80));
        Assert.False(ExitPolicySummary.RejectAll.Allows(443));
    }

    [Fact]
    public void Microdescriptor_Parses_The_P_Line()
    {
        string md = $"ntor-onion-key {Convert.ToBase64String(new byte[32])}\n" +
                    $"id ed25519 {Convert.ToBase64String(new byte[32])}\n" +
                    "p accept 80,443,8080\n";

        Assert.True(Microdescriptor.TryParse(md, out Microdescriptor parsed));
        Assert.True(parsed.ExitPolicyIPv4.Allows(8080));
        Assert.False(parsed.ExitPolicyIPv4.Allows(22));
    }

    [Fact]
    public void Microdescriptor_Without_P_Line_Rejects_All()
    {
        string md = $"ntor-onion-key {Convert.ToBase64String(new byte[32])}\n";

        Assert.True(Microdescriptor.TryParse(md, out Microdescriptor parsed));
        Assert.False(parsed.ExitPolicyIPv4.Allows(80)); // no "p" line ⇒ not an exit
    }
}
