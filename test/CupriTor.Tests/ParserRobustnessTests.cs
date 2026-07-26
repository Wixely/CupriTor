using CupriTor.Directory;
using Xunit;

namespace CupriTor.Tests;

// A hostile/broken directory cache must never crash the parsers — TryParse must return false, not throw.
public class ParserRobustnessTests
{
    [Theory]
    [InlineData("consensus-method\n")]                          // keyword with no argument
    [InlineData("consensus-method 99999999999999999999999\n")]  // overflow
    [InlineData("not a directory document at all")]
    [InlineData("")]
    public void Consensus_TryParse_Returns_False_Not_Throws(string text)
    {
        Assert.False(Consensus.TryParse(text, out _));
    }

    [Theory]
    [InlineData("p accept 99999999999999999999\n")] // overflow port in the exit-policy summary
    [InlineData("p\n")]                             // no args
    [InlineData("ntor-onion-key\n")]                // no arg
    [InlineData("id ed25519\n")]                    // truncated
    public void Microdescriptor_TryParse_Returns_False_Not_Throws(string text)
    {
        Assert.False(Microdescriptor.TryParse(text, out _));
    }
}
