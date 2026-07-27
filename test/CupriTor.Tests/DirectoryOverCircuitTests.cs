using System.Text;
using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

/// <summary>
/// Tests for the HTTP-over-BEGIN_DIR response parsing used by over-circuit directory fetches (0.1.3). The
/// circuit-building path itself needs a live relay, so only the pure parser is unit-tested here.
/// </summary>
public class DirectoryOverCircuitTests
{
    [Fact]
    public void ParseHttpBody_Extracts_Body_From_200()
    {
        byte[] resp = Encoding.ASCII.GetBytes("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nonion-key\nthe-body");
        Assert.Equal("onion-key\nthe-body", TorNetwork.ParseHttpBody(resp));
    }

    [Fact]
    public void ParseHttpBody_Throws_On_Non_200()
    {
        byte[] resp = Encoding.ASCII.GetBytes("HTTP/1.0 404 Not found\r\n\r\nnope");
        Assert.Throws<InvalidOperationException>(() => TorNetwork.ParseHttpBody(resp));
    }

    [Fact]
    public void ParseHttpBody_Throws_On_Missing_Header_Terminator()
    {
        byte[] resp = Encoding.ASCII.GetBytes("HTTP/1.0 200 OK\r\nno blank line follows");
        Assert.Throws<InvalidOperationException>(() => TorNetwork.ParseHttpBody(resp));
    }
}
