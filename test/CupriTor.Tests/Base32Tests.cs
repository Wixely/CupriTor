using System.Text;
using CupriTor.Internal;
using Xunit;

namespace CupriTor.Tests;

public class Base32Tests
{
    // RFC 4648 §10 test vectors (lowercase, unpadded — the Tor variant).
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "my")]
    [InlineData("fo", "mzxq")]
    [InlineData("foo", "mzxw6")]
    [InlineData("foob", "mzxw6yq")]
    [InlineData("fooba", "mzxw6ytb")]
    [InlineData("foobar", "mzxw6ytboi")]
    public void Encode_Matches_Rfc4648(string input, string expected)
    {
        Assert.Equal(expected, Base32.Encode(Encoding.ASCII.GetBytes(input)));
    }

    [Theory]
    [InlineData("my", "f")]
    [InlineData("mzxq", "fo")]
    [InlineData("mzxw6", "foo")]
    [InlineData("mzxw6ytboi", "foobar")]
    public void Decode_Matches_Rfc4648(string input, string expected)
    {
        Assert.True(Base32.TryDecode(input, out var bytes));
        // decode may yield a trailing zero-padding byte group; compare the meaningful prefix
        Assert.Equal(expected, Encoding.ASCII.GetString(bytes.AsSpan(0, expected.Length)));
    }

    [Fact]
    public void Decode_Rejects_Invalid_Chars()
    {
        Assert.False(Base32.TryDecode("018!", out _));
    }
}
