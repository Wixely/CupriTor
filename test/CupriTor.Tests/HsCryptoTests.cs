using CupriCurve;
using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

public class HsCryptoTests
{
    private static byte[] Identity(byte seedByte)
    {
        var seed = new byte[32];
        Array.Fill(seed, seedByte);
        var pub = new byte[32];
        Ed25519ExpandedKey.FromSeed(seed).GetPublicKey(pub);
        return pub;
    }

    [Fact]
    public void TimePeriod_Is_Monotonic_And_Bounded()
    {
        var t = new DateTimeOffset(2026, 7, 24, 15, 0, 0, TimeSpan.Zero);
        long tp = HsTimePeriod.Number(t);

        DateTimeOffset start = HsTimePeriod.Start(tp);
        DateTimeOffset nextStart = HsTimePeriod.Start(tp + 1);

        Assert.True(start <= t && t < nextStart);
        Assert.Equal(TimeSpan.FromMinutes(HsTimePeriod.DefaultLengthMinutes), nextStart - start);
        Assert.Equal(tp + 1, HsTimePeriod.Number(nextStart));
    }

    [Fact]
    public void BlindedKey_Is_Deterministic_And_A_Valid_Point()
    {
        byte[] identity = Identity(1);
        long tp = HsTimePeriod.Number(new DateTimeOffset(2026, 7, 24, 15, 0, 0, TimeSpan.Zero));

        var a = new byte[32];
        var b = new byte[32];
        Assert.True(HsBlinding.TryBlindPublicKey(identity, tp, HsTimePeriod.DefaultLengthMinutes, a));
        Assert.True(HsBlinding.TryBlindPublicKey(identity, tp, HsTimePeriod.DefaultLengthMinutes, b));

        Assert.Equal(a, b);                                   // deterministic
        Assert.NotEqual(identity, a);                         // actually blinded
        Assert.True(Ed25519Point.TryDecode(a, out _));        // still a valid curve point
    }

    [Fact]
    public void BlindedKey_Changes_With_Period()
    {
        byte[] identity = Identity(2);
        var p1 = new byte[32];
        var p2 = new byte[32];
        HsBlinding.TryBlindPublicKey(identity, 100, HsTimePeriod.DefaultLengthMinutes, p1);
        HsBlinding.TryBlindPublicKey(identity, 101, HsTimePeriod.DefaultLengthMinutes, p2);
        Assert.NotEqual(p1, p2);
    }

    [Fact]
    public void Subcredential_Is_Deterministic_And_Depends_On_BlindedKey()
    {
        byte[] identity = Identity(3);
        var blinded1 = new byte[32];
        var blinded2 = new byte[32];
        HsBlinding.TryBlindPublicKey(identity, 200, HsTimePeriod.DefaultLengthMinutes, blinded1);
        HsBlinding.TryBlindPublicKey(identity, 201, HsTimePeriod.DefaultLengthMinutes, blinded2);

        byte[] sub1a = HsBlinding.Subcredential(identity, blinded1);
        byte[] sub1b = HsBlinding.Subcredential(identity, blinded1);
        byte[] sub2 = HsBlinding.Subcredential(identity, blinded2);

        Assert.Equal(32, sub1a.Length);
        Assert.Equal(sub1a, sub1b);      // deterministic
        Assert.NotEqual(sub1a, sub2);    // depends on the (period-specific) blinded key
    }

    [Fact]
    public void Blinding_Rejects_Invalid_Identity()
    {
        var notAPoint = new byte[32];
        Array.Fill(notAPoint, (byte)0xFF);
        var outb = new byte[32];
        Assert.False(HsBlinding.TryBlindPublicKey(notAPoint, 1, HsTimePeriod.DefaultLengthMinutes, outb));
    }
}
