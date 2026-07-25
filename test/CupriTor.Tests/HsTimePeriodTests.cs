using CupriTor.OnionService;
using Xunit;

namespace CupriTor.Tests;

public class HsTimePeriodTests
{
    // rend-spec-v3 §2.2.4: the shared-random "day" turns over at 00:00 UTC, the time period at 12:00 UTC.
    // "Between new SRV and new TP" = [00:00, 12:00) (morning) → IsBetweenTpAndSrv == false.
    // "Between new TP and new SRV" = [12:00, 24:00) (afternoon) → IsBetweenTpAndSrv == true.
    [Theory]
    [InlineData(0, 0, false)]    // 00:00 — just after SRV publication
    [InlineData(6, 0, false)]    // 06:00 — morning
    [InlineData(11, 59, false)]  // 11:59 — just before TP rotation
    [InlineData(12, 0, true)]    // 12:00 — TP rotation
    [InlineData(18, 0, true)]    // 18:00 — afternoon
    [InlineData(23, 59, true)]   // 23:59 — just before the next SRV
    public void IsBetweenTpAndSrv_Splits_The_Day_At_Noon_Utc(int hour, int minute, bool expected)
    {
        var validAfter = new DateTimeOffset(2026, 7, 25, hour, minute, 0, TimeSpan.Zero);
        Assert.Equal(expected, HsTimePeriod.IsBetweenTpAndSrv(validAfter));
    }

    [Fact]
    public void Time_Period_Number_Rotates_At_Noon_Utc()
    {
        // 11:59 UTC and 12:01 UTC on the same day fall in adjacent time periods (rotation at 12:00).
        long before = HsTimePeriod.Number(new DateTimeOffset(2026, 7, 25, 11, 59, 0, TimeSpan.Zero));
        long after = HsTimePeriod.Number(new DateTimeOffset(2026, 7, 25, 12, 1, 0, TimeSpan.Zero));
        Assert.Equal(before + 1, after);
    }
}
