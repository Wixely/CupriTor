using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CupriTor.Protocol;

/// <summary>A source of uniform random integers, abstracted so path selection can be made deterministic in tests.</summary>
internal interface IRandomSource
{
    /// <summary>Uniformly random value in [0, exclusiveMax).</summary>
    ulong NextBelow(ulong exclusiveMax);
}

/// <summary>Cryptographically secure <see cref="IRandomSource"/> (rejection-sampled from the OS CSPRNG).</summary>
internal sealed class SecureRandomSource : IRandomSource
{
    public static SecureRandomSource Instance { get; } = new();

    public ulong NextBelow(ulong exclusiveMax)
    {
        ArgumentOutOfRangeException.ThrowIfZero(exclusiveMax);
        ulong limit = ulong.MaxValue - (ulong.MaxValue % exclusiveMax);
        Span<byte> b = stackalloc byte[8];
        while (true)
        {
            RandomNumberGenerator.Fill(b);
            ulong r = BinaryPrimitives.ReadUInt64LittleEndian(b);
            if (r < limit) return r % exclusiveMax;
        }
    }
}
