using System.Net;

namespace CupriTor.Protocol;

/// <summary>
/// The type/length/value address encoding used in NETINFO cells (tor-spec §6.4): a 1-byte type,
/// 1-byte length, then the raw address bytes. Only IPv4 (type 4) and IPv6 (type 6) are used here.
/// </summary>
internal readonly struct TorAddress
{
    public const byte TypeIPv4 = 0x04;
    public const byte TypeIPv6 = 0x06;

    public byte Type { get; }
    public ReadOnlyMemory<byte> Value { get; }

    public TorAddress(byte type, ReadOnlyMemory<byte> value)
    {
        Type = type;
        Value = value;
    }

    public int EncodedSize => 2 + Value.Length;

    public static TorAddress FromIP(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        byte type = bytes.Length == 4 ? TypeIPv4 : TypeIPv6;
        return new TorAddress(type, bytes);
    }

    /// <summary>Convert to an <see cref="IPAddress"/>, or null if this isn't a well-formed IPv4/IPv6 address.</summary>
    public IPAddress? ToIPAddress()
    {
        if (Type == TypeIPv4 && Value.Length == 4) return new IPAddress(Value.Span);
        if (Type == TypeIPv6 && Value.Length == 16) return new IPAddress(Value.Span);
        return null;
    }

    public int Write(Span<byte> dest)
    {
        dest[0] = Type;
        dest[1] = (byte)Value.Length;
        Value.Span.CopyTo(dest.Slice(2));
        return EncodedSize;
    }

    public static bool TryRead(ReadOnlySpan<byte> src, out TorAddress address, out int consumed)
    {
        address = default;
        consumed = 0;
        if (src.Length < 2) return false;
        int len = src[1];
        if (src.Length < 2 + len) return false;
        address = new TorAddress(src[0], src.Slice(2, len).ToArray());
        consumed = 2 + len;
        return true;
    }
}
