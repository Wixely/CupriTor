using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace CupriTor.Protocol;

/// <summary>RELAY_END reason codes (tor-spec §6.3).</summary>
internal enum RelayEndReason : byte
{
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

/// <summary>Flags for a RELAY_BEGIN cell (tor-spec §6.2).</summary>
[Flags]
internal enum RelayBeginFlags : uint
{
    None = 0,
    IPv6Okay = 1,
    IPv4NotOkay = 2,
    IPv6Preferred = 4,
}

/// <summary>RELAY_BEGIN payload: a nul-terminated "address:port" plus 4 flag bytes (tor-spec §6.2).</summary>
internal readonly struct RelayBeginPayload(string target, RelayBeginFlags flags = RelayBeginFlags.None)
{
    public string Target { get; } = target;
    public RelayBeginFlags Flags { get; } = flags;

    public byte[] Encode()
    {
        byte[] addr = Encoding.ASCII.GetBytes(Target);
        var buffer = new byte[addr.Length + 1 + 4];
        addr.CopyTo(buffer, 0);
        buffer[addr.Length] = 0; // nul terminator
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(addr.Length + 1), (uint)Flags);
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out RelayBeginPayload result)
    {
        result = default;
        int nul = payload.IndexOf((byte)0);
        if (nul < 0) return false;
        string target = Encoding.ASCII.GetString(payload.Slice(0, nul));
        uint flags = payload.Length >= nul + 5 ? BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(nul + 1, 4)) : 0;
        result = new RelayBeginPayload(target, (RelayBeginFlags)flags);
        return true;
    }
}

/// <summary>
/// RELAY_CONNECTED payload (tor-spec §6.2): empty for onion-service / BEGIN_DIR streams, or an IPv4
/// address plus TTL for clearnet connections.
/// </summary>
internal readonly struct RelayConnectedPayload(IPAddress? address, uint ttl)
{
    public IPAddress? Address { get; } = address;
    public uint Ttl { get; } = ttl;

    public byte[] Encode()
    {
        if (Address is null) return Array.Empty<byte>();
        if (Address.AddressFamily != AddressFamily.InterNetwork)
            throw new NotSupportedException("Only empty or IPv4 RELAY_CONNECTED payloads are supported.");
        var buffer = new byte[8];
        Address.GetAddressBytes().CopyTo(buffer, 0);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(4), Ttl);
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out RelayConnectedPayload result)
    {
        if (payload.Length == 0)
        {
            result = new RelayConnectedPayload(null, 0);
            return true;
        }
        if (payload.Length >= 8)
        {
            var addr = new IPAddress(payload.Slice(0, 4));
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(4, 4));
            result = new RelayConnectedPayload(addr, ttl);
            return true;
        }
        result = default;
        return false;
    }
}

/// <summary>RELAY_END payload: a single reason byte (tor-spec §6.3).</summary>
internal readonly struct RelayEndPayload(RelayEndReason reason)
{
    public RelayEndReason Reason { get; } = reason;

    public byte[] Encode() => new[] { (byte)Reason };

    public static bool TryParse(ReadOnlySpan<byte> payload, out RelayEndPayload result)
    {
        if (payload.Length < 1) { result = default; return false; }
        result = new RelayEndPayload((RelayEndReason)payload[0]);
        return true;
    }
}

/// <summary>
/// RELAY_SENDME payload (tor-spec §7.3): version 0 is empty (legacy); version 1 carries the digest of
/// the data being acknowledged for authenticated flow control.
/// </summary>
internal readonly struct RelaySendmePayload(byte version, ReadOnlyMemory<byte> data)
{
    public byte Version { get; } = version;
    public ReadOnlyMemory<byte> Data { get; } = data;

    public static RelaySendmePayload Legacy() => new(0, ReadOnlyMemory<byte>.Empty);

    public byte[] Encode()
    {
        if (Version == 0) return Array.Empty<byte>();
        var buffer = new byte[3 + Data.Length];
        buffer[0] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(1), (ushort)Data.Length);
        Data.Span.CopyTo(buffer.AsSpan(3));
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out RelaySendmePayload result)
    {
        if (payload.Length == 0)
        {
            result = new RelaySendmePayload(0, ReadOnlyMemory<byte>.Empty);
            return true;
        }
        if (payload.Length < 3) { result = default; return false; }
        byte version = payload[0];
        int len = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(1, 2));
        if (payload.Length < 3 + len) { result = default; return false; }
        result = new RelaySendmePayload(version, payload.Slice(3, len).ToArray());
        return true;
    }
}
