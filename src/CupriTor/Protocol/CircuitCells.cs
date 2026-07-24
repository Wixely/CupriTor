using System.Buffers.Binary;
using System.Net;

namespace CupriTor.Protocol;

/// <summary>Circuit handshake types (tor-spec §5.1).</summary>
internal enum HandshakeType : ushort
{
    Ntor = 0x0002,
    NtorV3 = 0x0003,
}

/// <summary>A CREATE2 cell payload: handshake type + handshake data (tor-spec §5.1).</summary>
internal readonly struct Create2Payload(HandshakeType type, ReadOnlyMemory<byte> data)
{
    public HandshakeType Type { get; } = type;
    public ReadOnlyMemory<byte> Data { get; } = data;

    public byte[] Encode()
    {
        var buffer = new byte[4 + Data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0), (ushort)Type);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), (ushort)Data.Length);
        Data.Span.CopyTo(buffer.AsSpan(4));
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out Create2Payload result)
    {
        result = default;
        if (payload.Length < 4) return false;
        var type = (HandshakeType)BinaryPrimitives.ReadUInt16BigEndian(payload);
        int len = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(2, 2));
        if (payload.Length < 4 + len) return false;
        result = new Create2Payload(type, payload.Slice(4, len).ToArray());
        return true;
    }
}

/// <summary>A CREATED2 / EXTENDED2 cell payload: a length-prefixed handshake reply (tor-spec §5.1).</summary>
internal readonly struct Created2Payload(ReadOnlyMemory<byte> data)
{
    public ReadOnlyMemory<byte> Data { get; } = data;

    public byte[] Encode()
    {
        var buffer = new byte[2 + Data.Length];
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0), (ushort)Data.Length);
        Data.Span.CopyTo(buffer.AsSpan(2));
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out Created2Payload result)
    {
        result = default;
        if (payload.Length < 2) return false;
        int len = BinaryPrimitives.ReadUInt16BigEndian(payload);
        if (payload.Length < 2 + len) return false;
        result = new Created2Payload(payload.Slice(2, len).ToArray());
        return true;
    }
}

/// <summary>A link specifier identifying a relay for EXTEND2 (tor-spec §5.1.2).</summary>
internal readonly struct LinkSpecifier(byte type, ReadOnlyMemory<byte> data)
{
    public const byte TypeTlsIPv4 = 0x00;
    public const byte TypeTlsIPv6 = 0x01;
    public const byte TypeLegacyId = 0x02;   // 20-byte RSA identity digest
    public const byte TypeEd25519Id = 0x03;  // 32-byte Ed25519 identity

    public byte Type { get; } = type;
    public ReadOnlyMemory<byte> Data { get; } = data;

    public int EncodedSize => 2 + Data.Length;

    public static LinkSpecifier FromIPv4(IPAddress address, ushort port)
    {
        byte[] ip = address.GetAddressBytes();
        var data = new byte[6];
        ip.AsSpan(0, 4).CopyTo(data);
        BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(4), port);
        return new LinkSpecifier(TypeTlsIPv4, data);
    }

    public static LinkSpecifier FromLegacyId(ReadOnlyMemory<byte> rsaIdentityDigest) => new(TypeLegacyId, rsaIdentityDigest);
    public static LinkSpecifier FromEd25519Id(ReadOnlyMemory<byte> ed25519Identity) => new(TypeEd25519Id, ed25519Identity);

    public int WriteTo(Span<byte> dest)
    {
        dest[0] = Type;
        dest[1] = (byte)Data.Length;
        Data.Span.CopyTo(dest.Slice(2));
        return EncodedSize;
    }

    /// <summary>Parse a serialized link-specifier list (NSPEC ‖ [type,len,data]…), e.g. from a descriptor intro point.</summary>
    public static bool TryParseList(ReadOnlySpan<byte> blob, out List<LinkSpecifier> specifiers)
    {
        specifiers = new List<LinkSpecifier>();
        if (blob.Length < 1) return false;
        int n = blob[0];
        int pos = 1;
        for (int i = 0; i < n; i++)
        {
            if (pos + 2 > blob.Length) return false;
            byte type = blob[pos];
            int len = blob[pos + 1];
            pos += 2;
            if (pos + len > blob.Length) return false;
            specifiers.Add(new LinkSpecifier(type, blob.Slice(pos, len).ToArray()));
            pos += len;
        }
        return true;
    }

    /// <summary>Serialize a link-specifier list as NSPEC ‖ [type,len,data]… (the INTRODUCE1 onion-key/link-spec form).</summary>
    public static byte[] EncodeList(IReadOnlyList<LinkSpecifier> specifiers)
    {
        int size = 1;
        foreach (LinkSpecifier s in specifiers) size += s.EncodedSize;
        var buffer = new byte[size];
        buffer[0] = (byte)specifiers.Count;
        int pos = 1;
        foreach (LinkSpecifier s in specifiers) pos += s.WriteTo(buffer.AsSpan(pos));
        return buffer;
    }

    /// <summary>The 20-byte legacy (RSA) identity from a link-specifier list, or null if absent — used as the ntor node id.</summary>
    public static byte[]? FindLegacyId(IReadOnlyList<LinkSpecifier> specifiers)
    {
        foreach (LinkSpecifier s in specifiers)
            if (s.Type == TypeLegacyId && s.Data.Length == 20) return s.Data.ToArray();
        return null;
    }
}

/// <summary>An EXTEND2 relay-cell payload: link specifiers + a CREATE2-style handshake (tor-spec §5.1.2).</summary>
internal readonly struct Extend2Payload(IReadOnlyList<LinkSpecifier> specifiers, HandshakeType type, ReadOnlyMemory<byte> data)
{
    public IReadOnlyList<LinkSpecifier> Specifiers { get; } = specifiers;
    public HandshakeType Type { get; } = type;
    public ReadOnlyMemory<byte> Data { get; } = data;

    public byte[] Encode()
    {
        int size = 1;
        foreach (LinkSpecifier s in Specifiers) size += s.EncodedSize;
        size += 4 + Data.Length;

        var buffer = new byte[size];
        int pos = 0;
        buffer[pos++] = (byte)Specifiers.Count;
        foreach (LinkSpecifier s in Specifiers) pos += s.WriteTo(buffer.AsSpan(pos));
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(pos), (ushort)Type); pos += 2;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(pos), (ushort)Data.Length); pos += 2;
        Data.Span.CopyTo(buffer.AsSpan(pos));
        return buffer;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out Extend2Payload result)
    {
        result = default;
        if (payload.Length < 1) return false;
        int nspec = payload[0];
        int pos = 1;

        var specs = new List<LinkSpecifier>(nspec);
        for (int i = 0; i < nspec; i++)
        {
            if (pos + 2 > payload.Length) return false;
            byte type = payload[pos];
            int len = payload[pos + 1];
            pos += 2;
            if (pos + len > payload.Length) return false;
            specs.Add(new LinkSpecifier(type, payload.Slice(pos, len).ToArray()));
            pos += len;
        }

        if (pos + 4 > payload.Length) return false;
        var htype = (HandshakeType)BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(pos, 2)); pos += 2;
        int hlen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(pos, 2)); pos += 2;
        if (pos + hlen > payload.Length) return false;

        result = new Extend2Payload(specs, htype, payload.Slice(pos, hlen).ToArray());
        return true;
    }
}
