using System.Buffers.Binary;

namespace CupriTor.Protocol;

/// <summary>VERSIONS cell payload (tor-spec §4.1): a sequence of 2-byte link-protocol versions.</summary>
internal static class VersionsCell
{
    public static byte[] Build(params ushort[] versions)
    {
        var payload = new byte[versions.Length * 2];
        for (int i = 0; i < versions.Length; i++)
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(i * 2), versions[i]);
        return payload;
    }

    public static bool TryParse(ReadOnlySpan<byte> payload, out ushort[] versions)
    {
        versions = Array.Empty<ushort>();
        if ((payload.Length & 1) != 0) return false; // must be an even number of bytes
        var result = new ushort[payload.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(i * 2, 2));
        versions = result;
        return true;
    }

    /// <summary>The highest version present in both lists, or null if there is no overlap.</summary>
    public static ushort? HighestCommon(ReadOnlySpan<ushort> ours, ReadOnlySpan<ushort> theirs)
    {
        ushort best = 0;
        foreach (ushort o in ours)
            foreach (ushort t in theirs)
                if (o == t && o > best) best = o;
        return best == 0 ? null : best;
    }
}

/// <summary>CERTS cell payload (tor-spec §4.2): a count followed by (type, length, bytes) certificates.</summary>
internal sealed class CertsCell
{
    public readonly record struct Entry(byte CertType, ReadOnlyMemory<byte> Cert);

    public IReadOnlyList<Entry> Certs { get; private init; } = Array.Empty<Entry>();

    /// <summary>First certificate with the given type, or null.</summary>
    public ReadOnlyMemory<byte>? Find(byte certType)
    {
        foreach (Entry e in Certs)
            if (e.CertType == certType) return e.Cert;
        return null;
    }

    public static byte[] Build(IReadOnlyList<Entry> certs)
    {
        if (certs.Count > 255) throw new ArgumentException("A CERTS cell holds at most 255 certificates.", nameof(certs));
        int size = 1;
        foreach (Entry e in certs) size += 3 + e.Cert.Length;

        var payload = new byte[size];
        payload[0] = (byte)certs.Count;
        int pos = 1;
        foreach (Entry e in certs)
        {
            payload[pos] = e.CertType;
            BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(pos + 1, 2), (ushort)e.Cert.Length);
            e.Cert.Span.CopyTo(payload.AsSpan(pos + 3));
            pos += 3 + e.Cert.Length;
        }
        return payload;
    }

    public static bool TryParse(ReadOnlyMemory<byte> payload, out CertsCell cell)
    {
        cell = null!;
        ReadOnlySpan<byte> s = payload.Span;
        if (s.Length < 1) return false;

        int n = s[0];
        int pos = 1;
        var entries = new List<Entry>(n);
        for (int i = 0; i < n; i++)
        {
            if (pos + 3 > s.Length) return false;
            byte certType = s[pos];
            int len = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(pos + 1, 2));
            pos += 3;
            if (pos + len > s.Length) return false;
            entries.Add(new Entry(certType, payload.Slice(pos, len)));
            pos += len;
        }
        cell = new CertsCell { Certs = entries };
        return true;
    }
}

/// <summary>AUTH_CHALLENGE cell payload (tor-spec §4.3): a 32-byte challenge and a list of 2-byte methods.</summary>
internal sealed class AuthChallengeCell
{
    public ReadOnlyMemory<byte> Challenge { get; private init; }
    public ushort[] Methods { get; private init; } = Array.Empty<ushort>();

    public static bool TryParse(ReadOnlyMemory<byte> payload, out AuthChallengeCell cell)
    {
        cell = null!;
        ReadOnlySpan<byte> s = payload.Span;
        if (s.Length < 34) return false; // 32-byte challenge + 2-byte count

        int n = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(32, 2));
        if (s.Length < 34 + n * 2) return false;

        var methods = new ushort[n];
        for (int i = 0; i < n; i++)
            methods[i] = BinaryPrimitives.ReadUInt16BigEndian(s.Slice(34 + i * 2, 2));

        cell = new AuthChallengeCell { Challenge = payload.Slice(0, 32), Methods = methods };
        return true;
    }
}

/// <summary>
/// NETINFO cell payload (tor-spec §4.5): a timestamp, the recipient's address as seen by the sender,
/// and the sender's own addresses. This is a fixed-length cell, so a parsed payload may have trailing padding.
/// </summary>
internal sealed class NetInfoCell
{
    public uint Timestamp { get; private init; }
    public TorAddress OtherAddress { get; private init; }
    public IReadOnlyList<TorAddress> MyAddresses { get; private init; } = Array.Empty<TorAddress>();

    public static byte[] Build(uint timestamp, TorAddress otherAddress, IReadOnlyList<TorAddress> myAddresses)
    {
        if (myAddresses.Count > 255) throw new ArgumentException("At most 255 addresses.", nameof(myAddresses));
        int size = 4 + otherAddress.EncodedSize + 1;
        foreach (TorAddress a in myAddresses) size += a.EncodedSize;

        var payload = new byte[size];
        BinaryPrimitives.WriteUInt32BigEndian(payload, timestamp);
        int pos = 4;
        pos += otherAddress.Write(payload.AsSpan(pos));
        payload[pos++] = (byte)myAddresses.Count;
        foreach (TorAddress a in myAddresses)
            pos += a.Write(payload.AsSpan(pos));
        return payload;
    }

    public static bool TryParse(ReadOnlyMemory<byte> payload, out NetInfoCell cell)
    {
        cell = null!;
        ReadOnlySpan<byte> s = payload.Span;
        if (s.Length < 5) return false;

        uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(s);
        int pos = 4;
        if (!TorAddress.TryRead(s.Slice(pos), out TorAddress other, out int c)) return false;
        pos += c;

        if (pos >= s.Length) return false;
        int n = s[pos++];
        var mine = new List<TorAddress>(n);
        for (int i = 0; i < n; i++)
        {
            if (!TorAddress.TryRead(s.Slice(pos), out TorAddress a, out int ac)) return false;
            pos += ac;
            mine.Add(a);
        }

        cell = new NetInfoCell { Timestamp = timestamp, OtherAddress = other, MyAddresses = mine };
        return true;
    }
}
