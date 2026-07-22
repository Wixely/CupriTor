using System.Buffers.Binary;

namespace CupriTor.Protocol;

/// <summary>Relay-cell commands carried inside the RELAY/RELAY_EARLY cell body (tor-spec §6.1).</summary>
internal enum RelayCommand : byte
{
    Begin = 1,
    Data = 2,
    End = 3,
    Connected = 4,
    Sendme = 5,
    Extend = 6,
    Extended = 7,
    Truncate = 8,
    Truncated = 9,
    Drop = 10,
    Resolve = 11,
    Resolved = 12,
    BeginDir = 13,
    Extend2 = 14,
    Extended2 = 15,
}

/// <summary>
/// The plaintext body of a RELAY cell (tor-spec §6.1): a relay command, the "recognized" field and
/// integrity digest (both managed by <see cref="RelayCrypto"/>), a stream id, and up to 498 bytes of
/// data. Encoding leaves recognized/digest zeroed for the crypto layer to fill.
/// </summary>
internal readonly struct RelayCell
{
    public const int CellLength = 509;
    public const int HeaderLength = 11;
    public const int MaxDataLength = CellLength - HeaderLength; // 498
    public const int RecognizedOffset = 1;
    public const int DigestOffset = 5;

    public RelayCommand Command { get; }
    public ushort StreamId { get; }
    public ReadOnlyMemory<byte> Data { get; }

    public RelayCell(RelayCommand command, ushort streamId, ReadOnlyMemory<byte> data)
    {
        if (data.Length > MaxDataLength)
            throw new ArgumentException($"Relay cell data exceeds {MaxDataLength} bytes.", nameof(data));
        Command = command;
        StreamId = streamId;
        Data = data;
    }

    /// <summary>Encode into a 509-byte buffer with recognized and digest left zeroed.</summary>
    public void EncodeTo(Span<byte> cell)
    {
        if (cell.Length != CellLength)
            throw new ArgumentException($"Buffer must be {CellLength} bytes.", nameof(cell));
        ReadOnlySpan<byte> data = Data.Span;

        cell.Clear();
        cell[0] = (byte)Command;
        // recognized (1..3) stays zero
        BinaryPrimitives.WriteUInt16BigEndian(cell.Slice(3, 2), StreamId);
        // digest (5..9) stays zero
        BinaryPrimitives.WriteUInt16BigEndian(cell.Slice(9, 2), (ushort)data.Length);
        data.CopyTo(cell.Slice(HeaderLength));
    }

    /// <summary>Parse a decrypted RELAY cell. Returns false if it is not recognized (recognized != 0) or malformed.</summary>
    public static bool TryParse(ReadOnlySpan<byte> cell, out RelayCell relayCell)
    {
        relayCell = default;
        if (cell.Length != CellLength) return false;
        if (cell[RecognizedOffset] != 0 || cell[RecognizedOffset + 1] != 0) return false; // not for us

        int length = BinaryPrimitives.ReadUInt16BigEndian(cell.Slice(9, 2));
        if (length > MaxDataLength) return false;

        var command = (RelayCommand)cell[0];
        ushort streamId = BinaryPrimitives.ReadUInt16BigEndian(cell.Slice(3, 2));
        byte[] data = cell.Slice(HeaderLength, length).ToArray();
        relayCell = new RelayCell(command, streamId, data);
        return true;
    }
}
