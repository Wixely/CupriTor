using System.Buffers.Binary;

namespace CupriTor.Protocol;

/// <summary>
/// Encodes and decodes Tor cells on the wire (tor-spec §3). A codec is bound to a circuit-id width:
/// 2 bytes for link protocol versions 1–3, 4 bytes for v4+. The VERSIONS cell is always framed with a
/// 2-byte circuit id regardless of the negotiated width, so it is special-cased on encode.
/// </summary>
internal sealed class CellCodec
{
    /// <summary>Payload size of a fixed-length cell.</summary>
    public const int FixedPayloadLength = 509;

    /// <summary>Maximum payload of a variable-length cell (2-byte length field).</summary>
    public const int MaxVariablePayloadLength = ushort.MaxValue;

    /// <summary>Circuit-id width in bytes (2 or 4).</summary>
    public int CircIdLength { get; }

    public CellCodec(int circIdLength)
    {
        if (circIdLength is not (2 or 4))
            throw new ArgumentOutOfRangeException(nameof(circIdLength), "Circuit id width must be 2 or 4 bytes.");
        CircIdLength = circIdLength;
    }

    /// <summary>The 2-byte codec used for the initial VERSIONS exchange.</summary>
    public static CellCodec Initial { get; } = new(2);

    private static int CircIdLenFor(CellCommand command, int width) =>
        command == CellCommand.Versions ? 2 : width;

    /// <summary>Exact number of bytes <see cref="Encode"/> will write for this cell.</summary>
    public int EncodedSize(in Cell cell)
    {
        int idLen = CircIdLenFor(cell.Command, CircIdLength);
        return cell.IsVariableLength
            ? idLen + 1 + 2 + cell.Payload.Length
            : idLen + 1 + FixedPayloadLength;
    }

    /// <summary>Encode a cell into <paramref name="dest"/>; returns the number of bytes written.</summary>
    public int Encode(in Cell cell, Span<byte> dest)
    {
        int idLen = CircIdLenFor(cell.Command, CircIdLength);
        ReadOnlySpan<byte> payload = cell.Payload.Span;

        if (cell.IsVariableLength)
        {
            if (payload.Length > MaxVariablePayloadLength)
                throw new ArgumentException("Variable-length cell payload exceeds 65535 bytes.", nameof(cell));
        }
        else if (payload.Length > FixedPayloadLength)
        {
            throw new ArgumentException($"Fixed-length cell payload exceeds {FixedPayloadLength} bytes.", nameof(cell));
        }

        int total = EncodedSize(cell);
        if (dest.Length < total)
            throw new ArgumentException("Destination buffer too small.", nameof(dest));

        WriteCircId(dest, idLen, cell.CircId);
        dest[idLen] = (byte)cell.Command;
        int pos = idLen + 1;

        if (cell.IsVariableLength)
        {
            BinaryPrimitives.WriteUInt16BigEndian(dest.Slice(pos, 2), (ushort)payload.Length);
            pos += 2;
            payload.CopyTo(dest.Slice(pos));
            pos += payload.Length;
        }
        else
        {
            payload.CopyTo(dest.Slice(pos));
            dest.Slice(pos + payload.Length, FixedPayloadLength - payload.Length).Clear();
            pos += FixedPayloadLength;
        }

        return pos;
    }

    /// <summary>
    /// Try to decode a single cell from the front of <paramref name="src"/>. On success, <paramref name="consumed"/>
    /// is the number of bytes the cell occupied. Returns false if <paramref name="src"/> does not yet hold a full cell.
    /// </summary>
    public bool TryDecode(ReadOnlySpan<byte> src, out Cell cell, out int consumed)
    {
        cell = default;
        consumed = 0;

        int idLen = CircIdLength;
        if (src.Length < idLen + 1) return false;

        var command = (CellCommand)src[idLen];
        int pos = idLen + 1;

        ReadOnlySpan<byte> payload;
        if (Cell.IsVariable(command))
        {
            if (src.Length < pos + 2) return false;
            int len = BinaryPrimitives.ReadUInt16BigEndian(src.Slice(pos, 2));
            pos += 2;
            if (src.Length < pos + len) return false;
            payload = src.Slice(pos, len);
            pos += len;
        }
        else
        {
            if (src.Length < pos + FixedPayloadLength) return false;
            payload = src.Slice(pos, FixedPayloadLength);
            pos += FixedPayloadLength;
        }

        cell = new Cell(ReadCircId(src, idLen), command, payload.ToArray());
        consumed = pos;
        return true;
    }

    /// <summary>Write a cell to a stream.</summary>
    public async ValueTask WriteAsync(Stream stream, Cell cell, CancellationToken ct = default)
    {
        byte[] buffer = new byte[EncodedSize(cell)];
        int n = Encode(cell, buffer);
        await stream.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
    }

    /// <summary>Read exactly one cell from a stream. Throws <see cref="EndOfStreamException"/> if the stream ends mid-cell.</summary>
    public async ValueTask<Cell> ReadAsync(Stream stream, CancellationToken ct = default)
    {
        int idLen = CircIdLength;
        byte[] header = new byte[idLen + 1];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);

        uint circId = ReadCircId(header, idLen);
        var command = (CellCommand)header[idLen];

        byte[] payload;
        if (Cell.IsVariable(command))
        {
            byte[] lenBuf = new byte[2];
            await stream.ReadExactlyAsync(lenBuf, ct).ConfigureAwait(false);
            int len = BinaryPrimitives.ReadUInt16BigEndian(lenBuf);
            payload = new byte[len];
            if (len > 0)
                await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
        }
        else
        {
            payload = new byte[FixedPayloadLength];
            await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
        }

        return new Cell(circId, command, payload);
    }

    private static void WriteCircId(Span<byte> dest, int idLen, uint circId)
    {
        if (idLen == 2)
            BinaryPrimitives.WriteUInt16BigEndian(dest, (ushort)circId);
        else
            BinaryPrimitives.WriteUInt32BigEndian(dest, circId);
    }

    private static uint ReadCircId(ReadOnlySpan<byte> src, int idLen) =>
        idLen == 2 ? BinaryPrimitives.ReadUInt16BigEndian(src) : BinaryPrimitives.ReadUInt32BigEndian(src);
}
