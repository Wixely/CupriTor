namespace CupriTor.Protocol;

/// <summary>Tor cell command codes (tor-spec §3). Commands 7 and >= 128 are variable-length.</summary>
internal enum CellCommand : byte
{
    Padding = 0,
    Create = 1,
    Created = 2,
    Relay = 3,
    Destroy = 4,
    CreateFast = 5,
    CreatedFast = 6,
    Versions = 7,
    Netinfo = 8,
    RelayEarly = 9,
    Create2 = 10,
    Created2 = 11,
    PaddingNegotiate = 12,
    VPadding = 128,
    Certs = 129,
    AuthChallenge = 130,
    Authenticate = 131,
    Authorize = 132,
}

/// <summary>
/// A single Tor cell: a circuit id, a command, and a payload. For fixed-length cells the payload is
/// the full 509-byte body; for variable-length cells it is exactly the cell's declared length.
/// </summary>
internal readonly struct Cell
{
    public uint CircId { get; }
    public CellCommand Command { get; }
    public ReadOnlyMemory<byte> Payload { get; }

    public Cell(uint circId, CellCommand command, ReadOnlyMemory<byte> payload)
    {
        CircId = circId;
        Command = command;
        Payload = payload;
    }

    public bool IsVariableLength => IsVariable(Command);

    /// <summary>Variable-length commands are VERSIONS (7) and everything from 128 up.</summary>
    public static bool IsVariable(CellCommand command) => command == CellCommand.Versions || (byte)command >= 128;
}
