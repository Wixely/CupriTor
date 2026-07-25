using System.IO.Pipelines;

namespace CupriTor.AspNetCore;

/// <summary>Adapts a duplex <see cref="Stream"/> (the onion stream) to the <see cref="IDuplexPipe"/> Kestrel reads and writes.</summary>
internal sealed class DuplexStreamPipe : IDuplexPipe
{
    public DuplexStreamPipe(Stream stream)
    {
        // leaveOpen: the ConnectionContext owns the stream's lifetime and disposes it (→ RELAY_END) itself.
        Input = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true));
        Output = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
    }

    public PipeReader Input { get; }
    public PipeWriter Output { get; }
}
