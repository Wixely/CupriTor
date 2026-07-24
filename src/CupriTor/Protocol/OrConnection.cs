using System.Net;
using CupriTor.Transport;

namespace CupriTor.Protocol;

/// <summary>
/// An established OR connection to a relay: an <see cref="ITlsTransport"/> TLS session with the Tor link
/// handshake completed (VERSIONS + CERTS chain validated + NETINFO exchanged). Owns the TLS connection
/// and exposes the negotiated <see cref="CellCodec"/> and duplex stream so circuits can be created over it.
/// </summary>
internal sealed class OrConnection : IAsyncDisposable
{
    private readonly ITlsConnection _tls;

    public Stream Stream => _tls.Stream;
    public CellCodec Codec { get; }
    public LinkHandshakeResult Link { get; }

    private OrConnection(ITlsConnection tls, CellCodec codec, LinkHandshakeResult link)
    {
        _tls = tls;
        Codec = codec;
        Link = link;
    }

    /// <summary>Connect, run the link handshake, and (optionally) pin the relay's expected Ed25519 identity.</summary>
    public static async Task<OrConnection> EstablishAsync(
        ITlsTransport transport,
        string host,
        int port,
        DateTimeOffset now,
        ReadOnlyMemory<byte>? expectedEd25519Identity = null,
        IPAddress? peerAddress = null,
        CancellationToken ct = default)
    {
        ITlsConnection tls = await transport.ConnectAsync(host, port, ct).ConfigureAwait(false);
        try
        {
            LinkHandshakeResult link = await LinkHandshake.PerformClientAsync(
                tls.Stream, tls.PeerCertificateDer, now,
                expectedEd25519Identity: expectedEd25519Identity,
                peerAddress: peerAddress,
                ct: ct).ConfigureAwait(false);

            var codec = new CellCodec(link.LinkVersion >= 4 ? 4 : 2);
            return new OrConnection(tls, codec, link);
        }
        catch
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Create a new circuit over this connection with the given circuit id (client-chosen, high bit set).</summary>
    public Circuit CreateCircuit(uint circuitId) => new(Stream, Codec, circuitId);

    public ValueTask DisposeAsync() => _tls.DisposeAsync();
}
