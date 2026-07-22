namespace CupriTor.Transport;

/// <summary>
/// An established TLS connection to a relay's OR port: a duplex byte stream plus the peer's
/// certificate (needed to bind the Tor link certificate to the TLS session).
/// </summary>
public interface ITlsConnection : IAsyncDisposable
{
    /// <summary>The encrypted duplex stream carrying Tor cells.</summary>
    Stream Stream { get; }

    /// <summary>The DER-encoded X.509 certificate the relay presented during the TLS handshake.</summary>
    ReadOnlyMemory<byte> PeerCertificateDer { get; }
}

/// <summary>
/// Opens TLS connections to relay OR ports. This is the seam that lets the transport be swapped:
/// the intended default is a 100%-managed TLS client (BouncyCastle), with an OS-backed
/// <c>SslStream</c> implementation available for A/B comparison. Tor does not trust the TLS PKI —
/// the relay is authenticated by the link certificate chain carried inside the connection — so the
/// transport only has to establish an encrypted stream and surface the peer certificate.
/// </summary>
public interface ITlsTransport
{
    /// <summary>Connect to <paramref name="host"/>:<paramref name="port"/> and complete a TLS handshake.</summary>
    Task<ITlsConnection> ConnectAsync(string host, int port, CancellationToken ct = default);
}
