using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace CupriTor.Transport;

/// <summary>
/// OS-backed TLS transport using <see cref="SslStream"/>. Serves as the A/B baseline against the
/// managed BouncyCastle transport (the intended default). Server certificate validation is
/// deliberately accept-all: Tor authenticates the relay via the in-band link certificate chain,
/// not via the web PKI, so trusting the TLS certificate here would be meaningless.
/// </summary>
public sealed class SslStreamTlsTransport : ITlsTransport
{
    /// <inheritdoc/>
    public async Task<ITlsConnection> ConnectAsync(string host, int port, CancellationToken ct = default)
    {
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

            byte[]? peerCertDer = null;
            var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false,
                userCertificateValidationCallback: (_, cert, _, _) =>
                {
                    peerCertDer = cert?.GetRawCertData();
                    return true; // Tor does not use the web PKI; the relay is authenticated in-band.
                });

            var options = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                RemoteCertificateValidationCallback = (_, cert, _, _) =>
                {
                    peerCertDer = cert?.GetRawCertData();
                    return true;
                },
            };
            await ssl.AuthenticateAsClientAsync(options, ct).ConfigureAwait(false);

            return new SslConnection(tcp, ssl, peerCertDer ?? Array.Empty<byte>());
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private sealed class SslConnection(TcpClient tcp, SslStream ssl, ReadOnlyMemory<byte> peerCertDer) : ITlsConnection
    {
        public Stream Stream => ssl;
        public ReadOnlyMemory<byte> PeerCertificateDer { get; } = peerCertDer;

        public async ValueTask DisposeAsync()
        {
            await ssl.DisposeAsync().ConfigureAwait(false);
            tcp.Dispose();
        }
    }
}
