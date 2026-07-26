using System.Net.Sockets;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CupriTor.Transport;

/// <summary>
/// 100%-managed TLS transport using BouncyCastle's TLS stack (<c>Org.BouncyCastle.Tls</c>) — the
/// intended default, with <see cref="SslStreamTlsTransport"/> as the OS-backed A/B baseline. As with
/// the baseline, the server certificate is accepted unconditionally: Tor authenticates the relay via
/// the in-band link certificate chain, not the web PKI. The peer certificate is captured so the link
/// certificate can be bound to the TLS session.
/// </summary>
public sealed class BouncyCastleTlsTransport : ITlsTransport
{
    /// <inheritdoc/>
    public async Task<ITlsConnection> ConnectAsync(string host, int port, CancellationToken ct = default)
    {
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

            var crypto = new BcTlsCrypto(new SecureRandom());
            var client = new AcceptAllTlsClient(crypto);
            var protocol = new TlsClientProtocol(tcp.GetStream());

            // BouncyCastle's TlsClientProtocol.Connect performs blocking I/O; run it off the caller's thread. Task.Run's
            // ct only affects scheduling, so also close the socket on cancellation to actually abort the blocking call.
            using (ct.Register(static s => { try { ((TcpClient)s!).Close(); } catch { } }, tcp))
            {
                await Task.Run(() => protocol.Connect(client), ct).ConfigureAwait(false);
            }

            return new BcConnection(tcp, protocol, client.PeerCertificateDer ?? Array.Empty<byte>());
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private sealed class AcceptAllTlsClient(BcTlsCrypto crypto) : DefaultTlsClient(crypto)
    {
        private readonly AcceptAllAuthentication _auth = new();

        public override TlsAuthentication GetAuthentication() => _auth;

        public byte[]? PeerCertificateDer => _auth.PeerCertificateDer;

        private sealed class AcceptAllAuthentication : TlsAuthentication
        {
            public byte[]? PeerCertificateDer { get; private set; }

            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                Certificate? chain = serverCertificate?.Certificate;
                if (chain is { IsEmpty: false })
                    PeerCertificateDer = chain.GetCertificateAt(0).GetEncoded();
                // Accept unconditionally (do not throw): the relay is authenticated in-band.
            }
        }
    }

    private sealed class BcConnection(TcpClient tcp, TlsClientProtocol protocol, ReadOnlyMemory<byte> peerCertDer)
        : ITlsConnection
    {
        public Stream Stream => protocol.Stream;
        public ReadOnlyMemory<byte> PeerCertificateDer { get; } = peerCertDer;

        public ValueTask DisposeAsync()
        {
            try { protocol.Close(); } catch { /* best-effort close */ }
            tcp.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
