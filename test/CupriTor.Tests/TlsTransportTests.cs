using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CupriTor.Transport;
using Xunit;

namespace CupriTor.Tests;

public class TlsTransportTests
{
    private static X509Certificate2 CreateSelfSignedServerCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=cupritor-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Round-trip through PKCS#12 so the private key is usable by the OS TLS server (schannel).
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
    }

    // Loopback TLS server that echoes the first 5 bytes it receives.
    private static (TcpListener Listener, int Port, Task Server) StartEchoServer(X509Certificate2 serverCert)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task server = Task.Run(async () =>
        {
            using TcpClient conn = await listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(conn.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(serverCert);
            var buf = new byte[5];
            await ssl.ReadExactlyAsync(buf);
            await ssl.WriteAsync(buf);
            await ssl.FlushAsync();
            // Give the client time to read the echo before tearing down.
            await Task.Delay(100);
        });

        return (listener, port, server);
    }

    private static async Task ExerciseTransport(ITlsTransport transport)
    {
        using X509Certificate2 serverCert = CreateSelfSignedServerCert();
        (TcpListener listener, int port, Task server) = StartEchoServer(serverCert);

        try
        {
            await using ITlsConnection conn = await transport.ConnectAsync("127.0.0.1", port);

            // The transport captured the relay's certificate for in-band binding.
            Assert.False(conn.PeerCertificateDer.IsEmpty);
            Assert.Equal(serverCert.RawData, conn.PeerCertificateDer.ToArray());

            // The encrypted channel round-trips bytes.
            var payload = new byte[] { 1, 2, 3, 4, 5 };
            await conn.Stream.WriteAsync(payload);
            await conn.Stream.FlushAsync();
            var echoed = new byte[5];
            await conn.Stream.ReadExactlyAsync(echoed);
            Assert.Equal(payload, echoed);

            await server;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public Task Managed_BouncyCastle_Transport_Handshakes_And_Captures_Cert()
        => ExerciseTransport(new BouncyCastleTlsTransport());

    [Fact]
    public Task Os_SslStream_Transport_Handshakes_And_Captures_Cert()
        => ExerciseTransport(new SslStreamTlsTransport());
}
