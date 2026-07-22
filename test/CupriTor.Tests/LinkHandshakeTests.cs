using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using CupriTor.Protocol;
using Xunit;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace CupriTor.Tests;

public class LinkHandshakeTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private static byte[] Pub(byte[] seed) { var p = new byte[32]; BcEd25519.GeneratePublicKey(seed, 0, p, 0); return p; }
    private static byte[] Seed(byte b) { var s = new byte[32]; Array.Fill(s, b); return s; }

    // Build a cert-spec Ed25519 certificate, optionally with a signed-with-ed25519-key extension.
    private static byte[] BuildCert(byte certType, byte certKeyType, byte[] certifiedKey,
        byte[]? signingKeyExt, byte[] signerSeed, DateTimeOffset expiration)
    {
        uint hours = (uint)(expiration - DateTimeOffset.UnixEpoch).TotalHours;
        var body = new List<byte> { 0x01, certType };
        Span<byte> h = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(h, hours);
        body.AddRange(h.ToArray());
        body.Add(certKeyType);
        body.AddRange(certifiedKey);
        if (signingKeyExt is not null)
        {
            body.Add(0x01);
            Span<byte> el = stackalloc byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(el, 32);
            body.AddRange(el.ToArray());
            body.Add(0x04);
            body.Add(0x00);
            body.AddRange(signingKeyExt);
        }
        else
        {
            body.Add(0x00);
        }

        var bodyArr = body.ToArray();
        var sig = new byte[64];
        BcEd25519.Sign(signerSeed, 0, bodyArr, 0, bodyArr.Length, sig, 0);
        var cert = new byte[bodyArr.Length + 64];
        bodyArr.CopyTo(cert, 0);
        sig.CopyTo(cert, bodyArr.Length);
        return cert;
    }

    private sealed record Relay(byte[] IdentitySeed, byte[] SigningSeed, byte[] TlsCertDer, byte[] CertsPayload);

    private static Relay BuildRelay(bool tamperSigningCert = false)
    {
        byte[] idSeed = Seed(0x11), sgSeed = Seed(0x22);
        byte[] idPub = Pub(idSeed), sgPub = Pub(sgSeed);
        var tls = new byte[200];
        RandomNumberGenerator.Fill(tls);
        var tlsHash = SHA256.HashData(tls);

        var future = Now.AddDays(30);
        byte[] cert4 = BuildCert(0x04, 0x01, sgPub, idPub, idSeed, future);      // identity -> signing
        if (tamperSigningCert) cert4[^1] ^= 0xFF;                                // break the signature
        byte[] cert5 = BuildCert(0x05, 0x03, tlsHash, null, sgSeed, future);     // signing -> TLS link

        byte[] certs = CertsCell.Build(new List<CertsCell.Entry>
        {
            new(0x04, cert4),
            new(0x05, cert5),
        });
        return new Relay(idSeed, sgSeed, tls, certs);
    }

    private static async Task RelaySideAsync(Stream s, byte[] certsPayload)
    {
        var initial = CellCodec.Initial;
        _ = await initial.ReadAsync(s);                                          // client VERSIONS
        await initial.WriteAsync(s, new Cell(0, CellCommand.Versions, VersionsCell.Build(4, 5)));

        var codec = new CellCodec(4);
        await codec.WriteAsync(s, new Cell(0, CellCommand.Certs, certsPayload));
        await codec.WriteAsync(s, new Cell(0, CellCommand.AuthChallenge, new byte[34])); // 32 challenge + 0 methods
        var other = TorAddress.FromIP(IPAddress.Loopback);
        await codec.WriteAsync(s, new Cell(0, CellCommand.Netinfo,
            NetInfoCell.Build((uint)Now.ToUnixTimeSeconds(), other, Array.Empty<TorAddress>())));

        _ = await codec.ReadAsync(s);                                            // client NETINFO
    }

    private static async Task<LinkHandshakeResult> RunAsync(byte[] certsPayload, byte[] clientTlsDer, byte[]? expectedId)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port);
        using var server = await acceptTask;
        listener.Stop();

        Stream clientStream = client.GetStream();
        var relay = Task.Run(async () => { try { await RelaySideAsync(server.GetStream(), certsPayload); } catch { } });

        try
        {
            var result = await LinkHandshake.PerformClientAsync(
                clientStream, clientTlsDer, Now,
                supportedVersions: new ushort[] { 3, 4, 5 },
                expectedEd25519Identity: expectedId,
                peerAddress: IPAddress.Loopback);
            await relay;
            return result;
        }
        catch
        {
            clientStream.Dispose();   // unblock the relay's pending read
            try { await relay; } catch { }
            throw;
        }
    }

    [Fact]
    public async Task Completes_And_Validates_Against_Synthetic_Relay()
    {
        Relay r = BuildRelay();
        LinkHandshakeResult result = await RunAsync(r.CertsPayload, r.TlsCertDer, expectedId: Pub(r.IdentitySeed));

        Assert.Equal((ushort)5, result.LinkVersion);
        Assert.Equal(Pub(r.IdentitySeed), result.RelayEd25519Identity);
        Assert.Equal(Pub(r.SigningSeed), result.RelaySigningKey);
    }

    [Fact]
    public async Task Rejects_Tampered_Signing_Certificate()
    {
        Relay r = BuildRelay(tamperSigningCert: true);
        await Assert.ThrowsAsync<LinkHandshakeException>(() => RunAsync(r.CertsPayload, r.TlsCertDer, null));
    }

    [Fact]
    public async Task Rejects_Wrong_Tls_Certificate()
    {
        Relay r = BuildRelay();
        var differentTls = new byte[200];
        RandomNumberGenerator.Fill(differentTls);
        await Assert.ThrowsAsync<LinkHandshakeException>(() => RunAsync(r.CertsPayload, differentTls, null));
    }

    [Fact]
    public async Task Rejects_Unexpected_Identity()
    {
        Relay r = BuildRelay();
        await Assert.ThrowsAsync<LinkHandshakeException>(() => RunAsync(r.CertsPayload, r.TlsCertDer, expectedId: Seed(0x99)));
    }
}
