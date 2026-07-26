using System.Net;
using System.Security.Cryptography;

namespace CupriTor.Protocol;

/// <summary>Raised when the OR link handshake fails or the relay's certificates don't validate.</summary>
internal sealed class LinkHandshakeException(string message) : Exception(message);

/// <summary>Outcome of a successful link handshake.</summary>
internal sealed record LinkHandshakeResult(
    ushort LinkVersion,
    byte[] RelayEd25519Identity,
    byte[] RelaySigningKey);

/// <summary>
/// Drives the client side of the Tor OR link handshake (tor-spec §4) over an established, encrypted
/// duplex stream: negotiate the link protocol version via VERSIONS, read the responder's
/// CERTS/AUTH_CHALLENGE/NETINFO, validate the Ed25519 certificate chain and its binding to the TLS
/// session, then send our own NETINFO. This is the responder-authenticated path — a client does not
/// send AUTHENTICATE.
/// </summary>
internal static class LinkHandshake
{
    private static readonly ushort[] DefaultVersions = { 3, 4, 5 };
    private const int MaxHandshakeCells = 32;

    public static async Task<LinkHandshakeResult> PerformClientAsync(
        Stream stream,
        ReadOnlyMemory<byte> peerTlsCertificateDer,
        DateTimeOffset now,
        ushort[]? supportedVersions = null,
        ReadOnlyMemory<byte>? expectedEd25519Identity = null,
        IPAddress? peerAddress = null,
        CancellationToken ct = default)
    {
        ushort[] ours = supportedVersions ?? DefaultVersions;

        // 1. VERSIONS is framed with a 2-byte circuit id, before any width is negotiated.
        var initial = CellCodec.Initial;
        await initial.WriteAsync(stream, new Cell(0, CellCommand.Versions, VersionsCell.Build(ours)), ct)
            .ConfigureAwait(false);

        Cell theirVersionsCell = await initial.ReadAsync(stream, ct).ConfigureAwait(false);
        if (theirVersionsCell.Command != CellCommand.Versions ||
            !VersionsCell.TryParse(theirVersionsCell.Payload.Span, out ushort[] theirs))
        {
            throw new LinkHandshakeException("Expected a VERSIONS cell from the responder.");
        }

        ushort version = VersionsCell.HighestCommon(ours, theirs)
            ?? throw new LinkHandshakeException("No common link protocol version.");

        // 2. After negotiation, v4+ uses a 4-byte circuit id.
        var codec = new CellCodec(version >= 4 ? 4 : 2);

        // 3. Read the responder's handshake cells until NETINFO.
        CertsCell? certs = null;
        bool gotNetInfo = false;
        for (int i = 0; i < MaxHandshakeCells && !gotNetInfo; i++)
        {
            Cell cell = await codec.ReadAsync(stream, ct).ConfigureAwait(false);
            switch (cell.Command)
            {
                case CellCommand.Certs:
                    if (!CertsCell.TryParse(cell.Payload, out certs))
                        throw new LinkHandshakeException("Malformed CERTS cell.");
                    break;
                case CellCommand.Netinfo:
                    gotNetInfo = true;
                    break;
                // AUTH_CHALLENGE, PADDING and any unexpected cells are ignored by a non-authenticating client.
            }
        }

        if (!gotNetInfo)
            throw new LinkHandshakeException("Responder did not complete the handshake (no NETINFO).");
        if (certs is null)
            throw new LinkHandshakeException("Responder sent no CERTS cell.");

        LinkHandshakeResult result = ValidateCertificates(certs, peerTlsCertificateDer.Span, now, version, expectedEd25519Identity);

        // 4. Send our NETINFO to complete the exchange.
        var other = TorAddress.FromIP(peerAddress ?? IPAddress.Any);
        byte[] netinfo = NetInfoCell.Build((uint)now.ToUnixTimeSeconds(), other, Array.Empty<TorAddress>());
        await codec.WriteAsync(stream, new Cell(0, CellCommand.Netinfo, netinfo), ct).ConfigureAwait(false);

        return result;
    }

    private static LinkHandshakeResult ValidateCertificates(
        CertsCell certs, ReadOnlySpan<byte> tlsCertDer, DateTimeOffset now, ushort version,
        ReadOnlyMemory<byte>? expectedIdentity)
    {
        // Ed25519 signing key, certified by the Ed25519 identity key (cert type 4).
        ReadOnlyMemory<byte> signingCertBytes = certs.Find((byte)TorCertificate.Type.SigningByIdentity)
            ?? throw new LinkHandshakeException("Missing identity->signing certificate (type 4).");
        if (!TorCertificate.TryParse(signingCertBytes, out TorCertificate signingCert))
            throw new LinkHandshakeException("Malformed signing certificate.");
        if (signingCert.CertType != TorCertificate.Type.SigningByIdentity || signingCert.CertifiedKeyType != TorCertificate.KeyType.Ed25519)
            throw new LinkHandshakeException("Signing certificate has the wrong cert/key type.");
        if (signingCert.IsExpired(now))
            throw new LinkHandshakeException("Signing certificate has expired.");

        ReadOnlyMemory<byte> identity = signingCert.SigningKey
            ?? throw new LinkHandshakeException("Signing certificate carries no identity key.");
        if (!signingCert.VerifySignatureWithEmbeddedKey())
            throw new LinkHandshakeException("Signing certificate is not signed by the identity key.");

        ReadOnlyMemory<byte> signingKey = signingCert.CertifiedKey;

        // TLS link certificate, certified by the signing key, bound to the presented TLS cert (cert type 5).
        ReadOnlyMemory<byte> linkCertBytes = certs.Find((byte)TorCertificate.Type.TlsLinkBySigning)
            ?? throw new LinkHandshakeException("Missing signing->link certificate (type 5).");
        if (!TorCertificate.TryParse(linkCertBytes, out TorCertificate linkCert))
            throw new LinkHandshakeException("Malformed link certificate.");
        // The TLS-bind compare below assumes the certified key is a SHA-256 of the X.509 cert — enforce that type.
        if (linkCert.CertType != TorCertificate.Type.TlsLinkBySigning || linkCert.CertifiedKeyType != TorCertificate.KeyType.Sha256OfX509)
            throw new LinkHandshakeException("Link certificate has the wrong cert/key type.");
        if (linkCert.IsExpired(now))
            throw new LinkHandshakeException("Link certificate has expired.");
        if (!linkCert.VerifySignature(signingKey.Span))
            throw new LinkHandshakeException("Link certificate is not signed by the signing key.");

        Span<byte> tlsHash = stackalloc byte[32];
        SHA256.HashData(tlsCertDer, tlsHash);
        if (!linkCert.CertifiedKey.Span.SequenceEqual(tlsHash))
            throw new LinkHandshakeException("Link certificate does not match the presented TLS certificate.");

        if (expectedIdentity is { } expected &&
            !CryptographicOperations.FixedTimeEquals(identity.Span, expected.Span))
        {
            throw new LinkHandshakeException("Relay identity does not match the expected Ed25519 identity.");
        }

        return new LinkHandshakeResult(version, identity.ToArray(), signingKey.ToArray());
    }
}
