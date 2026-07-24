using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CupriTor.OnionService;

/// <summary>
/// Introduction and rendezvous cell payloads (rend-spec-v3 §3.2, §4.1–4.2): ESTABLISH_RENDEZVOUS,
/// INTRODUCE1/2, and RENDEZVOUS1/2. The hs-ntor-encrypted portion of INTRODUCE and the handshake info
/// in RENDEZVOUS are treated as opaque blobs here (produced/consumed by <see cref="HsNtor"/>).
/// </summary>
internal static class HsCells
{
    public const int RendezvousCookieLength = 20;
    public const byte AuthKeyTypeEd25519 = 2;
    private const int LegacyKeyIdLength = 20;
    public const int RendezvousHandshakeLength = 64; // SERVER_PK(32) | AUTH(32)

    /// <summary>A fresh 20-byte rendezvous cookie (the ESTABLISH_RENDEZVOUS payload).</summary>
    public static byte[] NewRendezvousCookie()
    {
        var cookie = new byte[RendezvousCookieLength];
        RandomNumberGenerator.Fill(cookie);
        return cookie;
    }

    /// <summary>
    /// Build an INTRODUCE1/INTRODUCE2 payload: legacy key id (zeroed for v3), the ed25519 intro auth key,
    /// no extensions, then the hs-ntor encrypted blob.
    /// </summary>
    public static byte[] BuildIntroduce(ReadOnlySpan<byte> authKey, ReadOnlySpan<byte> encrypted)
    {
        int length = LegacyKeyIdLength + 1 + 2 + authKey.Length + 1 + encrypted.Length;
        var buffer = new byte[length];
        int pos = LegacyKeyIdLength; // legacy key id left zero
        buffer[pos++] = AuthKeyTypeEd25519;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(pos), (ushort)authKey.Length);
        pos += 2;
        authKey.CopyTo(buffer.AsSpan(pos));
        pos += authKey.Length;
        buffer[pos++] = 0; // N_EXTENSIONS
        encrypted.CopyTo(buffer.AsSpan(pos));
        return buffer;
    }

    public static bool TryParseIntroduce(ReadOnlySpan<byte> payload, out byte[] authKey, out byte[] encrypted)
    {
        authKey = Array.Empty<byte>();
        encrypted = Array.Empty<byte>();
        int pos = LegacyKeyIdLength;
        if (payload.Length < pos + 3) return false;

        pos++; // AUTH_KEY_TYPE
        int authKeyLen = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(pos, 2));
        pos += 2;
        if (payload.Length < pos + authKeyLen + 1) return false;
        authKey = payload.Slice(pos, authKeyLen).ToArray();
        pos += authKeyLen;

        int extensions = payload[pos++];
        for (int i = 0; i < extensions; i++)
        {
            if (pos + 2 > payload.Length) return false;
            int extLen = payload[pos + 1];
            pos += 2 + extLen;
            if (pos > payload.Length) return false;
        }

        encrypted = payload.Slice(pos).ToArray();
        return true;
    }

    /// <summary>RENDEZVOUS handshake info = SERVER_PK (Y, 32) ‖ AUTH (32); the RENDEZVOUS2 payload.</summary>
    public static byte[] BuildRendezvousHandshake(ReadOnlySpan<byte> servicePublic, ReadOnlySpan<byte> auth)
    {
        var buffer = new byte[RendezvousHandshakeLength];
        servicePublic.Slice(0, 32).CopyTo(buffer);
        auth.Slice(0, 32).CopyTo(buffer.AsSpan(32));
        return buffer;
    }

    public static bool TryParseRendezvousHandshake(ReadOnlySpan<byte> payload, out byte[] servicePublic, out byte[] auth)
    {
        servicePublic = Array.Empty<byte>();
        auth = Array.Empty<byte>();
        if (payload.Length < RendezvousHandshakeLength) return false;
        servicePublic = payload.Slice(0, 32).ToArray();
        auth = payload.Slice(32, 32).ToArray();
        return true;
    }

    /// <summary>RENDEZVOUS1 payload = RENDEZVOUS_COOKIE (20) ‖ handshake info.</summary>
    public static byte[] BuildRendezvous1(ReadOnlySpan<byte> cookie, ReadOnlySpan<byte> handshake)
    {
        var buffer = new byte[RendezvousCookieLength + handshake.Length];
        cookie.Slice(0, RendezvousCookieLength).CopyTo(buffer);
        handshake.CopyTo(buffer.AsSpan(RendezvousCookieLength));
        return buffer;
    }

    public static bool TryParseRendezvous1(ReadOnlySpan<byte> payload, out byte[] cookie, out byte[] handshake)
    {
        cookie = Array.Empty<byte>();
        handshake = Array.Empty<byte>();
        if (payload.Length < RendezvousCookieLength) return false;
        cookie = payload.Slice(0, RendezvousCookieLength).ToArray();
        handshake = payload.Slice(RendezvousCookieLength).ToArray();
        return true;
    }
}
