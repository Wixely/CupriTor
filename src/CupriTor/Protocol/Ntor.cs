using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CupriTor.Protocol;

/// <summary>
/// The Tor "ntor" circuit handshake (tor-spec §5.1.4): an authenticated Curve25519 key exchange that
/// yields a shared KEY_SEED from which the per-hop relay keys are derived. Implemented for both the
/// client side (CREATE2/CREATED2) and the responder side (used by relays and by onion services).
/// Uses BouncyCastle's managed X25519 and HKDF-SHA256.
/// </summary>
internal static class Ntor
{
    private const string ProtoId = "ntor-curve25519-sha256-1";
    private static readonly byte[] TMac = Encoding.ASCII.GetBytes(ProtoId + ":mac");
    private static readonly byte[] TKey = Encoding.ASCII.GetBytes(ProtoId + ":key_extract");
    private static readonly byte[] TVerify = Encoding.ASCII.GetBytes(ProtoId + ":verify");
    private static readonly byte[] MExpand = Encoding.ASCII.GetBytes(ProtoId + ":key_expand");
    private static readonly byte[] ProtoIdBytes = Encoding.ASCII.GetBytes(ProtoId);
    private static readonly byte[] ServerStr = Encoding.ASCII.GetBytes("Server");

    public const int NodeIdLength = 20;
    public const int KeyLength = 32;
    public const int ClientHandshakeLength = NodeIdLength + KeyLength + KeyLength; // 84
    public const int ServerHandshakeLength = KeyLength + 32;                        // Y + AUTH = 64

    /// <summary>Client-side handshake state carried between CREATE2 and CREATED2.</summary>
    internal sealed class ClientState
    {
        public required byte[] NodeId { get; init; }
        public required byte[] RelayNtorKey { get; init; }   // B
        public required X25519PrivateKeyParameters Ephemeral { get; init; }
        public required byte[] X { get; init; }
    }

    /// <summary>Build a client CREATE2 ntor handshake for a relay with the given node id and ntor onion key.</summary>
    public static (byte[] HandshakeData, ClientState State) CreateClient(
        byte[] nodeId, byte[] relayNtorKey, SecureRandom? random = null)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(nodeId.Length, NodeIdLength);
        ArgumentOutOfRangeException.ThrowIfNotEqual(relayNtorKey.Length, KeyLength);

        var ephemeral = new X25519PrivateKeyParameters(random ?? new SecureRandom());
        byte[] x = ephemeral.GeneratePublicKey().GetEncoded();
        byte[] handshake = Concat(nodeId, relayNtorKey, x);
        var state = new ClientState { NodeId = nodeId, RelayNtorKey = relayNtorKey, Ephemeral = ephemeral, X = x };
        return (handshake, state);
    }

    /// <summary>
    /// Responder side (relay / onion service). Validates the client handshake against this node's id and
    /// ntor key, and returns the CREATED2 payload plus the shared KEY_SEED. Returns null on failure.
    /// </summary>
    public static (byte[] CreatedData, byte[] KeySeed)? Respond(
        byte[] clientHandshake, byte[] nodeId, X25519PrivateKeyParameters ntorPrivate, byte[] ntorPublic,
        SecureRandom? random = null)
    {
        if (clientHandshake.Length != ClientHandshakeLength) return null;
        if (!clientHandshake.AsSpan(0, NodeIdLength).SequenceEqual(nodeId)) return null;
        if (!clientHandshake.AsSpan(NodeIdLength, KeyLength).SequenceEqual(ntorPublic)) return null;

        byte[] x = clientHandshake[(NodeIdLength + KeyLength)..];
        var y = new X25519PrivateKeyParameters(random ?? new SecureRandom());
        byte[] yPub = y.GeneratePublicKey().GetEncoded();

        byte[]? xy = Agree(y, x);
        byte[]? xb = Agree(ntorPrivate, x);
        if (xy is null || xb is null) return null;

        byte[] secretInput = Concat(xy, xb, nodeId, ntorPublic, x, yPub, ProtoIdBytes);
        byte[] keySeed = Hmac(TKey, secretInput);
        byte[] verify = Hmac(TVerify, secretInput);
        byte[] auth = Hmac(TMac, Concat(verify, nodeId, ntorPublic, yPub, x, ProtoIdBytes, ServerStr));

        return (Concat(yPub, auth), keySeed);
    }

    /// <summary>Client processes CREATED2, verifies AUTH, and returns the shared KEY_SEED (null on failure).</summary>
    public static byte[]? CompleteClient(ClientState state, byte[] createdData)
    {
        if (createdData.Length != ServerHandshakeLength) return null;

        byte[] yPub = createdData[..KeyLength];
        byte[] auth = createdData[KeyLength..];

        byte[]? yx = Agree(state.Ephemeral, yPub);
        byte[]? bx = Agree(state.Ephemeral, state.RelayNtorKey);
        if (yx is null || bx is null) return null;

        byte[] secretInput = Concat(yx, bx, state.NodeId, state.RelayNtorKey, state.X, yPub, ProtoIdBytes);
        byte[] keySeed = Hmac(TKey, secretInput);
        byte[] verify = Hmac(TVerify, secretInput);
        byte[] expectedAuth = Hmac(TMac, Concat(verify, state.NodeId, state.RelayNtorKey, yPub, state.X, ProtoIdBytes, ServerStr));

        return CryptographicOperations.FixedTimeEquals(expectedAuth, auth) ? keySeed : null;
    }

    /// <summary>Expand KEY_SEED into relay key material via HKDF-SHA256 (tor-spec §5.2.2).</summary>
    public static byte[] DeriveKeys(byte[] keySeed, int length) =>
        HKDF.Expand(HashAlgorithmName.SHA256, keySeed, length, MExpand);

    private static byte[]? Agree(X25519PrivateKeyParameters priv, byte[] peerPublic)
    {
        if (peerPublic.Length != KeyLength) return null;
        var agreement = new X25519Agreement();
        agreement.Init(priv);
        var shared = new byte[agreement.AgreementSize];
        try
        {
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublic, 0), shared, 0);
        }
        catch (Exception)
        {
            return null;
        }
        // Reject contributory / low-order results (all-zero shared secret).
        int acc = 0;
        foreach (byte b in shared) acc |= b;
        return acc == 0 ? null : shared;
    }

    private static byte[] Hmac(byte[] key, byte[] message) => HMACSHA256.HashData(key, message);

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] p in parts) total += p.Length;
        var result = new byte[total];
        int pos = 0;
        foreach (byte[] p in parts)
        {
            p.CopyTo(result, pos);
            pos += p.Length;
        }
        return result;
    }
}
