using CupriTor.Protocol;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace CupriTor.Tests;

public class NtorTests
{
    private static (X25519PrivateKeyParameters Priv, byte[] Pub, byte[] NodeId) MakeRelay(SecureRandom rng)
    {
        var priv = new X25519PrivateKeyParameters(rng);
        byte[] pub = priv.GeneratePublicKey().GetEncoded();
        var nodeId = new byte[Ntor.NodeIdLength];
        rng.NextBytes(nodeId);
        return (priv, pub, nodeId);
    }

    [Fact]
    public void Client_And_Responder_Agree_On_KeySeed()
    {
        var rng = new SecureRandom();
        (X25519PrivateKeyParameters relayPriv, byte[] B, byte[] nodeId) = MakeRelay(rng);

        (byte[] hs, Ntor.ClientState state) = Ntor.CreateClient(nodeId, B, rng);
        Assert.Equal(Ntor.ClientHandshakeLength, hs.Length);

        var responded = Ntor.Respond(hs, nodeId, relayPriv, B, rng);
        Assert.NotNull(responded);
        (byte[] created, byte[] serverSeed) = responded!.Value;
        Assert.Equal(Ntor.ServerHandshakeLength, created.Length);

        byte[]? clientSeed = Ntor.CompleteClient(state, created);
        Assert.NotNull(clientSeed);
        Assert.Equal(serverSeed, clientSeed);

        // The derived relay key material (Df|Db|Kf|Kb = 72 bytes) matches on both sides.
        Assert.Equal(Ntor.DeriveKeys(serverSeed, 72), Ntor.DeriveKeys(clientSeed!, 72));
    }

    [Fact]
    public void Client_Rejects_Tampered_Auth()
    {
        var rng = new SecureRandom();
        (X25519PrivateKeyParameters relayPriv, byte[] B, byte[] nodeId) = MakeRelay(rng);

        (byte[] hs, Ntor.ClientState state) = Ntor.CreateClient(nodeId, B, rng);
        (byte[] created, _) = Ntor.Respond(hs, nodeId, relayPriv, B, rng)!.Value;
        created[^1] ^= 0xFF; // corrupt the AUTH tag

        Assert.Null(Ntor.CompleteClient(state, created));
    }

    [Fact]
    public void Responder_Rejects_Wrong_NodeId_Or_Key()
    {
        var rng = new SecureRandom();
        (X25519PrivateKeyParameters relayPriv, byte[] B, byte[] nodeId) = MakeRelay(rng);
        (byte[] hs, _) = Ntor.CreateClient(nodeId, B, rng);

        var wrongNodeId = new byte[Ntor.NodeIdLength];
        rng.NextBytes(wrongNodeId);
        Assert.Null(Ntor.Respond(hs, wrongNodeId, relayPriv, B, rng));

        var otherPriv = new X25519PrivateKeyParameters(rng);
        byte[] otherPub = otherPriv.GeneratePublicKey().GetEncoded();
        Assert.Null(Ntor.Respond(hs, nodeId, otherPriv, otherPub, rng)); // client's KEYID (B) won't match
    }

    [Fact]
    public void Different_Relay_Key_Yields_Different_Seed()
    {
        var rng = new SecureRandom();
        (X25519PrivateKeyParameters relayPriv, byte[] B, byte[] nodeId) = MakeRelay(rng);
        (byte[] hs, Ntor.ClientState state) = Ntor.CreateClient(nodeId, B, rng);
        (byte[] created, byte[] serverSeed) = Ntor.Respond(hs, nodeId, relayPriv, B, rng)!.Value;

        byte[]? clientSeed = Ntor.CompleteClient(state, created);
        Assert.Equal(serverSeed, clientSeed);
        Assert.NotEqual(new byte[serverSeed.Length], serverSeed); // seed is not trivially zero
    }
}
