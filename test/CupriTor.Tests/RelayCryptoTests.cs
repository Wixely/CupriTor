using CupriTor.Protocol;
using Xunit;

namespace CupriTor.Tests;

public class RelayCryptoTests
{
    private const int CellLen = 509;
    private const int RecognizedOffset = 1;
    private const int DigestOffset = 5;

    private static (RelayCrypto[] Client, RelayCrypto[] Relay) MakeCircuit(int hops, Random rng)
    {
        var client = new RelayCrypto[hops];
        var relay = new RelayCrypto[hops];
        for (int i = 0; i < hops; i++)
        {
            var km = new byte[RelayCrypto.KeyMaterialLength];
            rng.NextBytes(km);
            client[i] = new RelayCrypto(km);
            relay[i] = new RelayCrypto(km);
        }
        return (client, relay);
    }

    private static byte[] FreshCell(Random rng)
    {
        var cell = new byte[CellLen];
        rng.NextBytes(cell);
        cell[RecognizedOffset] = 0;
        cell[RecognizedOffset + 1] = 0;
        Array.Clear(cell, DigestOffset, 4);
        return cell;
    }

    [Fact]
    public void Forward_Layers_RoundTrip_And_Digest_Matches()
    {
        var rng = new Random(7);
        int hops = 3, target = 2;
        (RelayCrypto[] client, RelayCrypto[] relay) = MakeCircuit(hops, rng);

        byte[] cell = FreshCell(rng);
        byte[] plaintext = (byte[])cell.Clone(); // digest field is zero here

        client[target].ForwardDigest(cell).CopyTo(cell, DigestOffset);
        for (int i = target; i >= 0; i--) client[i].CryptForward(cell);      // encrypt innermost..outermost

        for (int i = 0; i <= target; i++) relay[i].CryptForward(cell);       // each hop peels one layer

        Assert.Equal(0, cell[RecognizedOffset]);
        Assert.Equal(0, cell[RecognizedOffset + 1]);

        byte[] receivedDigest = cell[DigestOffset..(DigestOffset + 4)];
        byte[] zeroed = (byte[])cell.Clone();
        Array.Clear(zeroed, DigestOffset, 4);
        Assert.Equal(relay[target].ForwardDigest(zeroed), receivedDigest);
        Assert.Equal(plaintext, zeroed);
    }

    [Fact]
    public void Backward_Layers_RoundTrip_And_Digest_Matches()
    {
        var rng = new Random(11);
        int hops = 3, origin = 2;
        (RelayCrypto[] client, RelayCrypto[] relay) = MakeCircuit(hops, rng);

        byte[] cell = FreshCell(rng);
        byte[] plaintext = (byte[])cell.Clone();

        relay[origin].BackwardDigest(cell).CopyTo(cell, DigestOffset);
        for (int i = origin; i >= 0; i--) relay[i].CryptBackward(cell);      // origin encrypts, then outward
        for (int i = 0; i <= origin; i++) client[i].CryptBackward(cell);     // client peels each layer

        Assert.Equal(0, cell[RecognizedOffset]);
        Assert.Equal(0, cell[RecognizedOffset + 1]);

        byte[] receivedDigest = cell[DigestOffset..(DigestOffset + 4)];
        byte[] zeroed = (byte[])cell.Clone();
        Array.Clear(zeroed, DigestOffset, 4);
        Assert.Equal(client[origin].BackwardDigest(zeroed), receivedDigest);
        Assert.Equal(plaintext, zeroed);
    }

    [Fact]
    public void Running_Digest_And_Counter_Chain_Across_Cells()
    {
        var rng = new Random(13);
        int hops = 3, target = 2;
        (RelayCrypto[] client, RelayCrypto[] relay) = MakeCircuit(hops, rng);

        for (int c = 0; c < 4; c++)
        {
            byte[] cell = FreshCell(rng);
            byte[] plaintext = (byte[])cell.Clone();

            client[target].ForwardDigest(cell).CopyTo(cell, DigestOffset);
            for (int i = target; i >= 0; i--) client[i].CryptForward(cell);
            for (int i = 0; i <= target; i++) relay[i].CryptForward(cell);

            byte[] zeroed = (byte[])cell.Clone();
            Array.Clear(zeroed, DigestOffset, 4);
            Assert.Equal(relay[target].ForwardDigest(zeroed), cell[DigestOffset..(DigestOffset + 4)]);
            Assert.Equal(plaintext, zeroed);
        }
    }
}
