namespace CupriTor;

/// <summary>
/// A client's authorization key for connecting to a <b>private</b> (client-authorized) v3 onion service: the x25519
/// private key whose public half the service operator added to its authorized clients. Create one from a tor
/// <c>descriptor:x25519:BASE32</c> private line (interoperable with Tor Browser / c-tor <c>ClientOnionAuthDir</c>)
/// or from raw key bytes, then pass it to
/// <see cref="TorClient.ConnectToOnionAsync(string,int,OnionClientAuth,System.Threading.CancellationToken)"/>.
/// The public half is given to the operator via <see cref="OnionClientAuthorization"/>.
/// </summary>
public sealed class OnionClientAuth
{
    private readonly byte[] _privateKey;

    private OnionClientAuth(byte[] privateKey) => _privateKey = privateKey;

    /// <summary>The raw 32-byte x25519 private key, for the descriptor-decrypt path.</summary>
    internal ReadOnlyMemory<byte> PrivateKey => _privateKey;

    /// <summary>Wrap a raw 32-byte x25519 authorization private key.</summary>
    public static OnionClientAuth FromX25519PrivateKey(ReadOnlySpan<byte> privateKey32)
    {
        if (privateKey32.Length != 32)
            throw new ArgumentException("An x25519 private key must be exactly 32 bytes.", nameof(privateKey32));
        return new OnionClientAuth(privateKey32.ToArray());
    }

    /// <summary>
    /// Parse a tor client-auth private line — a base32 x25519 private key, with or without the
    /// <c>descriptor:x25519:</c> prefix — as produced by
    /// <see cref="OnionClientAuthorization.GenerateClientKeyPair"/> and stored in tor's <c>ClientOnionAuthDir</c>.
    /// </summary>
    public static OnionClientAuth FromTorPrivateKey(string privateLine) =>
        FromX25519PrivateKey(OnionClientAuthorization.ParsePrivateKey(privateLine));
}

/// <summary>
/// Thrown by <c>ConnectToOnionAsync</c> when the target is a private (client-authorized) onion service that the
/// supplied <see cref="OnionClientAuth"/> cannot decrypt — either because none was supplied
/// (<see cref="NoKeySupplied"/> is true) or because the supplied key is not in the descriptor's authorized-client
/// list (false). Distinguishes "this onion needs authorization" from an ordinary connection failure.
/// </summary>
public sealed class OnionClientAuthorizationRequiredException(bool noKeySupplied) : InvalidOperationException(
    noKeySupplied
        ? "This is a private (client-authorized) onion service. Supply the authorized client's x25519 private key " +
          "via ConnectToOnionAsync(onion, port, OnionClientAuth, …)."
        : "The supplied client authorization is not authorized for this private onion service (its key is not in " +
          "the descriptor's authorized-clients list).")
{
    /// <summary>True when no client key was supplied; false when a key was supplied but is not authorized.</summary>
    public bool NoKeySupplied { get; } = noKeySupplied;
}
