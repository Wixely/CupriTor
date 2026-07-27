using System.Security.Cryptography;
using System.Text;

namespace CupriTor.Protocol;

/// <summary>
/// A durable <see cref="IStateStore"/> that persists each key as a file under a directory, with atomic writes
/// (write-temp + rename) so a crash can't corrupt an entry. Use this (instead of the in-memory default) to keep
/// entry guards stable across restarts — essential for anonymity. Values are stored as raw bytes; wrap this store
/// if you want them encrypted at rest. Intended for a single process; concurrent writers across processes are not
/// coordinated.
/// </summary>
public sealed class FileStateStore : IStateStore
{
    private readonly string _directory;
    private readonly object _lock = new();

    /// <summary>Create (if needed) and use <paramref name="directory"/> to persist state.</summary>
    public FileStateStore(string directory)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
        System.IO.Directory.CreateDirectory(_directory);
    }

    /// <inheritdoc/>
    public byte[]? Read(string key)
    {
        string path = PathFor(key);
        lock (_lock)
            return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <inheritdoc/>
    public void Write(string key, byte[] data)
    {
        string path = PathFor(key);
        string tmp = path + ".tmp";
        lock (_lock)
        {
            File.WriteAllBytes(tmp, data);
            File.Move(tmp, path, overwrite: true); // atomic replace on the same volume
        }
    }

    // Map an opaque key to a stable, filesystem-safe filename (readable prefix + short hash to disambiguate).
    private string PathFor(string key)
    {
        string safe = string.Concat(key.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_'));
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..8];
        return Path.Combine(_directory, $"{safe}.{hash}.dat");
    }
}
