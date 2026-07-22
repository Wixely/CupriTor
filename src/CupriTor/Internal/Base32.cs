namespace CupriTor.Internal;

/// <summary>
/// RFC 4648 base32 (lowercase, no padding) — the encoding Tor uses for v3 .onion addresses.
/// </summary>
internal static class Base32
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz234567";

    internal static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return string.Empty;
        int outLen = (data.Length * 8 + 4) / 5;
        return string.Create(outLen, data.ToArray(), static (chars, src) =>
        {
            int bits = 0, value = 0, idx = 0;
            foreach (byte b in src)
            {
                value = (value << 8) | b;
                bits += 8;
                while (bits >= 5)
                {
                    chars[idx++] = Alphabet[(value >> (bits - 5)) & 31];
                    bits -= 5;
                }
            }
            if (bits > 0)
                chars[idx] = Alphabet[(value << (5 - bits)) & 31];
        });
    }

    internal static bool TryDecode(string s, out byte[] result)
    {
        result = Array.Empty<byte>();
        if (s.Length == 0) return true;

        int outLen = s.Length * 5 / 8;
        var outb = new byte[outLen];
        int bits = 0, value = 0, idx = 0;
        foreach (char ch in s)
        {
            int v = Decode(ch);
            if (v < 0) return false;
            value = (value << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                outb[idx++] = (byte)((value >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        result = outb;
        return true;
    }

    private static int Decode(char ch)
    {
        if (ch >= 'a' && ch <= 'z') return ch - 'a';
        if (ch >= 'A' && ch <= 'Z') return ch - 'A';
        if (ch >= '2' && ch <= '7') return ch - '2' + 26;
        return -1;
    }
}
