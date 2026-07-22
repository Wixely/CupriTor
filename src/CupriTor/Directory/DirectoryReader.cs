namespace CupriTor.Directory;

/// <summary>One item of a Tor directory document: a keyword, its arguments, and an optional object block.</summary>
internal readonly record struct DirectoryItem(string Keyword, string[] Arguments, string? ObjectType, byte[]? ObjectData);

/// <summary>Raised when a directory document is malformed.</summary>
internal sealed class DirectoryParseException(string message) : Exception(message);

/// <summary>
/// Tokenizes the line-based Tor directory document format (dir-spec §1.2): keyword lines
/// <c>KEYWORD ARG ARG ...</c> optionally followed by a PEM-style object
/// <c>-----BEGIN TYPE-----</c> / base64 / <c>-----END TYPE-----</c>.
/// </summary>
internal static class DirectoryReader
{
    private const string BeginPrefix = "-----BEGIN ";
    private const string EndPrefix = "-----END ";

    public static List<DirectoryItem> Parse(string text)
    {
        var items = new List<DirectoryItem>();
        string[] lines = text.Replace("\r", "").Split('\n');

        int i = 0;
        while (i < lines.Length)
        {
            string line = lines[i];
            if (line.Length == 0) { i++; continue; }
            if (line.StartsWith(BeginPrefix, StringComparison.Ordinal))
                throw new DirectoryParseException("Object block without a preceding keyword.");

            string[] parts = line.Split(' ');
            string keyword = parts[0];
            string[] args = parts.Length > 1 ? parts[1..] : Array.Empty<string>();
            i++;

            string? objectType = null;
            byte[]? objectData = null;
            if (i < lines.Length && lines[i].StartsWith(BeginPrefix, StringComparison.Ordinal))
            {
                objectType = lines[i].Substring(BeginPrefix.Length).TrimEnd('-');
                i++;
                var b64 = new System.Text.StringBuilder();
                while (i < lines.Length && !lines[i].StartsWith(EndPrefix, StringComparison.Ordinal))
                {
                    b64.Append(lines[i]);
                    i++;
                }
                if (i >= lines.Length)
                    throw new DirectoryParseException("Unterminated object block.");
                i++; // consume the END line
                try
                {
                    objectData = Convert.FromBase64String(b64.ToString());
                }
                catch (FormatException e)
                {
                    throw new DirectoryParseException($"Invalid base64 in {objectType} object: {e.Message}");
                }
            }

            items.Add(new DirectoryItem(keyword, args, objectType, objectData));
        }

        return items;
    }

    /// <summary>Decode Tor's padding-less standard base64 (e.g. identity digests in consensus lines).</summary>
    public static byte[] Base64(string s)
    {
        int pad = (4 - s.Length % 4) % 4;
        return Convert.FromBase64String(pad == 0 ? s : s + new string('=', pad));
    }
}
