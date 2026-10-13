namespace RansomFree.Client;

// Display conversion only. Native evidence is retained separately. Never use a
// guessed drive, relative DOS path, or partial device-prefix match as identity.
internal static class WindowsNativePaths
{
    internal static string Display(string path,IReadOnlyDictionary<string,string> drives,bool remote)
    {
        if(path.StartsWith(@"\??\",StringComparison.Ordinal)&&path.Length>=7&&char.IsAsciiLetter(path[4])&&path[5]==':'&&path[6]=='\\')return path[4..];
        if(remote&&path.StartsWith("\\Device\\Mup\\",StringComparison.OrdinalIgnoreCase)&&!path[12..].Contains(';'))return "\\\\"+path[12..];
        foreach(var item in drives.OrderByDescending(x=>x.Value.Length))if(path.StartsWith(item.Value+"\\",StringComparison.OrdinalIgnoreCase))return item.Key+path[item.Value.Length..];
        return path;
    }
}
