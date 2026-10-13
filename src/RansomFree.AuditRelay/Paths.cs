namespace RansomFree.LinuxAgent;

// Same strict path rules as the managed collector. This small bootstrap is
// compiled into the standalone AOT relay; no agent/configuration dependency.
internal static class Paths
{
    public static string NoLinks(string path)
    {
        if(!path.StartsWith('/')||path.Contains('\0')||path.Length>2048||path.Any(char.IsControl)||path.Split('/').Any(x=>x is "." or ".."))throw new InvalidDataException("Use an explicit absolute Unix path without dot segments.");
        path=Path.GetFullPath(path).TrimEnd('/');if(path.Length==0)throw new InvalidDataException("A filesystem root is not a valid application path.");
        for(string? parent=path;parent!=null;parent=Path.GetDirectoryName(parent))
            if(Path.Exists(parent)&&(File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0)throw new IOException("Path traverses a symbolic link; no change made.");
        return path;
    }
}
