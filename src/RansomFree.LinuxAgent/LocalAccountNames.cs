namespace RansomFree.LinuxAgent;

// Best-effort local display labels, never authoritative credentials or an LDAP lookup.
internal static class LocalAccountNames
{
    public static Dictionary<uint,string> Read()
    {
        var result=new Dictionary<uint,string>();
        try
        {
            Native.ValidateAdminPath("/etc/passwd",false);
            using var input=Native.FileAt("/etc/passwd",false);
            if(input.Length>1048576)return result;
            using var reader=new StreamReader(input);
            for(var count=0;count<16384&&reader.ReadLine() is {} line;count++)
            {
                var fields=line.Split(':');
                if(fields.Length==7&&uint.TryParse(fields[2],out var id)&&fields[0].Length is >0 and <=256&&!fields[0].Any(char.IsControl))result.TryAdd(id,fields[0]);
            }
        }
        catch{ /* Numeric kernel IDs remain available when name enrichment is unavailable. */ }
        return result;
    }
}
