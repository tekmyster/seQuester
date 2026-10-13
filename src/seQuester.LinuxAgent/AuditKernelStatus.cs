using System.Globalization;

namespace RansomFree.LinuxAgent;

internal static class AuditKernelStatus
{
    // auditctl -s (without -i) emits numeric scalar fields, except the optional
    // loginuid_immutable feature: '<0|1> <locked|unlocked>' in audit-userspace 3.0.7.
    // Do not confuse that feature lock with the required audit enabled state.
    public static int ActivePid(string text)
    {
        if(text.Length>65536)throw new InvalidDataException("Kernel audit status exceeds limit.");
        var lines=text.Split('\n',StringSplitOptions.RemoveEmptyEntries);
        if(lines.Length>256)throw new InvalidDataException("Too many kernel audit status fields.");
        var fields=new Dictionary<string,uint>(StringComparer.Ordinal);
        foreach(var line in lines)
        {
            if(line.Length>512)throw new InvalidDataException("Kernel audit status field exceeds limit.");
            var tokens=line.Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries);
            if(tokens.Length==0)continue;
            if(tokens.Length<2||!tokens[0].All(c=>char.IsAsciiLetter(c)||c=='_')||!uint.TryParse(tokens[1],NumberStyles.None,CultureInfo.InvariantCulture,out var value)||!fields.TryAdd(tokens[0],value))throw new InvalidDataException("Malformed or duplicate kernel audit status field.");
            if(tokens[0]=="loginuid_immutable")
            {
                if(tokens.Length!=3||value>1||tokens[2] is not ("locked" or "unlocked"))throw new InvalidDataException("Malformed audit loginuid feature status.");
            }
            else if(tokens.Length!=2)throw new InvalidDataException("Malformed kernel audit scalar status.");
        }
        if(!fields.TryGetValue("enabled",out var enabled)||enabled is not (1 or 2)||!fields.TryGetValue("pid",out var pid)||pid<=1||pid>int.MaxValue)throw new InvalidDataException("Active kernel audit identity unavailable.");
        return (int)pid;
    }
}
