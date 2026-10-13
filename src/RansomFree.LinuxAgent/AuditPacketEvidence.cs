using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal static class AuditPacketEvidence
{
    static bool Text(string? value,int maximum,bool required=false)=>value is not null&&(!required||!string.IsNullOrWhiteSpace(value))&&value.Length<=maximum&&!value.Any(char.IsControl);
    public static AuditPacket Normalize(AuditPacket packet)
    {
        if(!Text(packet.Identity,160,true)||packet.Pid is <0||packet.Paths is not {Length:>=0 and <=128}
            ||packet.Paths.Length==0&&(packet.Attribution is not {CompleteRecordSet:false,PathRole:"UNAVAILABLE"})
            ||packet.Paths.Any(p=>p==null||!Text(p.Path,2048,true)||!p.Path.StartsWith('/')||!Text(p.Role,32))
            ||packet.Executable is not null&&!Text(packet.Executable,1024)||!Text(packet.Operation,64,true)
            ||packet.ObservedUtc>DateTimeOffset.UtcNow.AddMinutes(5)||packet.ObservedUtc==default)
            throw new InvalidDataException("Malformed audit packet; original evidence must be retained.");
        var a=packet.Attribution??new EventAttribution{Provider="Linux Audit",Level="Detection only",Basis="Audit packet had no attribution record.",EvidenceId=packet.Identity};
        if(!a.IsValid()||a.Provider!="Linux Audit")throw new InvalidDataException("Invalid audit attribution contract.");
        var missing=new List<string>();
        if(packet.Pid is not >0)missing.Add("PID");
        if(string.IsNullOrWhiteSpace(packet.Executable))missing.Add("executable");
        if(a.UserId==null&&a.EffectiveUserId==null&&a.FileSystemUserId==null)missing.Add("user IDs");
        if(missing.Count>0)
        {
            var detail="Missing "+string.Join(", ",missing)+"; partial detection retained.";
            var basis=a.Basis??"";basis=basis[..Math.Min(basis.Length,Math.Max(0,510-detail.Length))];
            a=a with{Level=missing.Count==3?"Detection only":"Partial attribution",Basis=basis+" "+detail};
        }
        return packet with{Executable=packet.Executable??"",Attribution=a};
    }
    public static string? User(EventAttribution a)
    {
        var actor=a.FileSystemUserId is {} fs?"fsuid:"+fs:a.EffectiveUserId is {} effective?"euid:"+effective:a.UserId is {} real?"uid:"+real:null;
        if(actor==null)return null;
        return $"{actor}; uid:{a.UserId?.ToString()??"unknown"} euid:{a.EffectiveUserId?.ToString()??"unknown"} loginuid:{a.LoginUserId?.ToString()??"unset"}";
    }
}
