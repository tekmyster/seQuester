using System.Security.Cryptography;
using System.Text;
using RansomFree.Contracts;

namespace RansomFree.Client;

public static class WindowsSyscallEvent
{
    public static AgentEvent Create(string sensor,WindowsSyscallObservation observation)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||!observation.IsValid()||observation.Native.ProcessId>int.MaxValue)
            throw new InvalidDataException("Invalid syscall source observation");
        var n=observation.Native;
        var id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensor+":"+observation.ObservationId)).AsSpan(0,16)).ToLowerInvariant();
        var op=n.Operation switch{1=>"Content read (copy possible)",2=>"Content written",3 when n.InformationClass is 10 or 65=>"File renamed",3 when n.InformationClass is 13 or 64=>"Delete requested",3 when n.InformationClass==20=>"File truncated",_=>"File metadata changed"};
        return new(id,n.EntryUtc,op,observation.TargetPath??"Unavailable",n.ThreadEffective.Sid,null,(int)n.ProcessId,"Windows syscall")
        {Attribution=new(){Provider="Windows syscall",Level="Partial attribution",EvidenceId=observation.ObservationId,
            Basis="Native syscall entry/return tokens. Process owner and effective thread identity remain separate. Target name is a later query of the retained file object. Actor executable acquisition is independently linked by exact process creation identity. Scope: "+observation.Scope,
            UserSid=n.ThreadEffective.Sid,UserName=null,LogonId=n.ThreadEffective.AuthenticationId,OsStatus=n.ReturnStatus,
            ProcessStartTicks=n.ProcessCreatedFileTime.ToString(System.Globalization.CultureInfo.InvariantCulture),
            EventTimeCredentials=n.ProcessOwner.Captured==31&&n.ThreadEffective.Captured==31,CompleteRecordSet=false,
            Outcome=n.Outcome,WindowsSyscall=observation}};
    }
}
