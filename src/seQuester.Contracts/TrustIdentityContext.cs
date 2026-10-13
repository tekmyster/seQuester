using System.Globalization;
namespace RansomFree.Contracts;

// Derive selectors from validated native operation evidence, never from a later
// PID lookup or an arbitrary claimed owner. Capture session also prevents rules
// surviving source restart/reboot; it is explicitly not called an OS boot ID.
public static class TrustIdentityContext
{
    public static string? SidAuthority(string sid)
    {
        if(sid is not {Length:>=7 and <=184}||!System.Text.RegularExpressions.Regex.IsMatch(sid,@"\AS-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100)))return null;
        return sid.StartsWith("S-1-5-21-",StringComparison.Ordinal)?"sid-domain:"+sid[..sid.LastIndexOf('-')]:"sid-authority:"+sid[..sid.LastIndexOf('-')];
    }
    public static TrustContext Bind(TrustContext context,AgentEvent value)
    {
        TrustActor? owner=null,effective=null;TrustProcessSelector? instance=null;
        if(value.Source=="Windows minifilter"&&value.Attribution?.WindowsKernel is {} windows&&windows.IsValid()&&WindowsKernelEvidence.Matches(value))
        {
            TrustActor? Principal(WindowsTokenSnapshot token)=>token.Captured==31&&token.Sid is {} sid&&SidAuthority(sid) is {} authority?new(Authority:authority,AccountId:sid,AccountKind:"sid",Verified:true):null;
            if(windows.CaptureIrql==0){owner=Principal(windows.RequestorPrimary);effective=Principal(windows.ThreadEffective);}
            if(windows.ProcessId is {} pid&&windows.ProcessCreatedFileTime is {} birth)instance=new(context.Host,pid,birth.ToString(CultureInfo.InvariantCulture),"windows:"+windows.Instance);
        }
        else if(value.Source=="Linux kernel"&&value.Attribution?.LinuxKernel is {} linux&&linux.IsValid()&&LinuxKernelEvidence.Matches(value))
        {
            TrustActor? Principal(uint? uid)=>linux.CredentialFields==63&&linux.CredentialError==0&&uid is {} id&&id!=uint.MaxValue?new(Authority:context.Host,AccountId:id.ToString(CultureInfo.InvariantCulture),AccountKind:"uid",Verified:true):null;
            // Linux credentials belong to the accessing task; do not label a
            // non-leader thread's real UID as the thread-group owner's UID.
            owner=linux.ThreadId==linux.ProcessId?Principal(linux.Uid):null;effective=Principal(linux.FileSystemUid);
            if(linux.ProcessId is {} pid&&linux.ProcessStartNs!="0")instance=new(context.Host,pid,linux.ProcessStartNs,"linux:"+linux.ProviderEpoch+":"+linux.CollectorInstance);
        }
        return context with{ProcessOwner=owner,EffectiveUser=effective,ProcessInstance=instance};
    }
}
