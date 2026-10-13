namespace RansomFree.Contracts;

// A syscall return is separate from a filesystem completion or minifilter event.
// The native UUID identifies a driver lifetime. The target name is queried later
// from its retained file object; it is not a pre-operation path snapshot.
public sealed record WindowsSyscallObservation
{
    public int Version {get;init;}=1;
    public string SourceInstance {get;init;}="";
    public string SourceInstanceStatus {get;init;}="";
    public string Scope {get;init;}="owned-thread-registered-handles";
    public WindowsSyscallEvidence Native {get;init;}=new();
    public string? NativeTargetPath {get;init;}
    public string? TargetPath {get;init;}
    public DateTimeOffset TargetQueriedUtc {get;init;}
    public EvidenceStatus TargetStatus {get;init;}=EvidenceStatus.Unavailable("retained-target-name-not-queried");
    // Preserve undecodable name bytes without inventing a display path. Optional
    // additive fields retain compatibility with previously stored observations.
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetReplySha256 {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? UnavailableTargetNameBase64 {get;init;}
    public long LostRecords {get;init;}
    public bool IsValid()=>Version==1&&Guid.TryParseExact(SourceInstance,"N",out var id)&&id!=Guid.Empty&&
        SourceInstanceStatus is "0x00000000" or "0x40020056"&&Scope=="owned-thread-registered-handles"&&Native?.IsValid()==true&&
        LostRecords>=0&&TargetQueriedUtc!=default&&TargetStatus is {State:"captured" or "unavailable",Reason.Length:>0 and <=256}&&
        (TargetStatus.State=="captured"?NativeTargetPath is {Length:>0 and <=1535}&&TargetPath is {Length:>0 and <=4096}:NativeTargetPath==null&&TargetPath==null)&&
        (TargetStatus.NativeCode==null||TargetStatus.NativeCode is {Length:10}&&TargetStatus.NativeCode.StartsWith("0x",StringComparison.Ordinal)&&TargetStatus.NativeCode[2..].All(Uri.IsHexDigit))&&
        (TargetReplySha256==null||TargetReplySha256 is {Length:64}&&TargetReplySha256.All(Uri.IsHexDigit))&&
        ValidUnavailableName()&&
        (NativeTargetPath==null||!NativeTargetPath.Any(char.IsControl))&&(TargetPath==null||!TargetPath.Any(char.IsControl));
    private bool ValidUnavailableName()
    {
        if(UnavailableTargetNameBase64==null)return TargetStatus.Reason!="retained-target-name-not-displayable";
        if(TargetStatus.State!="unavailable"||TargetStatus.Reason!="retained-target-name-not-displayable"||TargetReplySha256==null||UnavailableTargetNameBase64.Length is 0 or >4096)return false;
        try{var bytes=Convert.FromBase64String(UnavailableTargetNameBase64);return bytes.Length is >0 and <=3070&&bytes.Length%2==0&&Convert.ToBase64String(bytes)==UnavailableTargetNameBase64;}
        catch(FormatException){return false;}
    }
    public string ObservationId=>SourceInstance+":"+Native.Sequence;
    public static bool Matches(AgentEvent e)=>e.Attribution?.WindowsSyscall is not {} s?e.Source!="Windows syscall"&&e.Forensics?.ActorExecutable.Acquisition?.Version!=2:s.IsValid()&&
        e.Source is "Windows syscall" or "Forensic enrichment" or "Evidence transfer" or "Agent response"&&e.Attribution.Provider=="Windows syscall"&&
        e.ProcessId==s.Native.ProcessId&&e.Attribution.UserSid==s.Native.ThreadEffective.Sid&&
        e.Attribution.ProcessStartTicks==s.Native.ProcessCreatedFileTime.ToString(System.Globalization.CultureInfo.InvariantCulture)&&
        e.Attribution.EvidenceId==s.ObservationId&&e.Attribution.OsStatus==s.Native.ReturnStatus&&
        (e.Source!="Windows syscall"||e.ObservedUtc==s.Native.EntryUtc&&e.Path==(s.TargetPath??"Unavailable"))&&
        (e.Forensics?.ActorExecutable.Acquisition is not {} a||a.Version==2&&a.SyscallSourceInstance==s.SourceInstance&&
            a.EventSequence==s.Native.Sequence&&a.SyscallRecordSha256==s.Native.RawRecordSha256&&a.ProcessId==s.Native.ProcessId&&a.ProcessCreatedFileTime==s.Native.ProcessCreatedFileTime);
}
