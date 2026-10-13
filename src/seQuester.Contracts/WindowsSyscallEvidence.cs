namespace RansomFree.Contracts;

// Separate from minifilter evidence: these are native syscall entry/return
// observations, including failures before filesystem dispatch. Collection does
// not establish detection, trust, final asynchronous completion or preservation.
public sealed record WindowsSyscallEvidence
{
    public int Version {get;init;}=1;
    public long Sequence {get;init;}
    public DateTimeOffset EntryUtc {get;init;}
    public DateTimeOffset ReturnUtc {get;init;}
    public long EntryMonotonic {get;init;}
    public long ReturnMonotonic {get;init;}
    // Native research v1 does not emit a frequency. Never substitute a constant.
    public long? MonotonicFrequency {get;init;}
    public uint ProcessId {get;init;}
    public uint ThreadId {get;init;}
    public long ProcessCreatedFileTime {get;init;}
    public string ProcessInstanceKey=>$"{ProcessId:X8}:{ProcessCreatedFileTime:X16}";
    public string TargetHandle {get;init;}="";
    public uint Operation {get;init;}
    public uint InformationClass {get;init;}
    public uint RequestedLength {get;init;}
    public string ReturnStatus {get;init;}="";
    public string AttributionStatus {get;init;}="";
    public string FileObjectStatus {get;init;}="";
    public bool? ThreadImpersonating {get;init;}
    public uint CaptureIrql {get;init;}
    public uint RequestorMode {get;init;}
    public WindowsTokenSnapshot ProcessOwner {get;init;}=new();
    public WindowsTokenSnapshot ThreadEffective {get;init;}=new();
    public string RawRecordSha256 {get;init;}="";
    public long? BytesTransferred {get;init;}
    public string ByteCountStatus {get;init;}="unavailable: native v1 captures submission status only";
    public string Outcome=>ReturnStatus=="0x00000103"?"pending":
        ReturnStatus is {Length:10}&&uint.TryParse(ReturnStatus.AsSpan(2),System.Globalization.NumberStyles.HexNumber,null,out var s)?
        unchecked((int)s)<0?"failed":"success":"unknown";
    public bool IsValid()
    {
        static bool Status(string s)=>s is {Length:10}&&s.StartsWith("0x",StringComparison.Ordinal)&&s[2..].All(Uri.IsHexDigit);
        static bool SameToken(WindowsTokenSnapshot a,WindowsTokenSnapshot b)=>
            a.Captured==b.Captured&&a.Sid==b.Sid&&a.TokenId==b.TokenId&&
            a.AuthenticationId==b.AuthenticationId&&a.ModifiedId==b.ModifiedId&&a.Type==b.Type&&
            a.ImpersonationLevel==b.ImpersonationLevel&&a.SessionId==b.SessionId&&
            a.IntegrityRid==b.IntegrityRid&&a.Elevated==b.Elevated&&a.QueryStatus.SequenceEqual(b.QueryStatus);
        return Version==1&&Sequence>0&&EntryUtc!=default&&ReturnUtc!=default&&
            EntryMonotonic>=0&&ReturnMonotonic>=EntryMonotonic&&MonotonicFrequency==null&&
            ProcessId>0&&ThreadId>0&&ProcessCreatedFileTime is >0 and <=2650467743999999999&&
            TargetHandle is {Length:16}&&TargetHandle.All(Uri.IsHexDigit)&&
            Operation is 1 or 2 or 3&&(Operation==3||InformationClass==0)&&
            Status(ReturnStatus)&&Status(AttributionStatus)&&Status(FileObjectStatus)&&
            CaptureIrql==0&&RequestorMode is 0 or 1&&ThreadImpersonating!=null&&
            ProcessOwner?.IsValid()==true&&ThreadEffective?.IsValid()==true&&
            (ThreadImpersonating!=false||SameToken(ProcessOwner,ThreadEffective))&&
            RawRecordSha256 is {Length:64}&&RawRecordSha256.All(Uri.IsHexDigit)&&
            BytesTransferred==null&&ByteCountStatus=="unavailable: native v1 captures submission status only";
    }
}
