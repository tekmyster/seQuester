namespace RansomFree.Contracts;

// Additive companion schema, negotiated independently of forensic-v1. Strings
// describe the creation notification, not the current process or a safety verdict.
public sealed record WindowsProcessCreationEvidence
{
    public int Version {get;init;}=1;
    public string? RawSha256 {get;init;}
    public DateTimeOffset? CapturedUtc {get;init;}
    public ulong? Monotonic {get;init;}
    public ulong? CreatorPid {get;init;}
    public ulong? CreatorTid {get;init;}
    public long? CreatorCreatedFileTime {get;init;}
    public EvidenceStatus CreatorStatus {get;init;}=EvidenceStatus.Unavailable("creation-not-collected");
    public ulong? ReportedParentPid {get;init;}
    public long? ParentCreatedFileTime {get;init;}
    public string? ImageName {get;init;}
    public bool? FileOpenNameAvailable {get;init;}
    public uint? ImageOriginalBytes {get;init;}
    public uint? ImageStoredBytes {get;init;}
    public EvidenceStatus ImageStatus {get;init;}=EvidenceStatus.Unavailable("creation-not-collected");
    public uint? CommandOriginalBytes {get;init;}
    public uint? CommandStoredBytes {get;init;}
    public string? NotificationCreationStatus {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("creation-not-collected");

    public bool IsValid(ProcessInstanceEvidence process,ActorAcquisitionEvidence? acquisition)
    {
        static bool StatusOk(EvidenceStatus? s)=>s!=null&&s.State is "captured" or "partial" or "unavailable" or "failed"&&s.Reason is {Length:>0 and <=256}&&(s.NativeCode==null||s.NativeCode.Length<=128);
        static bool Code(string? s)=>s?.Length==10&&s.StartsWith("0x",StringComparison.Ordinal)&&s[2..].All(Uri.IsHexDigit);
        if(Version!=1||!StatusOk(Status)||!StatusOk(CreatorStatus)||!StatusOk(ImageStatus)||acquisition?.ProcessGeneration==null)return false;
        if(Status.State!="captured")return RawSha256==null&&CapturedUtc==null&&Monotonic==null&&CreatorPid==null&&CreatorTid==null&&CreatorCreatedFileTime==null&&ReportedParentPid==null&&ParentCreatedFileTime==null&&ImageName==null&&FileOpenNameAvailable==null&&ImageOriginalBytes==null&&ImageStoredBytes==null&&CommandOriginalBytes==null&&CommandStoredBytes==null&&NotificationCreationStatus==null;
        if(RawSha256 is not {Length:64}||!RawSha256.All(Uri.IsHexDigit)||CapturedUtc==null||Monotonic==null||CreatorPid==null||CreatorTid==null||ReportedParentPid==null||!Code(NotificationCreationStatus)||FileOpenNameAvailable==null||
            ImageOriginalBytes is not <=65535||ImageStoredBytes is not <=1024||ImageStoredBytes%2!=0||ImageStoredBytes>ImageOriginalBytes||ImageName?.Length>512||
            CommandOriginalBytes is not <=65535||CommandStoredBytes is not <=4096||CommandStoredBytes%2!=0||CommandStoredBytes>CommandOriginalBytes||process.CommandLine?.Length>2048)return false;
        if(CreatorCreatedFileTime is <=0 or >2650467743999999999||ParentCreatedFileTime is <=0 or >2650467743999999999)return false;
        if(CreatorStatus.State=="captured"?CreatorCreatedFileTime==null:CreatorCreatedFileTime!=null)return false;
        if(ParentCreatedFileTime!=null&&(ReportedParentPid!=CreatorPid||ParentCreatedFileTime!=CreatorCreatedFileTime||CreatorStatus.State!="captured"))return false;
        var parent=ReportedParentPid is >0 and <=int.MaxValue?(int?)ReportedParentPid:null;
        return process.ParentPid==parent&&process.ParentStartKey==ParentCreatedFileTime?.ToString(System.Globalization.CultureInfo.InvariantCulture)&&
            process.ParentStartedUtc==(ParentCreatedFileTime is {} start?DateTimeOffset.FromFileTime(start):(DateTimeOffset?)null)&&
            (ParentCreatedFileTime!=null?process.ParentStatus.State=="captured":process.ParentInstanceId==null&&process.ParentStatus.State=="unavailable");
    }
}
