namespace RansomFree.Contracts;

// Versioned independently so older forensic-v1 senders remain compatible.
// Source file metadata describes the actor; SnapshotFile describes the private copy.
public sealed record ActorAcquisitionEvidence
{
    public int Version {get;init;}=1;
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? SyscallSourceInstance {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? SyscallRecordSha256 {get;init;}
    public string Method {get;init;}="windows-operation-bound-backing-bytes";
    public string SourceEventId {get;init;}="";
    public string Provider {get;init;}="";
    public string ProviderStatus {get;init;}="";
    public string ProviderScope {get;init;}="unknown";
    public string EventInstance {get;init;}="";
    public long EventSequence {get;init;}
    public string? ProcessGeneration {get;init;}
    public string BindingKind {get;init;}="unavailable";
    public string? CandidateId {get;init;}
    public int? ProcessId {get;init;}
    public long? ProcessCreatedFileTime {get;init;}
    public string? SourceFileIndex {get;init;}
    public EvidenceStatus SourceIdentityStatus {get;init;}=EvidenceStatus.Unavailable("source-volume-identity-not-collected; file-index-is-not-global");
    public uint? OriginalRequestedAccess {get;init;}
    public uint? MappedRequestedAccess {get;init;}
    public uint? AccessQualificationVersion {get;init;}
    public string? CreateStatus {get;init;}
    public DateTimeOffset? CopyStartedUtc {get;init;}
    public DateTimeOffset? CopyEndedUtc {get;init;}
    public string ContentSemantics {get;init;}="backing-file-interval-read; not-atomic-or-executed-memory";
    public string? SnapshotId {get;init;}
    public string? SnapshotSha256 {get;init;}
    public FileIdentityEvidence? SnapshotFile {get;init;}
    public DateTimeOffset? PersistedUtc {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-acquired");
    // Status above is the historical acquisition. A later recovery failure does
    // not erase its original hash/identity or authorize use of the current file.
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public EvidenceStatus? RecoveryStatus {get;init;}

    public bool IsValidSourceFile(FileIdentityEvidence file)
    {
        if(file is null||file.Status is null||SourceIdentityStatus is null)return false;
        if(SourceIdentityStatus.State!="captured")return file.StableId==null;
        const string prefix="windows-volume-guid:";var suffix=":file-index:"+SourceFileIndex;
        return SourceIdentityStatus.Reason=="ntfs-volume-guid-and-file-index-at-source-copy"&&SourceIdentityStatus.NativeCode=="0x00000000"&&
            SourceFileIndex is {Length:16}&&SourceFileIndex!="0000000000000000"&&file.Status.State=="captured"&&file.StableId is {} id&&
            id.Length==prefix.Length+32+suffix.Length&&id.StartsWith(prefix,StringComparison.Ordinal)&&id.EndsWith(suffix,StringComparison.Ordinal)&&Guid.TryParseExact(id.AsSpan(prefix.Length,32),"N",out _);
    }

    public bool IsValid(ProcessInstanceEvidence process,string eventId,string? relatedEventId,string? actorHash)
    {
        static bool Hex(string? s,int n)=>s?.Length==n&&s.All(Uri.IsHexDigit);
        static bool Code(string? s)=>s?.Length==10&&s.StartsWith("0x",StringComparison.Ordinal)&&s[2..].All(Uri.IsHexDigit);
        static bool StatusOk(EvidenceStatus? s)=>s!=null&&s.State is "captured" or "unavailable" or "failed"&&s.Reason is {Length:>0 and <=256}&&(s.NativeCode==null||s.NativeCode.Length<=128);
        if(Version==1?Method!="windows-operation-bound-backing-bytes"||SyscallSourceInstance!=null||SyscallRecordSha256!=null:
            Version!=2||Method!="windows-process-snapshot-bound-to-syscall"||!Guid.TryParseExact(SyscallSourceInstance,"N",out var syscallId)||syscallId==Guid.Empty||!Hex(SyscallRecordSha256,64))return false;
        if(!Guid.TryParseExact(SourceEventId,"N",out _)||SourceEventId!=eventId&&SourceEventId!=relatedEventId||
            !Hex(Provider,32)||!Code(ProviderStatus)||!Hex(EventInstance,16)||EventSequence<=0||!StatusOk(Status)||!StatusOk(SourceIdentityStatus)||
            ContentSemantics!="backing-file-interval-read; not-atomic-or-executed-memory"||
            ProviderScope!=(ProviderStatus=="0x00000000"?"os-uuid":ProviderStatus=="0x40020056"?"local-only":"unknown"))return false;
        if((ProcessGeneration==null)!=(CandidateId==null)||(ProcessGeneration==null)!=(ProcessId==null)||(ProcessGeneration==null)!=(ProcessCreatedFileTime==null))return false;
        if(ProcessGeneration==null?BindingKind!="unavailable":BindingKind is not ("bytes-pinned" or "process-generation-only"))return false;
        if(ProcessGeneration!=null&&(!Hex(ProcessGeneration,16)||ProcessGeneration=="0000000000000000"||!Hex(CandidateId,16)||CandidateId=="0000000000000000"||ProcessId is not >0||ProcessCreatedFileTime is not >0||process.Pid!=ProcessId||process.StartKey!=ProcessCreatedFileTime.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)))return false;
        if(SourceFileIndex!=null&&!Hex(SourceFileIndex,16)||CreateStatus!=null&&!Code(CreateStatus))return false;
        if(RecoveryStatus!=null&&(!StatusOk(RecoveryStatus)||RecoveryStatus.State!="failed"||Status.State!="captured"||actorHash!=null))return false;
        if(Status.State!="captured")return SnapshotId==null&&SnapshotSha256==null&&SnapshotFile==null&&PersistedUtc==null;
        var f=SnapshotFile;
        return ProcessGeneration!=null&&Guid.TryParseExact(SnapshotId,"N",out _)&&Hex(SnapshotSha256,64)&&(actorHash==null||string.Equals(actorHash,SnapshotSha256,StringComparison.OrdinalIgnoreCase))&&
            PersistedUtc!=null&&PersistedUtc!=default(DateTimeOffset)&&CopyStartedUtc!=null&&CopyEndedUtc!=null&&OriginalRequestedAccess!=null&&MappedRequestedAccess!=null&&AccessQualificationVersion==2&&CreateStatus!=null&&
            f!=null&&f.Size is >0 and <=8388608&&f.StableId is {Length:>0 and <=256}&&f.ChangeMarker is {Length:>0 and <=256}&&(f.ResolvedPath==null||f.ResolvedPath.Length<=32768)&&f.Status?.State=="captured"&&StatusOk(f.Status);
    }
}
