using System.Globalization;
using System.Text.Json.Serialization;

namespace RansomFree.Contracts;

// This is the SIEM representation of sq_lease.h ABI 2. Native 64-bit fields
// are decimal strings, including values larger than JavaScript's exact range.
public sealed record LinuxActorLeaseEvidence
{
    public int SchemaVersion {get;init;}=2;
    public int StructSize {get;init;}=160;
    public string Id {get;init;}="";
    public string Cookie {get;init;}="";
    public string StartedNs {get;init;}="";
    public string FinishedNs {get;init;}="";
    public string DeadlineNs {get;init;}="";
    public string Size {get;init;}="";
    public string Inode {get;init;}="";
    public string Device {get;init;}="";
    public string Bytes {get;init;}="";
    public string ProcessId {get;init;}="";
    public string ThreadId {get;init;}="";
    public string ProcessStartNs {get;init;}="";
    public string TaskStartNs {get;init;}="";
    public string SelfExecId {get;init;}="";
    public string AssociationGeneration {get;init;}="";
    public string ProviderEpoch {get;init;}="";
    public uint State {get;init;}
    public int Error {get;init;}
    public uint WriteLease {get;init;}
    public uint MetadataChanged {get;init;}
    public uint AssociationState {get;init;}
    public int AssociationError {get;init;}
    private static ulong Number(string value)=>ulong.Parse(value,NumberStyles.None,CultureInfo.InvariantCulture);
    public bool IsValid()=>SchemaVersion==2&&StructSize==160&&
        new[]{Id,Cookie,StartedNs,FinishedNs,DeadlineNs,Size,Inode,Device,Bytes,ProcessId,ThreadId,ProcessStartNs,TaskStartNs,SelfExecId,AssociationGeneration,ProviderEpoch}.All(LinuxKernelEvidence.Decimal)&&
        Number(Id) is >0 and <=long.MaxValue&&Number(Size) is >0 and <=4194304&&Number(Bytes)<=Number(Size)&&
        Number(Device)<=uint.MaxValue&&Number(ProcessId) is >0 and <=int.MaxValue&&Number(ThreadId) is >0 and <=uint.MaxValue&&
        State is >=1 and <=6&&Error is >=-4095 and <=0&&WriteLease<=1&&MetadataChanged<=1&&AssociationState<=2&&AssociationError is >=-4095 and <=0;
    [JsonIgnore] public bool Ready=>IsValid()&&State==3&&Error==0&&Bytes==Size&&WriteLease==0&&Number(StartedNs)>0&&Number(FinishedNs)>=Number(StartedNs)&&Number(FinishedNs)<Number(DeadlineNs);
    [JsonIgnore] public string ProcessStartKey=>ProviderEpoch+":"+ProcessStartNs+":"+SelfExecId;
    [JsonIgnore] public string SourceStableId=>"linux-kernel-device:"+Device+":inode:"+Inode;
    public bool Matches(LinuxKernelEvidence k)=>IsValid()&&k.IsValid()&&k.Lease>0&&k.Reservation==k.Lease&&k.FinalizeError==0&&
        Id==k.Lease.ToString(CultureInfo.InvariantCulture)&&Cookie==k.Cookie&&ProviderEpoch==k.ProviderEpoch&&ProcessId==k.ProcessId?.ToString(CultureInfo.InvariantCulture)&&
        ThreadId==k.ThreadId?.ToString(CultureInfo.InvariantCulture)&&ProcessStartNs==k.ProcessStartNs&&TaskStartNs==k.TaskStartNs&&SelfExecId==k.SelfExecId&&
        Inode==k.ActorInode&&Device==k.ActorDevice.ToString(CultureInfo.InvariantCulture)&&AssociationGeneration==k.AssociationAfter&&AssociationError==k.AssociationError&&
        AssociationState==(AssociationError==0?1u:2u);
}

// Source actor identity and private snapshot identity must remain separate.
// This evidence establishes referenced backing bytes; it is not a verdict on
// executed memory, file provenance, or whitelist eligibility.
public sealed record LinuxActorAcquisitionEvidence
{
    public int Version {get;init;}=1;
    public string Method {get;init;}="linux-operation-bound-retained-backing-bytes";
    public string ContentSemantics {get;init;}="backing-file-interval-read; not-atomic-or-executed-memory";
    public string SourceEventId {get;init;}="";
    public string NativeObservationSha256 {get;init;}="";
    public LinuxActorLeaseEvidence? NativeStatus {get;init;}
    public string? SnapshotId {get;init;}
    public string? SnapshotSha256 {get;init;}
    public FileIdentityEvidence? SnapshotFile {get;init;}
    public DateTimeOffset? PersistedUtc {get;init;}
    public bool? SizeMatchesEarlierObservation {get;init;}
    public bool WhitelistEligible {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-acquired");
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public EvidenceStatus? RecoveryStatus {get;init;}

    private static bool Hash(string? s)=>s is {Length:64}&&s.All(Uri.IsHexDigit);
    private static bool StatusValid(EvidenceStatus? s)=>s!=null&&s.State is "captured" or "unavailable" or "failed"&&s.Reason is {Length:>0 and <=256}&&(s.NativeCode==null||s.NativeCode.Length<=128);
    public bool IsValid(ProcessInstanceEvidence p,string eventId,string? relatedEventId,string? actorHash,FileIdentityEvidence source)
    {
        if(Version!=1||Method!="linux-operation-bound-retained-backing-bytes"||ContentSemantics!="backing-file-interval-read; not-atomic-or-executed-memory"||WhitelistEligible||
            !Guid.TryParseExact(SourceEventId,"N",out _)||SourceEventId!=eventId&&SourceEventId!=relatedEventId||!Hash(NativeObservationSha256)||!StatusValid(Status)||p==null||source==null||
            NativeStatus!=null&&!NativeStatus.IsValid()||RecoveryStatus!=null&&(!StatusValid(RecoveryStatus)||RecoveryStatus.State!="failed"||Status.State!="captured"||actorHash!=null))return false;
        if(Status.State!="captured")return SnapshotId==null&&SnapshotSha256==null&&SnapshotFile==null&&PersistedUtc==null&&SizeMatchesEarlierObservation==null&&actorHash==null;
        var n=NativeStatus;var f=SnapshotFile;
        return n?.Ready==true&&p.Pid?.ToString(CultureInfo.InvariantCulture)==n.ProcessId&&p.ThreadId?.ToString(CultureInfo.InvariantCulture)==n.ThreadId&&p.StartKey==n.ProcessStartKey&&p.StartedUtc==null&&p.Creation==null&&
            Guid.TryParseExact(SnapshotId,"N",out _)&&Hash(SnapshotSha256)&&(actorHash==null||string.Equals(actorHash,SnapshotSha256,StringComparison.OrdinalIgnoreCase))&&
            PersistedUtc!=null&&PersistedUtc!=default(DateTimeOffset)&&SizeMatchesEarlierObservation!=null&&
            f!=null&&f.Size?.ToString(CultureInfo.InvariantCulture)==n.Size&&f.StableId is {Length:>0 and <=256}&&f.ChangeMarker is {Length:>0 and <=256}&&f.Status?.State=="captured"&&StatusValid(f.Status)&&
            (f.ResolvedPath==null||f.ResolvedPath.Length<=32768)&&source.StableId==n.SourceStableId&&source.Size==f.Size&&
            source.CreatedUtc==null&&source.ModifiedUtc==null&&source.AccessedUtc==null&&source.ChangedUtc==null&&source.ChangeMarker==null&&source.Status?.State=="captured";
    }
    public bool Matches(LinuxKernelEvidence k)=>StatusValid(Status)&&k.IsValid()&&string.Equals(NativeObservationSha256,k.NativeObservationSha256,StringComparison.OrdinalIgnoreCase)&&
        (NativeStatus==null||NativeStatus.Matches(k))&&(Status.State!="captured"||NativeStatus!=null&&SizeMatchesEarlierObservation==(NativeStatus.Size==k.ActorSize));
}
