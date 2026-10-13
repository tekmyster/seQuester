using System.Text.Json;
namespace RansomFree.Contracts;

// Additive evidence contract. Null is unknown; status explains why. None of these fields is a safety verdict.
public sealed record EvidenceStatus(string State,string Reason,string? NativeCode=null)
{
    public static EvidenceStatus Unavailable(string reason)=>new("unavailable",reason);
    public static EvidenceStatus Captured(string reason)=>new("captured",reason);
}
public sealed record FileIdentityEvidence
{
    public string? StableId {get;init;}
    public long? Size {get;init;}
    public DateTimeOffset? CreatedUtc {get;init;}
    public DateTimeOffset? ModifiedUtc {get;init;}
    public DateTimeOffset? AccessedUtc {get;init;}
    public DateTimeOffset? ChangedUtc {get;init;}
    public string? ChangeMarker {get;init;}
    public string? ResolvedPath {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-collected");
}
public sealed record PrincipalEvidence
{
    public string? Sid {get;init;}
    public string? Account {get;init;}
    public uint? Uid {get;init;}
    public uint? EffectiveUid {get;init;}
    public uint? FileSystemUid {get;init;}
    public uint? Gid {get;init;}
    public uint? EffectiveGid {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public uint? FileSystemGid {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? CredentialNamespace {get;init;}
    public uint[]? SupplementaryGroups {get;init;}
    public string? LogonId {get;init;}
    public uint? SessionId {get;init;}
    public string? IntegritySid {get;init;}
    public bool? Elevated {get;init;}
    public string? TokenType {get;init;}
    public string? TokenId {get;init;}
    public string? AuthenticationId {get;init;}
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-collected");
}
public sealed record ProcessInstanceEvidence
{
    public int? Pid {get;init;}
    public string? InstanceId {get;init;}
    public string? StartKey {get;init;}
    public DateTimeOffset? StartedUtc {get;init;}
    public int? ParentPid {get;init;}
    public string? ParentStartKey {get;init;}
    public DateTimeOffset? ParentStartedUtc {get;init;}
    public string? ParentInstanceId {get;init;}
    public string? ParentExecutablePath {get;init;}
    public EvidenceStatus ParentStatus {get;init;}=EvidenceStatus.Unavailable("parent-not-collected");
    public uint? ProcessSessionId {get;init;}
    public EvidenceStatus SessionStatus {get;init;}=EvidenceStatus.Unavailable("process-session-not-collected");
    public string? ExecutablePath {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsProcessCreationEvidence? Creation {get;init;}
    public string? CommandLine {get;init;}
    public EvidenceStatus CommandLineStatus {get;init;}=EvidenceStatus.Unavailable("provider-does-not-supply-command-line");
    public PrincipalEvidence Owner {get;init;}=new();
    public PrincipalEvidence? ThreadOwner {get;init;}
    public long? ThreadOwnerCreatedFileTime {get;init;}
    public PrincipalEvidence EventSubject {get;init;}=new();
    public PrincipalEvidence ThreadToken {get;init;}=new(){Status=EvidenceStatus.Unavailable("provider-does-not-supply-actor-thread-id")};
    public bool? Impersonating {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public uint? ThreadId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public PrincipalEvidence? EffectiveThreadContext {get;init;}
    public EvidenceStatus ImpersonationStatus {get;init;}=EvidenceStatus.Unavailable("event-subject-is-separate-from-later-process-owner");
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-collected");
}
public sealed record SignatureEvidence
{
    public string Kind {get;init;}="unknown";
    public bool? Present {get;init;}
    public bool? Valid {get;init;}
    public string? Signer {get;init;}
    public string? Publisher {get;init;}
    public string? Issuer {get;init;}
    public string? Thumbprint {get;init;}
    public DateTimeOffset? NotBeforeUtc {get;init;}
    public DateTimeOffset? NotAfterUtc {get;init;}
    public string? ChainStatus {get;init;}
    public bool? TimestampPresent {get;init;}
    public bool? TimestampValid {get;init;}
    public string? TimestampStatus {get;init;}
    public string? TrustStatus {get;init;}
    public string? CatalogPath {get;init;}
    public string RevocationMode {get;init;}="cache-only";
    public EvidenceStatus Status {get;init;}=EvidenceStatus.Unavailable("not-collected");
}
public sealed record ExecutableEvidence
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ActorAcquisitionEvidence? Acquisition {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxActorAcquisitionEvidence? LinuxAcquisition {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxNativeWorkEvidence? LinuxNativeWork {get;init;}
    public string? ObservedPath {get;init;}
    public FileIdentityEvidence File {get;init;}=new();
    public string? Sha256 {get;init;}
    public EvidenceStatus HashStatus {get;init;}=EvidenceStatus.Unavailable("not-collected");
    public SignatureEvidence Signature {get;init;}=new();
    public string? CompanyName {get;init;}
    public string? FileDescription {get;init;}
    public string? ProductName {get;init;}
    public string? ProductVersion {get;init;}
    public string? FileVersion {get;init;}
    public string? OriginalFilename {get;init;}
    public string? InternalName {get;init;}
    public string Location {get;init;}="unknown";
    public EvidenceStatus MetadataStatus {get;init;}=EvidenceStatus.Unavailable("not-collected");
    public EvidenceStatus BindingStatus {get;init;}=EvidenceStatus.Unavailable("not-bound-to-process-instance");
    public string? BindingSourceEventId {get;init;}
    public DateTimeOffset? BindingCapturedUtc {get;init;}
}
public sealed record TargetOperationEvidence
{
    public string? Path {get;init;}
    public string? RenameSource {get;init;}
    public string? RenameDestination {get;init;}
    public string? ExtensionBefore {get;init;}
    public string? ExtensionAfter {get;init;}
    public string[] Actions {get;init;}=[];
    public string? AccessMask {get;init;}
    public string? OsStatus {get;init;}
    public string? Outcome {get;init;}
    public long? BytesTransferred {get;init;}
    public long? Offset {get;init;}
    public long? Length {get;init;}
    public long? PreSize {get;init;}
    public long? PostSize {get;init;}
    public bool? Deleted {get;init;}
    public bool? Truncated {get;init;}
    public string Storage {get;init;}="unknown";
    public FileIdentityEvidence File {get;init;}=new();
    public EvidenceStatus IoStatus {get;init;}=EvidenceStatus.Unavailable("provider-does-not-supply-completed-byte-counts-or-offsets");
    public string HashPolicy {get;init;}="not-hashed-by-forensic-collector";
}
public sealed record PreservationEvidence
{
    public string? EvidenceId {get;init;}
    public string? ArtifactRelativePath {get;init;}
    public string? ManifestRelativePath {get;init;}
    public string? SourceEventId {get;init;}
    public string? ProcessInstanceId {get;init;}
    public string? OriginalPath {get;init;}
    public string? Sha256 {get;init;}
    public long? Size {get;init;}
    public DateTimeOffset? PreservedUtc {get;init;}
    public bool? HashMatched {get;init;}
    public string? ManifestSha256 {get;init;}
    public EvidenceStatus Status {get;init;}=new("not-requested","below-preservation-threshold");
}
public sealed record ForensicDetection(string Disposition,string Severity,string[] RuleIds,string[] ReasonCodes);
public sealed record ForensicResponse(string Action,string Status,string? RelatedEventId=null);
public sealed record ForensicEvidence
{
    public int Version {get;init;}=1;
    public string EventId {get;init;}="";
    public string? RelatedEventId {get;init;}
    public string SensorId {get;init;}="";
    public string CollectorEpoch {get;init;}="";
    public long CollectorSequence {get;init;}
    public long? ProcessSequence {get;init;}
    public long MonotonicTicks {get;init;}
    public long MonotonicFrequency {get;init;}
    public string? SourceSequence {get;init;}
    public DateTimeOffset ObservedUtc {get;init;}
    public DateTimeOffset CapturedUtc {get;init;}
    public DateTimeOffset? EnrichedUtc {get;init;}
    public ProcessInstanceEvidence Process {get;init;}=new();
    public TargetOperationEvidence Observation {get;init;}=new();
    public ExecutableEvidence ActorExecutable {get;init;}=new();
    public ForensicDetection Detection {get;init;}=new("alert","alert",[],["MONITORED_FILE_ACTIVITY"]);
    public PreservationEvidence Preservation {get;init;}=new();
    public ForensicResponse Response {get;init;}=new("none","not-requested");
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public EvidenceTransferEvidence? Transfer {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxIoPairEvidence? LinuxIoPair {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxPermissionPairEvidence? LinuxPermissionPair {get;init;}
    public EvidenceStatus Collection {get;init;}=new("pending","enrichment-queued");
    public bool IsValid()
    {
        static bool Text(string? x,int max)=>x==null||x.Length<=max;
        static bool Hash(string? x)=>x==null||x.Length==64&&x.All(Uri.IsHexDigit);
        static bool Status(EvidenceStatus? x)=>x!=null&&x.State is "captured" or "partial" or "unavailable" or "pending" or "failed" or "not-requested"&&x.Reason is {Length:>0 and <=256}&&Text(x.NativeCode,128);
        static bool File(FileIdentityEvidence? x)=>x!=null&&Text(x.StableId,256)&&Text(x.ChangeMarker,256)&&Text(x.ResolvedPath,32768)&&x.Size is not <0&&Status(x.Status);
        static bool Principal(PrincipalEvidence? x)=>x!=null&&Text(x.Sid,184)&&Text(x.Account,512)&&Text(x.IntegritySid,184)&&Text(x.LogonId,64)&&Text(x.TokenId,64)&&Text(x.AuthenticationId,64)&&Text(x.TokenType,32)&&Text(x.CredentialNamespace,64)&&(x.SupplementaryGroups==null||x.SupplementaryGroups.Length<=64)&&Status(x.Status);
        if(Version!=1||!Guid.TryParseExact(EventId,"N",out _)||!Guid.TryParseExact(SensorId,"N",out _)||!Guid.TryParseExact(CollectorEpoch,"N",out _)||RelatedEventId!=null&&(!Guid.TryParseExact(RelatedEventId,"N",out _)||RelatedEventId==EventId)||CollectorSequence<=0||ProcessSequence is <=0||MonotonicFrequency<=0||MonotonicTicks<0||ObservedUtc==default||CapturedUtc==default||!Text(SourceSequence,160)||!Status(Collection))return false;
        var p=Process;var a=ActorExecutable;var t=Observation;var d=Detection;var e=Preservation;var r=Response;
        if(p==null||a?.Signature==null||t==null||d==null||e==null||r==null||p.Pid is <0||p.ParentPid is <0||!Hash(p.InstanceId)||!Hash(p.ParentInstanceId)||!Text(p.StartKey,128)||!Text(p.ParentStartKey,128)||!Text(p.ExecutablePath,32768)||!Text(p.ParentExecutablePath,32768)||!Text(p.CommandLine,2048)||!Status(p.ParentStatus)||!Status(p.SessionStatus)||!Status(p.CommandLineStatus)||!Status(p.Status)||!Status(p.ImpersonationStatus)||!Principal(p.Owner)||!Principal(p.EventSubject)||!Principal(p.ThreadToken))return false;
        if(p.Creation!=null&&!p.Creation.IsValid(p,a.Acquisition))return false;
        if(p.ThreadId is 0||p.EffectiveThreadContext!=null&&!Principal(p.EffectiveThreadContext)||p.ThreadOwner!=null&&!Principal(p.ThreadOwner)||p.ThreadOwnerCreatedFileTime is <=0)return false;
        if(!Hash(a.Sha256)||!Status(a.HashStatus)||!Status(a.MetadataStatus)||!Status(a.BindingStatus)||!File(a.File)||!Status(a.Signature.Status)||!Text(a.Signature.Signer,512)||!Text(a.Signature.Issuer,512)||!Text(a.Signature.Publisher,512)||!Text(a.ObservedPath,32768)||!Text(a.Location,128))return false;
        if((a.BindingSourceEventId==null)!=(!a.BindingCapturedUtc.HasValue)||a.BindingSourceEventId!=null&&(!Guid.TryParseExact(a.BindingSourceEventId,"N",out _)||a.BindingCapturedUtc==default(DateTimeOffset)))return false;
        if(a.Acquisition!=null&&(!a.Acquisition.IsValid(p,EventId,RelatedEventId,a.Sha256)||!a.Acquisition.IsValidSourceFile(a.File)))return false;
        if(a.Acquisition is {Status.State:"captured"} acquisition&&(a.File.Size!=acquisition.SnapshotFile?.Size||a.BindingSourceEventId!=acquisition.SourceEventId))return false;
        if(a.LinuxAcquisition is {} linux&&(a.Acquisition!=null||p.Creation!=null||!linux.IsValid(p,EventId,RelatedEventId,a.Sha256,a.File)||linux.Status.State=="captured"&&a.BindingSourceEventId!=linux.SourceEventId))return false;
        if(a.LinuxNativeWork is {} nativeWork&&(a.Acquisition!=null||p.Creation!=null||!nativeWork.IsValid(EventId,RelatedEventId)))return false;
        if(!File(t.File)||!Status(t.IoStatus)||t.Actions is not {Length:<=16}||t.Actions.Any(x=>x is not {Length:>0 and <=64})||t.BytesTransferred is <0||t.Offset is <0||t.Length is <0||t.PreSize is <0||t.PostSize is <0||!Text(t.Path,4096)||!Text(t.RenameSource,4096)||!Text(t.RenameDestination,4096)||!Text(t.AccessMask,64)||!Text(t.OsStatus,64))return false;
        if(d.RuleIds is not {Length:<=64}||d.ReasonCodes is not {Length:>0 and <=32}||d.RuleIds.Any(x=>x is not {Length:>0 and <=128})||d.ReasonCodes.Any(x=>x is not {Length:>0 and <=128})||d.Disposition is not ("alert" or "log-only")||d.Severity is not ("normal" or "informational" or "alert" or "warning" or "high" or "critical"))return false;
        if(Transfer is {} upload&&(!EvidenceTransferLimits.Id(upload.EvidenceId)||!EvidenceTransferLimits.Id(upload.CompletionEventId)||!EvidenceTransferLimits.Id(upload.ReceiptId)||!EvidenceTransferLimits.Hash(upload.Sha256)||!EvidenceTransferLimits.Hash(upload.ManifestSha256)||upload.Size<0||upload.ReceivedUtc==default))return false;
        return Status(e.Status)&&Hash(e.Sha256)&&Hash(e.ManifestSha256)&&e.Size is not <0&&Text(e.ArtifactRelativePath,256)&&Text(e.ManifestRelativePath,256)&&Text(e.OriginalPath,32768)&&Text(r.Action,128)&&Text(r.Status,128)&&JsonSerializer.SerializeToUtf8Bytes(this).Length<=(p.Creation==null&&a.LinuxAcquisition==null&&a.LinuxNativeWork==null?16384:32768);
    }
}
public sealed record ForensicPolicy(bool PreserveActorOnAlert=true,string PreservationThreshold="alert",int MaximumActorMiB=256,int EvidenceStoreMiB=1024,int CacheEntries=256)
{
    public bool IsValid()=>PreservationThreshold is "alert" or "high" or "critical"&&MaximumActorMiB is >=1 and <=1024&&EvidenceStoreMiB is >=64 and <=102400&&CacheEntries is >=1 and <=4096;
}
