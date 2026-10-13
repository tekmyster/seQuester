using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RansomFree.Contracts;

// Exact native pathname bytes remain authoritative. The bounded display is a
// JSON string literal, so controls and literal backslashes cannot look alike.
public sealed record LinuxKernelPathEvidence
{
    public int NativeResult {get;init;}
    public string State {get;init;}="unavailable";
    public string? BytesBase64 {get;init;}
    public string? RenderedAtNs {get;init;}
    public string Semantics {get;init;}="LINUX_D_PATH_CURRENT_TASK_FS_ROOT";
    public string NamespaceStatus {get;init;}="NOT_CAPTURED";
    public string OriginalSyscallPathStatus {get;init;}="UNAVAILABLE_FROM_RESOLVED_FILE_PATH";
    public string DeletedTextStatus {get;init;}="POSSIBLY_PRESENT_AND_AMBIGUOUS";
    private static readonly UTF8Encoding StrictUtf8=new(false,true);
    public bool IsValid()
    {
        if(Semantics!="LINUX_D_PATH_CURRENT_TASK_FS_ROOT"||NamespaceStatus!="NOT_CAPTURED"||OriginalSyscallPathStatus!="UNAVAILABLE_FROM_RESOLVED_FILE_PATH"||DeletedTextStatus!="POSSIBLY_PRESENT_AND_AMBIGUOUS"||RenderedAtNs!=null&&!LinuxKernelEvidence.Decimal(RenderedAtNs))return false;
        if(State=="unavailable")return BytesBase64==null&&NativeResult<=0;
        if(State is not ("captured" or "invalid_utf8")||BytesBase64 is not {Length:>0 and <=5460}||NativeResult is <2 or >4096)return false;
        try
        {
            var bytes=Convert.FromBase64String(BytesBase64);
            if(bytes.Length!=NativeResult-1||Convert.ToBase64String(bytes)!=BytesBase64||bytes.Contains((byte)0))return false;
            try{StrictUtf8.GetString(bytes);return State=="captured";}
            catch(DecoderFallbackException){return State=="invalid_utf8";}
        }
        catch(FormatException){return false;}
    }
    [JsonIgnore] public string? Text=>State=="captured"&&IsValid()?StrictUtf8.GetString(Convert.FromBase64String(BytesBase64!)):null;
    [JsonIgnore] public string Display
    {
        get
        {
            var text=Text;if(text==null)return State=="invalid_utf8"?"[Invalid UTF-8; raw path bytes retained]":"[Path unavailable]";
            const string suffix=" [display truncated; raw bytes retained]";
            var encoded=JsonSerializer.Serialize(text);return encoded.Length<=512?encoded:encoded[..(512-suffix.Length)]+suffix;
        }
    }
}

public sealed record LinuxKernelTargetIdentity
{
    public uint Device {get;init;}
    public string Inode {get;init;}="";
    public uint Ordinal {get;init;}
    public string Semantics {get;init;}="WATCHED_INODE_MEMBERSHIP_NOT_CONFIGURED_PATH";
    public bool IsValid()=>Device!=0&&LinuxKernelEvidence.Decimal(Inode)&&Inode!="0"&&Ordinal<32&&Semantics=="WATCHED_INODE_MEMBERSHIP_NOT_CONFIGURED_PATH";
    [JsonIgnore] public string StableId=>"linux-kernel-device:"+Device.ToString(CultureInfo.InvariantCulture)+":inode:"+Inode;
}

// Native observations are pre-open evidence. They do not observe the
// final syscall result, and an actor lease number alone is not a captured hash.
// 64-bit native values use canonical decimal strings to survive JS/SIEM parsing.
public sealed record LinuxKernelEvidence
{
    public static int RequiredVersion(IEnumerable<AgentEvent> events)=>events.Select(e=>e.Attribution?.LinuxKernel?.Version??0).DefaultIfEmpty(0).Max();
    // Keep the original wire capability at 1 for deployed clients that require
    // an exact match. Schema-6 target identity requires this additive capability
    // both before upload and in the durable receipt; old servers cannot imply it.
    public static bool Supports(int required,int baseVersion,int targetIdentityVersion,int permissionObservationVersion=0,int ioObservationVersion=0)=>required==0||
        baseVersion==1&&(required==1||required==2&&targetIdentityVersion==1||required==3&&targetIdentityVersion==1&&permissionObservationVersion==1||required==4&&targetIdentityVersion==1&&ioObservationVersion==1);
    public int Version {get;init;}=1;
    public int NativeSchemaVersion {get;init;}=5;
    public string CollectorInstance {get;init;}="";
    public long CollectorSequence {get;init;}
    public string NativeObservationSha256 {get;init;}="";
    public string WallTimeSource {get;init;}="collector-receipt; not-native-operation-wall-clock";
    public string ProviderEpoch {get;init;}="";
    public string Cookie {get;init;}="";
    public int? ProcessId {get;init;}
    public uint? ThreadId {get;init;}
    public string TaskStartNs {get;init;}="";
    public string ProcessStartNs {get;init;}="";
    public string SelfExecId {get;init;}="";
    public string AssociationBefore {get;init;}="";
    public string AssociationAfter {get;init;}="";
    public int AssociationErrorBefore {get;init;}
    public int AssociationErrorAfter {get;init;}
    public int AssociationError {get;init;}
    public string ActorInode {get;init;}="";
    public uint ActorDevice {get;init;}
    public string ActorSize {get;init;}="";
    // Omitted only from legacy version-1 serialization to retain exact saved
    // canonical bytes. Legacy schema 5 never supplied target file identity.
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public LinuxKernelTargetIdentity? TargetIdentity {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public LinuxPermissionObservation? PermissionObservation {get;init;}
    [JsonIgnore(Condition=JsonIgnoreCondition.WhenWritingNull)]
    public LinuxIoObservation? IoObservation {get;init;}
    [JsonIgnore] public string CanonicalCookie=>Cookie=="0"?"0":IoObservation is {} io?Cookie+":"+io.OperationNonce+":"+io.Stage:PermissionObservation is {} p?Cookie+":"+p.OperationNonce+":"+p.Stage:Cookie;
    [JsonIgnore] public string OperationDescription=>IoObservation is {} io?io.Stage switch
        {1=>"File write entered",2 when io.Outcome=="pending"=>"File write completion pending",2 when io.Outcome=="failure"=>"File write failed",2 when io.AppendRequested==true=>"File append completed",2=>"File write completed",_=>"File write capture diagnostic"}:PermissionObservation is {} p?p.Stage switch
        {1=>"File permission check entered",2=>"File permission check returned",_=>"File permission capture diagnostic"}:"File open observed before final result";
    public string CaptureStartNs {get;init;}="";
    public string CaptureEndNs {get;init;}="";
    public long Reservation {get;init;}
    public long Lease {get;init;}
    public long FinalizeError {get;init;}
    public long DiagnosticResult {get;init;}
    public uint DiagnosticMode {get;init;}
    public uint CredentialFields {get;init;}
    public int CredentialError {get;init;}
    public uint? Uid {get;init;}
    public uint? EffectiveUid {get;init;}
    public uint? FileSystemUid {get;init;}
    public uint? Gid {get;init;}
    public uint? EffectiveGid {get;init;}
    public uint? FileSystemGid {get;init;}
    public string CredentialNamespace {get;init;}="INITIAL_USER_NAMESPACE";
    public string CredentialEncoding {get;init;}="KERNEL_GLOBAL_KUID_KGID";
    public string Hook {get;init;}="bpf-lsm/file_open";
    public int PriorResult {get;init;}
    public string PriorResultMeaning {get;init;}="PRECEDING_BPF_LSM_RESULT";
    public string OperationOutcome {get;init;}="not-observed";
    public string CaptureIssue {get;init;}="";
    public string RecordForm {get;init;}="";
    public LinuxKernelPathEvidence ActorPath {get;init;}=new();
    public LinuxKernelPathEvidence TargetPath {get;init;}=new();
    public bool WhitelistEligible {get;init;}
    internal static bool Decimal(string? s)=>s is {Length:>0 and <=20}&&ulong.TryParse(s,NumberStyles.None,CultureInfo.InvariantCulture,out var value)&&value.ToString(CultureInfo.InvariantCulture)==s;
    public bool IsValid()
    {
        if(Version==4)return IsValidIoObservation();
        if(IoObservation!=null)return false;
        if(Version==3)return IsValidPermissionObservation();
        if(PermissionObservation!=null)return false;
        if(!(Version==1&&NativeSchemaVersion==5&&TargetIdentity==null||Version==2&&NativeSchemaVersion==6&&DiagnosticMode==0&&TargetIdentity?.IsValid()==true)||!Guid.TryParseExact(CollectorInstance,"N",out _)||CollectorSequence<=0||NativeObservationSha256 is not {Length:64}||!NativeObservationSha256.All(Uri.IsHexDigit)||WhitelistEligible||
            WallTimeSource!="collector-receipt; not-native-operation-wall-clock"||Hook!="bpf-lsm/file_open"||OperationOutcome!="not-observed"||PriorResultMeaning!="PRECEDING_BPF_LSM_RESULT"||
            CredentialNamespace!="INITIAL_USER_NAMESPACE"||CredentialEncoding!="KERNEL_GLOBAL_KUID_KGID"||ProcessId is not (null or >0)||ThreadId is not (null or >0)||CredentialFields>63||
            RecordForm is not ("full" or "compact")||CaptureIssue is not ("NONE" or "SCRATCH_UNAVAILABLE" or "SCRATCH_REENTRANT" or "SCRATCH_LOST_AFTER_CAPTURE" or "SCRATCH_LOST_AFTER_FINALIZE" or "SEQUENCE_UNAVAILABLE")||
            !new[]{ProviderEpoch,Cookie,TaskStartNs,ProcessStartNs,SelfExecId,AssociationBefore,AssociationAfter,ActorInode,ActorSize,CaptureStartNs,CaptureEndNs}.All(Decimal)||ActorPath?.IsValid()!=true||TargetPath?.IsValid()!=true)return false;
        var fields=new uint?[]{Uid,EffectiveUid,FileSystemUid,Gid,EffectiveGid,FileSystemGid};
        for(var i=0;i<fields.Length;i++)if(((CredentialFields&(1u<<i))!=0)!=fields[i].HasValue)return false;
        return !(RecordForm=="compact"&&(CaptureIssue=="NONE"||ActorPath.State!="unavailable"||TargetPath.State!="unavailable"));
    }
    private bool IsValidIoObservation()
    {
        var io=IoObservation;
        if(NativeSchemaVersion!=8||io?.IsValid()!=true||PermissionObservation!=null||TargetIdentity?.IsValid()!=true||DiagnosticMode!=0||WhitelistEligible||
            !Guid.TryParseExact(CollectorInstance,"N",out _)||CollectorSequence<=0||NativeObservationSha256 is not {Length:64}||!NativeObservationSha256.All(Uri.IsHexDigit)||
            WallTimeSource!="collector-receipt; not-native-operation-wall-clock"||Hook is not ("fentry-fexit/vfs_write" or "fentry-fexit/do_iter_readv_writev")||
            OperationOutcome!=io.Outcome||PriorResultMeaning!="NO_PRECEDING_LSM_RESULT"||PriorResult!=0||
            CredentialNamespace!="INITIAL_USER_NAMESPACE"||CredentialEncoding!="KERNEL_GLOBAL_KUID_KGID"||ProcessId is not >0||ThreadId is not >0||
            CredentialFields>63||RecordForm!="full"||CaptureIssue!="NONE"||ActorPath?.IsValid()!=true||TargetPath?.IsValid()!=true||
            ActorPath.State!="unavailable"||TargetPath.State!="unavailable"||
            !new[]{ProviderEpoch,Cookie,TaskStartNs,ProcessStartNs,SelfExecId,AssociationBefore,AssociationAfter,ActorInode,ActorSize,CaptureStartNs,CaptureEndNs}.All(Decimal)||
            ProviderEpoch=="0"||CaptureStartNs!=io.EntryNs||CaptureEndNs!=io.ObservedNs||AssociationBefore!=AssociationAfter||AssociationErrorBefore!=AssociationError||AssociationErrorAfter!=AssociationError)return false;
        if(io.Diagnostic?(Cookie!="0"||Lease!=0||AssociationBefore!="0"):(Cookie=="0"||io.OperationNonce=="0"))return false;
        if(Lease<0||Lease>0&&(io.Stage!=1||io.Schema!=3||io.ObservedLease!=Lease.ToString(CultureInfo.InvariantCulture)||Reservation!=Lease||FinalizeError!=0||
            io.IdentityFields!=7||io.IdentityError!=0||io.ActorMetadataError!=0||AssociationError!=0||ActorDevice==0||ActorInode=="0"||
            ProcessStartNs=="0"||TaskStartNs=="0"||SelfExecId=="0"||AssociationBefore=="0"||(ulong.Parse(AssociationBefore,CultureInfo.InvariantCulture)&1)!=0)||DiagnosticResult!=0)return false;
        var fields=new uint?[]{Uid,EffectiveUid,FileSystemUid,Gid,EffectiveGid,FileSystemGid};
        for(var i=0;i<fields.Length;i++)if(((CredentialFields&(1u<<i))!=0)!=fields[i].HasValue||fields[i]==uint.MaxValue)return false;
        return true;
    }
    private bool IsValidPermissionObservation()
    {
        var p=PermissionObservation;
        if(NativeSchemaVersion!=7||p?.IsValid()!=true||TargetIdentity?.IsValid()!=true||DiagnosticMode!=0||WhitelistEligible||
            !Guid.TryParseExact(CollectorInstance,"N",out _)||CollectorSequence<=0||NativeObservationSha256 is not {Length:64}||!NativeObservationSha256.All(Uri.IsHexDigit)||
            WallTimeSource!="collector-receipt; not-native-operation-wall-clock"||Hook is not ("fentry-fexit/inode_permission" or "fentry-fexit/security_file_permission")||
            OperationOutcome!="not-observed"||PriorResultMeaning!="NO_PRECEDING_LSM_RESULT"||PriorResult!=0||
            CredentialNamespace!="INITIAL_USER_NAMESPACE"||CredentialEncoding!="KERNEL_GLOBAL_KUID_KGID"||ProcessId is not >0||ThreadId is not >0||
            CredentialFields>63||RecordForm!="full"||CaptureIssue!="NONE"||ActorPath?.IsValid()!=true||TargetPath?.IsValid()!=true||
            ActorPath.State!="unavailable"||TargetPath.State!="unavailable"||
            !new[]{ProviderEpoch,Cookie,TaskStartNs,ProcessStartNs,SelfExecId,AssociationBefore,AssociationAfter,ActorInode,ActorSize,CaptureStartNs,CaptureEndNs}.All(Decimal)||
            ProviderEpoch=="0"||CaptureStartNs!=p.EntryNs||CaptureEndNs!=p.ObservedNs||AssociationBefore!=AssociationAfter||AssociationErrorBefore!=AssociationError||AssociationErrorAfter!=AssociationError)return false;
        if(p.Diagnostic?(Cookie!="0"||Lease!=0||AssociationBefore!="0"):(Cookie=="0"||p.OperationNonce=="0"))return false;
        if(Lease<0||Lease>0&&(p.Stage!=1||p.Schema!=1||p.ObservedLease!=Lease.ToString(CultureInfo.InvariantCulture)||Reservation!=Lease||FinalizeError!=0||
            p.IdentityFields!=7||p.IdentityError!=0||p.ActorMetadataError!=0||AssociationError!=0||ActorDevice==0||ActorInode=="0"||
            ProcessStartNs=="0"||TaskStartNs=="0"||SelfExecId=="0"||AssociationBefore=="0"||(ulong.Parse(AssociationBefore,CultureInfo.InvariantCulture)&1)!=0)||DiagnosticResult!=0)return false;
        var fields=new uint?[]{Uid,EffectiveUid,FileSystemUid,Gid,EffectiveGid,FileSystemGid};
        for(var i=0;i<fields.Length;i++)if(((CredentialFields&(1u<<i))!=0)!=fields[i].HasValue||fields[i]==uint.MaxValue)return false;
        return true;
    }
    [JsonIgnore] public string? SubjectDisplay=>FileSystemUid is {} uid?"uid:"+uid.ToString(CultureInfo.InvariantCulture)+" (initial user namespace)":null;
    [JsonIgnore] public string ProcessStartKey=>ProviderEpoch+":"+ProcessStartNs+":"+SelfExecId;
    public static bool SameIoOperation(LinuxKernelEvidence entry,LinuxKernelEvidence result)
    {
        if(!entry.IsValid()||!result.IsValid()||entry.IoObservation is not {Schema:3,Stage:1} first||result.IoObservation is not {Schema:3,Stage:2} second)return false;
        var normalized=result with{CollectorSequence=entry.CollectorSequence,NativeObservationSha256=entry.NativeObservationSha256,CaptureEndNs=entry.CaptureEndNs,Lease=entry.Lease,OperationOutcome=entry.OperationOutcome,
            IoObservation=second with{Stage=1,ObservedNs=first.ObservedNs,ReturnValue=null,OffsetAfter=null,SizeAfter=null,AvailabilityFields=second.AvailabilityFields&~20u,CollectionError=first.CollectionError}};
        return normalized==entry;
    }
    public static bool SamePermissionOperation(LinuxKernelEvidence entry,LinuxKernelEvidence result)
    {
        if(!entry.IsValid()||!result.IsValid()||entry.Version!=3||result.Version!=3||entry.PermissionObservation is not {Schema:1,Stage:1} first||result.PermissionObservation is not {Schema:1,Stage:2} second)return false;
        var normalized=result with{CollectorSequence=entry.CollectorSequence,NativeObservationSha256=entry.NativeObservationSha256,CaptureEndNs=entry.CaptureEndNs,Lease=entry.Lease,
            PermissionObservation=second with{Stage=1,ObservedNs=first.ObservedNs,PermissionResult=null}};
        return normalized==entry;
    }
    private bool MatchesForensics(ForensicEvidence? f,string? process)
    {
        if(f==null)return true;
        var p=f.Process;var known=ProcessId!=null&&ProcessStartNs!="0"&&SelfExecId!="0"&&ProviderEpoch!="0";
        var instance=known?Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(f.SensorId+":"+ProcessId+":"+ProcessStartKey))):null;
        var actor=f.ActorExecutable;
        if(f.LinuxIoPair is {} ioPair&&!ioPair.Matches(this,f.EventId,f.RelatedEventId))return false;
        if(f.LinuxPermissionPair is {} permissionPair&&!permissionPair.Matches(this,f.EventId,f.RelatedEventId))return false;
        if(actor==null||actor.Acquisition!=null)return false;
        if(actor.LinuxNativeWork is {} work&&(!work.IsValid(f.EventId,f.RelatedEventId)||!work.Matches(this)))return false;
        if(actor.LinuxAcquisition is {} acquired)
        {
            if(!acquired.Matches(this))return false;
        }
        else if(actor.Sha256!=null||actor.BindingStatus?.State=="captured")return false;
        bool Principal(PrincipalEvidence? x)=>x!=null&&x.Uid==Uid&&x.EffectiveUid==EffectiveUid&&x.FileSystemUid==FileSystemUid&&x.Gid==Gid&&x.EffectiveGid==EffectiveGid&&x.FileSystemGid==FileSystemGid&&x.CredentialNamespace==CredentialNamespace;
        return p!=null&&p.Pid==ProcessId&&p.ThreadId==ThreadId&&p.StartKey==(known?ProcessStartKey:null)&&p.InstanceId==instance&&p.StartedUtc==null&&p.ExecutablePath==process&&p.Creation==null&&
            Principal(p.EventSubject)&&Principal(p.EffectiveThreadContext)&&f.SourceSequence==CollectorInstance+":"+CollectorSequence.ToString(CultureInfo.InvariantCulture)&&
            f.Observation is {Storage:"unknown"} target&&target.Outcome==(IoObservation?.Outcome switch{"success"=>"success","failure"=>"failed",_=>"unknown"})&&target.Path==TargetPath.Display&&target.File.StableId==TargetIdentity?.StableId;
    }
    public static bool Matches(AgentEvent e)=>e.Attribution?.LinuxKernel is not {} k?e.Source!="Linux kernel"&&e.Forensics?.LinuxIoPair==null&&e.Forensics?.LinuxPermissionPair==null&&e.Forensics?.ActorExecutable?.LinuxAcquisition==null&&e.Forensics?.ActorExecutable?.LinuxNativeWork==null:k.IsValid()&&e.Attribution.WindowsKernel==null&&e.Source is "Linux kernel" or "Forensic enrichment" or "Evidence transfer"&&
        e.Attribution.Provider=="Linux kernel"&&e.ProcessId==k.ProcessId&&e.User==k.SubjectDisplay&&e.Process==(k.ActorPath.State=="captured"?k.ActorPath.Display:null)&&e.Path==k.TargetPath.Display&&
        e.Attribution.UserId==k.Uid&&e.Attribution.EffectiveUserId==k.EffectiveUid&&e.Attribution.FileSystemUserId==k.FileSystemUid&&e.Attribution.GroupId==k.Gid&&e.Attribution.EffectiveGroupId==k.EffectiveGid&&
        e.Attribution.ProcessStartTicks==k.ProcessStartKey&&e.Attribution.Outcome=="Unknown"&&e.Attribution.ExecutableSha256==null&&e.Attribution.TargetStableId==k.TargetIdentity?.StableId&&
        e.Attribution.EventTimeCredentials==(k.CredentialFields!=0)&&!e.Attribution.CompleteRecordSet&&
        (e.Forensics?.ActorExecutable.LinuxNativeWork is not {} work||e.Source!="Forensic enrichment"||work.CompletionEventId==e.EventId)&&
        (e.Source!="Linux kernel"||e.Operation==k.OperationDescription)&&k.MatchesForensics(e.Forensics,e.Process);
}
