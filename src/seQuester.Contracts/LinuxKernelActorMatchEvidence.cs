using System.Globalization;
using System.Security.Cryptography;

namespace RansomFree.Contracts;

// These are reproducible matching facts, NOT policy or live-source authority.
// No TrustActor.Verified flag or whitelist eligibility is granted here. The
// owned source, policy version and immutable decision still need separate gates.
public sealed record LinuxKernelActorMatchEvidence(
    string SourceEventId,string NativeObservationSha256,string SourceSessionId,string NativePinId,
    long SourceGeneration,string ForensicPolicySha256,DateTimeOffset NativeReturnedUtc,string CollectorInstance,long CollectorSequence,
    string ProviderEpoch,string Cookie,long Lease,int ProcessId,uint ThreadId,string ProcessStartNs,
    string TaskStartNs,string SelfExecId,string AssociationGeneration,uint FileSystemUid,uint ActorDevice,string ActorInode,
    string Executable,string ExecutablePathBytesBase64,int ExecutablePathByteLength,string ExecutablePathSha256,string SnapshotId,string Sha256,
    string SnapshotStableId,string SnapshotChangeMarker,long Size,DateTimeOffset SnapshotPersistedUtc)
{
    public int Version {get;init;}=1;
    public string PathScope {get;init;}="TASK_FS_ROOT_UTF8_V1";
    public string CredentialNamespace {get;init;}="INITIAL_USER_NAMESPACE";
    public string CredentialIdEncoding {get;init;}="KERNEL_GLOBAL_KUID_KGID";
    public string OperationObservation {get;init;}="OPEN_REQUEST";
    public string OperationOutcome {get;init;}="NOT_OBSERVED";
    public string PathEncoding {get;init;}="STRICT_UTF8";

    // Uses exact strict-UTF8 d_path bytes relative to the accessing task's root.
    // Display text, host-root interpretation, case folding and Unicode
    // normalization are deliberately absent. The existing rule grammar is a
    // conservative subset of Linux pathnames; unsupported paths retain evidence.
    public static string? MatchingPath(LinuxKernelPathEvidence? path)
    {
        var text=path?.Text;
        if(text is not {Length:>1 and <=1024}||!text.StartsWith('/')||text.EndsWith(" (deleted)",StringComparison.Ordinal)||
            text.Any(char.IsControl)||text.Any(c=>"\\*?\"<>|".Contains(c))||text.Split('/').Any(p=>p is "." or ".."))return null;
        return text;
    }

    public static (LinuxKernelActorMatchEvidence? Evidence,string Reason) Inspect(AgentEvent? value)
    {
        if(value?.Source!="Linux kernel"||value.Attribution?.LinuxKernel is not {} k||value.Forensics is not {} f||
            f.EventId!=value.EventId||f.RelatedEventId!=null||!f.IsValid()||!LinuxKernelEvidence.Matches(value))return (null,"LINUX_MATCH_EVENT_INVALID");
        if(k.Version!=2||k.NativeSchemaVersion!=6||k.RecordForm!="full"||k.CaptureIssue!="NONE"||k.DiagnosticMode!=0||k.DiagnosticResult!=0||
            k.ProviderEpoch=="0"||k.Cookie=="0"||k.ProcessId==null||k.ThreadId==null||k.ProcessStartNs=="0"||k.TaskStartNs=="0"||k.SelfExecId=="0"||
            k.ActorDevice==0||k.ActorInode=="0"||k.ActorSize=="0"||
            k.AssociationBefore=="0"||k.AssociationBefore!=k.AssociationAfter||k.AssociationErrorBefore!=0||k.AssociationErrorAfter!=0||k.AssociationError!=0||
            k.PriorResult!=0||k.CaptureStartNs=="0"||ulong.Parse(k.CaptureEndNs,CultureInfo.InvariantCulture)<ulong.Parse(k.CaptureStartNs,CultureInfo.InvariantCulture))
            return (null,"LINUX_MATCH_OPERATION_UNQUALIFIED");
        if(k.CredentialFields!=63||k.CredentialError!=0||k.FileSystemUid is null or uint.MaxValue)
            return (null,"LINUX_MATCH_CREDENTIALS_UNAVAILABLE");
        var path=MatchingPath(k.ActorPath);
        if(path==null)return (null,"LINUX_MATCH_PATH_UNAVAILABLE");
        var actor=f.ActorExecutable;
        if(actor.BindingStatus?.State!="captured"||actor.BindingSourceEventId!=value.EventId||actor.ObservedPath!=value.Process||
            actor.LinuxAcquisition is not {Status.State:"captured",RecoveryStatus:null,NativeStatus.Ready:true,SnapshotSha256:not null,SnapshotId:not null,SnapshotFile:not null,PersistedUtc:not null,SizeMatchesEarlierObservation:true} a||
            a.SourceEventId!=value.EventId||actor.BindingCapturedUtc!=a.PersistedUtc||!a.Matches(k)||!a.IsValid(f.Process,value.EventId,null,actor.Sha256,actor.File)||
            a.NativeStatus.AssociationState!=1||a.NativeStatus.AssociationError!=0||a.NativeStatus.Size!=k.ActorSize)
            return (null,"LINUX_MATCH_ACTOR_COPY_UNAVAILABLE");
        var work=actor.LinuxNativeWork;
        if(work is not {Version:2,State:"NATIVE_RETURNED_RECEIPT_COMMITTED",ReturnOutcome:"committed",StartingState:"Active",StartOrdering:"SAME_GENERATION_START",Method:not null}||
            !work.IsValid(value.EventId,null)||!work.Matches(k)||work.IssuedGeneration!=work.AuthorizationGeneration||work.IssuedGeneration!=work.StartingGeneration||
            work.Method is not {ControllerMethodAttempted:true,DropMethodAttempted:true,DropMethodReturned:true,DropReceiptCommitObserved:true,ErrorKind:null,LatestStatus.Ready:true}||
            !work.Method.LatestStatus.Matches(k)||work.Method.LatestStatus.Size!=a.NativeStatus.Size)
            return (null,"LINUX_MATCH_NATIVE_WORK_UNAVAILABLE");
        return (new(value.EventId,k.NativeObservationSha256,work.SourceSessionId,work.PinId,work.IssuedGeneration,work.PolicySha256,work.ActualReturnUtc!.Value,
            k.CollectorInstance,k.CollectorSequence,k.ProviderEpoch,k.Cookie,k.Lease,
            k.ProcessId.Value,k.ThreadId.Value,k.ProcessStartNs,k.TaskStartNs,k.SelfExecId,k.AssociationAfter,k.FileSystemUid.Value,k.ActorDevice,k.ActorInode,
            path,k.ActorPath.BytesBase64!,k.ActorPath.NativeResult-1,Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(k.ActorPath.BytesBase64!))),a.SnapshotId,a.SnapshotSha256,
            a.SnapshotFile.StableId!,a.SnapshotFile.ChangeMarker!,a.SnapshotFile.Size!.Value,a.PersistedUtc.Value),"LINUX_MATCH_FACTS_CAPTURED");
    }
}
