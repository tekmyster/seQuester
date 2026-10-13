using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// A retained image descriptor survives path renames and process exit. It is never a response/termination handle.
public sealed class ActorLease:IDisposable
{
    public FileStream? Image {get;internal set;}
    public FileIdentityEvidence File {get;internal set;}=new();
    // A staged copy has its own identity. Never report its file ID as the source actor's ID.
    internal FileIdentityEvidence? SnapshotFile {get;set;}
    internal string? SnapshotPath {get;set;}
    internal FileIdentityEvidence DescriptorFile=>SnapshotFile??File;
    internal string? InspectionPath=>SnapshotPath??Process.ExecutablePath;
    internal ActorAcquisitionEvidence? Acquisition {get;set;}
    internal LinuxActorAcquisitionEvidence? LinuxAcquisition {get;set;}
    internal LinuxNativeWorkEvidence? LinuxNativeWork {get;set;}
    // Trust-only entry reference on a separately restored entry actor. It never
    // changes the return event's own acquisition or process metadata.
    internal AgentEvent? LinuxTrustEntry {get;set;}
    public ProcessInstanceEvidence Process {get;internal set;}=new();
    public EvidenceStatus Binding {get;internal set;}=EvidenceStatus.Unavailable("not-captured");
    public string? BindingSourceEventId {get;internal set;}
    public DateTimeOffset? BindingCapturedUtc {get;internal set;}
    public DateTimeOffset CapturedUtc {get;}=DateTimeOffset.UtcNow;
    public long CapturedMonotonicTicks {get;}=Stopwatch.GetTimestamp();
    internal Action? DeferredMetadata {get;set;}
    internal IDisposable? MetadataHandle {get;set;}
    public (string Sha256,DateTimeOffset CreatedUtc,DateTimeOffset CheckedUtc)? AcquiredTrustIdentity(AgentEvent value)
    {
        if(value.Source!="Windows minifilter"||value.Attribution?.WindowsKernel is not {} kernel||Image==null||SnapshotFile==null||
            Binding.State!="captured"||Acquisition is not {Status.State:"captured",RecoveryStatus:null,SnapshotSha256:not null,PersistedUtc:not null} a||
            a.SourceEventId!=value.EventId||a.EventInstance!=kernel.Instance||a.EventSequence!=kernel.Sequence||a.ProcessId!=kernel.ProcessId||a.ProcessCreatedFileTime!=kernel.ProcessCreatedFileTime||
            !a.IsValid(Process,value.EventId,null,a.SnapshotSha256)||Process.StartedUtc==null||
            !string.Equals(value.Process,Process.ExecutablePath,StringComparison.OrdinalIgnoreCase))return null;
        try{return NativeFileIdentity.Same(SnapshotFile,NativeFileIdentity.Read(Image))?(a.SnapshotSha256,Process.StartedUtc.Value,a.PersistedUtc.Value):null;}
        catch(Exception ex)when(OptionalFailure(ex)){return null;}
    }
    // Only describes a currently held, verified private snapshot. The caller
    // still needs live-source and policy authority; this never enables a rule.
    internal (LinuxKernelActorMatchEvidence? Evidence,string Reason) AcquiredLinuxMatchEvidence(AgentEvent value)
    {
        var result=LinuxKernelActorMatchEvidence.Inspect(value);
        if(result.Evidence==null)return result;
        if(Image==null||SnapshotFile==null||Binding.State!="captured"||LinuxAcquisition!=value.Forensics!.ActorExecutable.LinuxAcquisition||
            LinuxNativeWork!=value.Forensics.ActorExecutable.LinuxNativeWork||Process!=value.Forensics.Process||File!=value.Forensics.ActorExecutable.File||
            !NativeFileIdentity.Same(SnapshotFile,LinuxAcquisition!.SnapshotFile!))return (null,"LINUX_MATCH_PRIVATE_DESCRIPTOR_UNAVAILABLE");
        try{return NativeFileIdentity.Same(SnapshotFile,NativeFileIdentity.Read(Image))?result:(null,"LINUX_MATCH_PRIVATE_DESCRIPTOR_CHANGED");}
        catch(Exception ex)when(OptionalFailure(ex)){return (null,"LINUX_MATCH_PRIVATE_DESCRIPTOR_UNAVAILABLE");}
    }
    internal string? AcquiredLinuxNativeHash(AgentEvent value)
    {
        var hash=LinuxNativeHashBinding.ActorHash(value);
        if(hash==null||Image==null||SnapshotFile==null||Binding.State!="captured"||LinuxAcquisition!=value.Forensics!.ActorExecutable.LinuxAcquisition||
            LinuxNativeWork!=value.Forensics.ActorExecutable.LinuxNativeWork||Process!=value.Forensics.Process||File!=value.Forensics.ActorExecutable.File||!NativeFileIdentity.Same(SnapshotFile,LinuxAcquisition!.SnapshotFile!))return null;
        try{return NativeFileIdentity.Same(SnapshotFile,NativeFileIdentity.Read(Image))?hash:null;}
        catch(Exception ex)when(OptionalFailure(ex)){return null;}
    }
    internal static ActorLease Unavailable(AgentEvent value,string reason){var lease=new ActorLease{Process=new(){Pid=value.ProcessId,ExecutablePath=value.Process,EventSubject=Subject(value)},Binding=EvidenceStatus.Unavailable(reason)};lease.ApplyKernel(value,"");return lease;}
    internal static bool OptionalFailure(Exception ex)=>ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or ArgumentException or FormatException or OverflowException or EntryPointNotFoundException;
    internal static EvidenceStatus FailedField(string reason,Exception ex)=>new("unavailable",ex is LinuxProcessBindingException binding?binding.Reason:reason,ex is Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name);
    public static string Correlate(string sensor,int pid,string start)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensor+":"+pid+":"+start)));
    public static ActorLease Capture(AgentEvent value,string sensor,bool deferWindowsMetadata=false)
    {
        var result=new ActorLease{Process=new(){Pid=value.ProcessId,ExecutablePath=value.Process,EventSubject=Subject(value)}};
        if(value.Attribution?.WindowsSyscall!=null||value.Source=="Windows syscall")
        {
            if(!WindowsSyscallObservation.Matches(value))throw new InvalidDataException("Syscall process identity is contradictory");
            result.Binding=EvidenceStatus.Unavailable("syscall-process-snapshot-not-supplied");result.ApplyKernel(value,sensor);return result;
        }
        if(value.Attribution?.LinuxKernel!=null||value.Source=="Linux kernel")
        {
            // A later /proc/PID/exe open cannot replace this operation's kernel
            // lease. Keep event-time identity even after PID exit/reuse.
            if(!LinuxKernelEvidence.Matches(value))throw new InvalidDataException("Linux kernel identity is contradictory");
            result.Binding=EvidenceStatus.Unavailable("linux-kernel-retained-lease-not-supplied");result.ApplyKernel(value,sensor);return result;
        }
        if(value.ProcessId is not >0||string.IsNullOrWhiteSpace(value.Process))
        {result.Binding=EvidenceStatus.Unavailable("actor-pid-or-executable-unavailable");result.ApplyKernel(value,sensor);return result;}
        try
        {
            if(OperatingSystem.IsWindows())WindowsProcessCapture.Capture(result,value,sensor,deferWindowsMetadata);
            else if(OperatingSystem.IsLinux())LinuxProcessCapture.Capture(result,value,sensor);
            else result.Binding=EvidenceStatus.Unavailable("platform-provider-unavailable");
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException or ArgumentException or PlatformNotSupportedException or EntryPointNotFoundException or FormatException or OverflowException)
        {
            // Optional reads after a successfully bound image must not discard the retained bytes.
            if(result.Binding.State=="captured")result.Process=result.Process with{Status=new("partial","optional-process-metadata-unavailable",ex is Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name)};
            else
            {
                result.Image?.Dispose();result.Image=null;result.Binding=FailedField("actor-capture-failed",ex);
                if(value.Source=="Linux Audit")
                    // A current PID sampled before an image mismatch cannot be
                    // attached to a historical audit event after failed binding.
                    result.Process=new(){Pid=value.ProcessId,ExecutablePath=value.Process,EventSubject=Subject(value),Status=FailedField("audit-process-instance-not-bound",ex)};
            }
        }
        if(result.Binding.State=="captured"){result.BindingSourceEventId=value.EventId;result.BindingCapturedUtc=result.CapturedUtc;}
        result.ApplyKernel(value,sensor);return result;
    }
    internal void CompleteMetadata(AgentEvent value,string sensor)
    {
        var enrich=DeferredMetadata;DeferredMetadata=null;
        try{enrich?.Invoke();}
        catch(Exception ex)when(OptionalFailure(ex)){Process=Process with{Status=new("partial","optional-process-metadata-unavailable",ex is Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name)};}
        finally{MetadataHandle?.Dispose();MetadataHandle=null;ApplyKernel(value,sensor);}
    }
    internal void ApplyKernel(AgentEvent value,string sensor)
    {
        if(value.Attribution?.WindowsSyscall is {} syscall)
        {
            var n=syscall.Native;var syscallStart=n.ProcessCreatedFileTime.ToString(System.Globalization.CultureInfo.InvariantCulture);
            Process=Process with{Pid=checked((int)n.ProcessId),ThreadId=n.ThreadId,StartKey=syscallStart,StartedUtc=DateTimeOffset.FromFileTime(n.ProcessCreatedFileTime),
                InstanceId=sensor.Length>0?Correlate(sensor,(int)n.ProcessId,syscallStart):null,ExecutablePath=value.Process,
                Owner=n.ProcessOwner.Principal("syscall-entry-process-primary-token"),ThreadOwner=n.ProcessOwner.Principal("syscall-entry-owning-process-primary-token"),
                ThreadOwnerCreatedFileTime=n.ProcessCreatedFileTime,EventSubject=n.ThreadEffective.Principal("syscall-entry-effective-thread-token"),
                EffectiveThreadContext=n.ThreadEffective.Principal("syscall-entry-effective-thread-token"),Impersonating=n.ThreadImpersonating,
                ThreadToken=n.ThreadImpersonating==true?n.ThreadEffective.Principal("syscall-entry-impersonation-token"):new(){Status=EvidenceStatus.Unavailable(n.ThreadImpersonating==false?"thread-has-no-impersonation-token":"thread-impersonation-state-unavailable")},
                ImpersonationStatus=n.ThreadImpersonating!=null?EvidenceStatus.Captured("syscall-entry-thread-impersonation-state"):EvidenceStatus.Unavailable("thread-impersonation-state-unavailable"),
                ProcessSessionId=n.ProcessOwner.SessionId,SessionStatus=n.ProcessOwner.SessionId!=null?EvidenceStatus.Captured("syscall-entry-process-token-session"):EvidenceStatus.Unavailable("process-token-session-unavailable"),
                Status=EvidenceStatus.Captured("syscall-entry-process-creation-identity")};
            return;
        }
        if(value.Source=="Linux Audit"&&value.Attribution is {Provider:"Linux Audit",EventTimeCredentials:true,CompleteRecordSet:true} audit&&audit.IsValid())
        {
            // Preserve historical syscall metadata even after process exit. It
            // cannot establish a process instance or qualify an executable.
            if(audit.ParentProcessId is >0&&audit.ParentProcessId!=Process.ParentPid)
                Process=Process with{ParentPid=audit.ParentProcessId,ParentStartKey=null,ParentStartedUtc=null,ParentInstanceId=null,ParentExecutablePath=null,
                    ParentStatus=new("partial","linux-audit-event-parent-pid; parent-process-instance-unavailable")};
            if(audit.CommandLine is {Length:>0} command)
            {
                var partial=audit.CommandLineTruncated==true||command.Length==2048;
                // Keep the separately bound later procfs observation when it
                // contains more information than the capped historical title.
                // The raw event retains the capped audit text and its status.
                if(!(partial&&Binding.State=="captured"&&Process.CommandLineStatus.State=="captured"&&Process.CommandLine is { } live&&live.Length>command.Length&&live.StartsWith(command,StringComparison.Ordinal)))
                    Process=Process with{CommandLine=command,CommandLineStatus=new(partial?"partial":"captured",
                        partial?"linux-audit-event-proctitle-at-limit; mutable-application-memory":"linux-audit-event-proctitle; mutable-application-memory")};
            }
            // Audit ses is the audit login session, not the POSIX session ID.
            // EventSubject retains it; ProcessSessionId stays independently sourced.
        }
        if(value.Attribution?.LinuxKernel is {} linux)
        {
            var known=linux.ProcessId!=null&&linux.ProcessStartNs!="0"&&linux.SelfExecId!="0"&&linux.ProviderEpoch!="0";
            Process=Process with{Pid=linux.ProcessId,ThreadId=linux.ThreadId,StartKey=known?linux.ProcessStartKey:null,StartedUtc=null,
                InstanceId=known&&sensor.Length>0?Correlate(sensor,linux.ProcessId!.Value,linux.ProcessStartKey):null,
                ExecutablePath=value.Process,EventSubject=Subject(value),EffectiveThreadContext=Subject(value),
                Owner=new(){Status=EvidenceStatus.Unavailable("kernel-task-credentials-do-not-establish-thread-group-owner")},
                ThreadToken=new(){Status=EvidenceStatus.Unavailable("windows-token-not-applicable-to-linux")},Impersonating=null,
                ImpersonationStatus=EvidenceStatus.Unavailable("windows-impersonation-not-applicable-to-linux"),
                Status=known?EvidenceStatus.Captured("linux-kernel-task-lifetime-and-exec; wall-start-unavailable"):EvidenceStatus.Unavailable("linux-kernel-process-lifetime-unavailable")};
            return;
        }
        if(value.Source!="Windows minifilter"||value.Attribution?.WindowsKernel is not {} k)return;
        // Preserve operation-time token evidence even if the process has already exited.
        // Later process inspection never replaces these observed security contexts.
        var start=k.ProcessCreatedFileTime?.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var deferred=k.DeferredTokenContext;
        var impersonating=deferred?.ThreadImpersonating??k.ThreadImpersonating;
        var effective=deferred?.ThreadEffective??k.ThreadEffective;
        Process=Process with{Pid=k.ProcessId,ThreadId=k.ThreadId,StartKey=start,StartedUtc=k.ProcessCreatedFileTime is {} stamp?DateTimeOffset.FromFileTime(stamp):null,
            InstanceId=k.ProcessId is {} pid&&start!=null&&sensor.Length>0?Correlate(sensor,pid,start):null,
            Owner=(deferred?.RequestorPrimary??k.RequestorPrimary).Principal(deferred?.PrimaryMetadataTiming??"kernel-requestor-primary-token"),EventSubject=k.Subject.Principal(k.SubjectSource),
            ThreadOwner=(deferred?.ThreadOwnerPrimary??k.ThreadOwnerPrimary)?.Principal(deferred?.PrimaryMetadataTiming??("kernel-initiating-thread-owner-primary-token; "+k.ThreadOwnerStatus)),ThreadOwnerCreatedFileTime=deferred?.ThreadProcessCreatedFileTime??k.ThreadProcessCreatedFileTime,
            ThreadToken=impersonating==true?effective.Principal(deferred?.ImpersonationMetadataTiming??"kernel-request-thread-impersonation-token"):new(){Status=EvidenceStatus.Unavailable(impersonating==false?"request-thread-has-no-impersonation-token":"request-thread-context-unavailable")},
            EffectiveThreadContext=effective.Principal(deferred?.ImpersonationMetadataTiming??"kernel-request-thread-effective-context"),Impersonating=impersonating,
            ImpersonationStatus=impersonating!=null?EvidenceStatus.Captured(deferred!=null?"callback-token-reference; metadata-query-later":"referenced-request-thread-token-at-preoperation"):EvidenceStatus.Unavailable("request-thread-context-unavailable"),
            Status=k.ProcessId!=null&&start!=null?EvidenceStatus.Captured("kernel-requestor-process-start"):EvidenceStatus.Unavailable("kernel-process-identity-unavailable")};
    }
    public static PrincipalEvidence Subject(AgentEvent e)
    {
        var a=e.Attribution;
        if(a?.WindowsSyscall is {} s)return s.Native.ThreadEffective.Principal("syscall-entry-effective-thread-token");
        if(a?.LinuxKernel is {} linux)return new(){Uid=linux.Uid,EffectiveUid=linux.EffectiveUid,FileSystemUid=linux.FileSystemUid,Gid=linux.Gid,EffectiveGid=linux.EffectiveGid,FileSystemGid=linux.FileSystemGid,
            CredentialNamespace=linux.CredentialNamespace,Status=linux.CredentialFields==63&&linux.CredentialError==0?EvidenceStatus.Captured("linux-kernel-accessing-task-credentials"):
                new(linux.CredentialFields==0?"unavailable":"partial","linux-kernel-credential-fields-incomplete",linux.CredentialError.ToString(System.Globalization.CultureInfo.InvariantCulture))};
        if(e.Source=="Windows minifilter"&&a?.WindowsKernel is {} k)return k.Subject.Principal(k.SubjectSource);
        if(e.Source is "Windows audit 4656" or "Windows audit 4663")return new(){Sid=a?.UserSid,Account=e.User,LogonId=a?.LogonId,Status=a?.UserSid!=null?EvidenceStatus.Captured("windows-security-event-subject"):EvidenceStatus.Unavailable("audit-subject-sid-unavailable")};
        if(e.Source=="Linux Audit"&&a!=null)return new(){Uid=a.UserId,EffectiveUid=a.EffectiveUserId,FileSystemUid=a.FileSystemUserId,Gid=a.GroupId,EffectiveGid=a.EffectiveGroupId,FileSystemGid=a.FileSystemGroupId,Account=a.UserName,SessionId=a.SessionId,Status=a.EventTimeCredentials?EvidenceStatus.Captured("linux-audit-event-credentials"):EvidenceStatus.Unavailable("incomplete-audit-credentials")};
        return new(){Status=EvidenceStatus.Unavailable("provider-does-not-supply-event-time-principal")};
    }
    public void Dispose(){DeferredMetadata=null;MetadataHandle?.Dispose();MetadataHandle=null;Image?.Dispose();Image=null;}
}
