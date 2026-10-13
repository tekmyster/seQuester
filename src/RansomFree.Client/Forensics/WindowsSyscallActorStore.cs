using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class WindowsStagedActorStore
{
    private readonly object syscallIndexGate=new();
    private readonly Dictionary<string,List<ProcessRecord>> syscallIndex=new(StringComparer.Ordinal);
    private readonly HashSet<string> syscallVerifiedSnapshots=new(StringComparer.Ordinal);
    private bool syscallIndexLoaded;
    private int syscallIndexFailures;
    private static string SyscallProcessKey(WindowsReadyActor k)=>k.Provider+":"+k.OperationInstance+":"+k.Pid+":"+k.Created;
    private void IndexSyscallProcess(ProcessRecord p)
    {
        if(p.State!="captured")return;
        lock(syscallIndexGate){var key=SyscallProcessKey(p.Ready);if(!syscallIndex.TryGetValue(key,out var list)){
            if(syscallIndex.Count>=4096)syscallIndex.Remove(syscallIndex.Keys.First());syscallIndex[key]=list=new();}
            if(!list.Any(x=>x.Ready.Generation==p.Ready.Generation&&x.Ready.Candidate==p.Ready.Candidate)){if(list.Count<2)list.Add(p);}}
    }
    // Both sources observe the exact PID + creation FILETIME on this sensor.
    // Only a fully committed, verified process snapshot from the connected
    // acquisition provider/epoch may be linked. No later PID/path reopening.
    internal ActorLease CaptureSyscall(AgentEvent observed,string provider,ulong instance,Func<string,string> resolvePath,out AgentEvent value,Action<string>? health=null)
    {
        value=observed;
        if(!WindowsSyscallObservation.Matches(observed)||observed.Attribution?.WindowsSyscall is not {} syscall)
            throw new InvalidDataException("Invalid syscall acquisition observation");
        var n=syscall.Native;
        lock(syscallIndexGate)if(!syscallIndexLoaded)
        {
            var scanned=0;
            foreach(var path in Directory.EnumerateFiles(root,"*.process.json")){
                if(++scanned>8192){health?.Invoke("Syscall executable recovery scan capacity reached; unmatched processes remain unavailable");break;}
                try{
                    var recovered=ReadProcess(path);
                    if(!string.Equals(path,ProcessPath(recovered.Ready),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Process acquisition index filename differs from its full identity");
                    IndexSyscallProcess(recovered);
                }
                catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException){
                    syscallIndexFailures++;health?.Invoke("Syscall executable recovery rejected index "+Path.GetFileName(path)+": "+ex.GetType().Name);
                }
            }
            // Only mark the directory scan complete after enumeration succeeds.
            // One damaged record cannot hide independently verified records.
            syscallIndexLoaded=true;
        }
        List<ProcessRecord> matches;
        lock(syscallIndexGate)matches=syscallIndex.TryGetValue(provider+":"+instance+":"+n.ProcessId+":"+n.ProcessCreatedFileTime,out var found)?[..found]:[];
        if(matches.Count!=1){var missing=ActorLease.Unavailable(observed,matches.Count==0?(syscallIndexFailures>0?"syscall-exact-process-snapshot-unavailable; recovery-records-rejected":"syscall-exact-process-snapshot-unavailable-or-index-capacity"):"syscall-process-snapshot-ambiguous");missing.ApplyKernel(observed,sensor);return missing;}
        var record=matches[0];bool verified;
        lock(syscallIndexGate)verified=syscallVerifiedSnapshots.Contains(record.SnapshotId!);
        if(!verified){VerifyProcessBytes(record);lock(syscallIndexGate){if(syscallVerifiedSnapshots.Count>=4096)syscallVerifiedSnapshots.Clear();syscallVerifiedSnapshots.Add(record.SnapshotId!);}}
        // Cached verification only avoids re-reading unchanged private bytes.
        // Every reopened descriptor is still checked below against its original
        // stable identity and change marker; the collector checks hash linkage.
        var key=record.Ready;
        var a=TransferFields(key) with{Version=2,Method="windows-process-snapshot-bound-to-syscall",SourceEventId=observed.EventId,
            EventSequence=n.Sequence,BindingKind="bytes-pinned",SyscallSourceInstance=syscall.SourceInstance,SyscallRecordSha256=n.RawRecordSha256};
        var (acquisition,source)=WindowsStagedActorProtocol.Metadata(ProcessMetadata(record.Metadata!),a);
        (acquisition,source)=WindowsStagedActorProtocol.SourceIdentity(acquisition,source,record.SourceIdentityReply==null?null:ProcessMetadata(record.SourceIdentityReply),record.SourceIdentityFailure,false);
        acquisition=acquisition with{SnapshotId=record.SnapshotId,SnapshotSha256=record.Sha256,SnapshotFile=record.SnapshotFile,PersistedUtc=record.RecordedUtc,
            Status=EvidenceStatus.Captured("exact-process-creation-key; committed-snapshot-hash-verified")};
        var lease=ActorLease.Unavailable(observed,"process-snapshot-pending");lease.ApplyKernel(observed,sensor);
        lease.Process=WindowsProcessCreationProtocol.Apply(record.Creation,acquisition,lease.Process,sensor);
        // ImageName is explicitly a creation observation; never resolve a path
        // from an unrelated live process that reused this PID.
        var image=lease.Process.Creation?.ImageName;
        var executable=string.IsNullOrWhiteSpace(image)?null:resolvePath(image);
        value=observed with{Process=executable,Attribution=observed.Attribution! with{ProcessName=executable==null?null:Path.GetFileName(executable)}};
        lease.Process=lease.Process with{ExecutablePath=executable};lease.Acquisition=acquisition;lease.File=source;
        var imagePath=ArtifactPath(record.SnapshotId!);
        try
        {
            lease.Image=Open(imagePath,FileMode.Open,FileAccess.Read);lease.SnapshotFile=NativeFileIdentity.Read(lease.Image);
            if(!NativeFileIdentity.Same(record.SnapshotFile!,lease.SnapshotFile))throw new IOException("Syscall snapshot identity changed");
            lease.SnapshotPath=imagePath;lease.Binding=EvidenceStatus.Captured("syscall-process-creation-key-and-verified-proactive-snapshot");
            lease.BindingSourceEventId=observed.EventId;lease.BindingCapturedUtc=record.RecordedUtc;
            if(!acquisition.IsValid(lease.Process,observed.EventId,null,record.Sha256)||!acquisition.IsValidSourceFile(source)||!WindowsSyscallObservation.Matches(value))throw new InvalidDataException("Syscall actor acquisition linkage invalid");
            return lease;
        }
        catch{lease.Dispose();throw;}
    }
}
