using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Durable intake feeds the existing forensic collector/evidence store. It is not
// an alternate forensic upload path. Enabled only by the explicit staging opt-in.
internal sealed partial class WindowsStagedActorStore
{
    private sealed record Record(int Version,string Sensor,ActorAcquisitionEvidence Acquisition,FileIdentityEvidence Source,WindowsCreationRecord? Creation=null);
    private readonly string root,sensor;
    private readonly long quota;
    private readonly object gate=new();
    internal WindowsStagedActorStore(string directory,string sensor,long quota=512L*1024*1024)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||quota<1)throw new ArgumentException("Invalid intake configuration");
        this.sensor=sensor;this.quota=quota;root=Path.GetFullPath(Path.Combine(directory,"kernel-actor-intake"));EvidenceStore.EnsurePrivate(root);
    }
    private string EventPath(string id)
    {if(!Guid.TryParseExact(id,"N",out _))throw new InvalidDataException("Invalid intake event ID");return Path.Combine(root,id+".event.json");}
    private string CandidatePath(ActorAcquisitionEvidence a)=>Path.Combine(root,Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensor+":"+a.Provider+":"+a.EventInstance+":"+a.ProcessGeneration+":"+a.CandidateId+":"+a.ProcessId+":"+a.ProcessCreatedFileTime)))+".candidate.json");
    private string ArtifactPath(string id)
    {if(!Guid.TryParseExact(id,"N",out _))throw new InvalidDataException("Invalid intake artifact ID");return Path.Combine(root,id+".bin");}
    private void CheckQuota(long needed)
    {
        // Enumerated FileInfo.Length is populated by the directory query. Avoid
        // a second metadata request for every retained artifact/manifest while
        // still summing current files, including failed temporary files and WAL.
        // No lifetime byte cache or relaxed quota is introduced.
        if(new DirectoryInfo(root).EnumerateFiles().Sum(p=>p.Length)+needed>quota)throw new IOException("Actor intake quota exceeded; journal ACK withheld");
    }
    private static void NoLinks(string file)
    {for(string? p=Path.GetFullPath(file);p!=null;p=Path.GetDirectoryName(p))if(Path.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Linked actor intake path rejected");}
    private static FileStream Open(string path,FileMode mode,FileAccess access)
    {
        NoLinks(path);var o=new FileStreamOptions{Mode=mode,Access=access,Share=FileShare.Read,Options=FileOptions.WriteThrough};
        if(!OperatingSystem.IsWindows()&&mode!=FileMode.Open)o.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        return new FileStream(path,o);
    }
    private static Record Read(string path)
    {using var f=Open(path,FileMode.Open,FileAccess.Read);if(f.Length>32768)throw new InvalidDataException("Oversized acquisition manifest");return JsonSerializer.Deserialize<Record>(f)??throw new InvalidDataException("Empty acquisition manifest");}
    private void Save(string path,Record record)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(record);if(bytes.Length>32768)throw new InvalidDataException("Oversized acquisition manifest");
        SaveImmutable(path,bytes);
    }
    private void SaveImmutable(string path,byte[] bytes)
    {
        if(File.Exists(path)){if(!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Acquisition identity collision");return;}
        CheckQuota(bytes.Length);var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        using(var file=Open(temporary,FileMode.CreateNew,FileAccess.Write)){file.Write(bytes);file.Flush(true);}
        // Windows write-through rename makes the manifest visible only after the bytes were flushed.
        if(OperatingSystem.IsWindows()){if(!MoveFileEx(ExtendedWindowsPath(temporary),ExtendedWindowsPath(path),8))throw new IOException("Acquisition manifest commit failed: "+Marshal.GetLastPInvokeError());}
        else File.Move(temporary,path,false);
    }
    internal ActorLease? Restore(AgentEvent e)
    {
        // Committed manifests are immutable and atomically renamed. Delivery can
        // read one without waiting for another candidate's disk flush or transfer.
        var path=EventPath(e.EventId);return File.Exists(path)?Lease(Read(path),e):null;
    }
    internal ActorLease? RestoreForDelivery(AgentEvent e,Action<string> health)
    {
        Record? record=null;
        try
        {
            var path=EventPath(e.EventId);if(!File.Exists(path))throw new FileNotFoundException("Durable acquisition manifest missing",path);
            record=Read(path);return Lease(record,e);
        }
        catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or ArgumentException or System.ComponentModel.Win32Exception)
        {
            var status=new EvidenceStatus("failed","durable-actor-snapshot-recovery-failed",ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode.ToString():ex.GetType().Name);
            var lease=ActorLease.Unavailable(e,status.Reason);lease.ApplyKernel(e,sensor);lease.Binding=status;
            // Trust historical metadata only after validating its original linkage.
            // The private source record and suspect bytes remain untouched.
            if(record is {Version:1}&&record.Sensor==sensor&&record.Acquisition is {} a&&a.SourceEventId==e.EventId&&a.EventInstance==e.Attribution?.WindowsKernel?.Instance&&a.EventSequence==e.Attribution?.WindowsKernel?.Sequence&&a.IsValid(lease.Process,e.EventId,null,null)&&a.Status.State=="captured"&&record.Source is {} historicalSource&&a.IsValidSourceFile(historicalSource)&&historicalSource.Size==a.SnapshotFile?.Size)
            {
                // A captured original volume/file ID remains historical evidence
                // when the separate snapshot is damaged. It grants no usable
                // image, trust identity, or new preservation success.
                lease.Acquisition=a with{RecoveryStatus=status};lease.File=historicalSource;
                lease.BindingSourceEventId=e.EventId;lease.BindingCapturedUtc=a.PersistedUtc;
                lease.Process=WindowsProcessCreationProtocol.Apply(record.Creation,a,lease.Process,sensor);
            }
            health("Actor snapshot recovery failed; original operation/token evidence retained: "+e.EventId+" "+status.NativeCode);
            return lease;
        }
    }
    private ActorLease Lease(Record record,AgentEvent e)
    {
        if(record.Version!=1||record.Acquisition?.Status==null||record.Source?.Status==null)throw new InvalidDataException("Invalid acquisition manifest structure");
        var a=record.Acquisition;var lease=ActorLease.Unavailable(e,a.Status.Reason);lease.ApplyKernel(e,sensor);
        try
        {
            if(record.Version!=1||record.Sensor!=sensor||a.SourceEventId!=e.EventId||a.EventInstance!=e.Attribution?.WindowsKernel?.Instance||a.EventSequence!=e.Attribution?.WindowsKernel?.Sequence||!a.IsValid(lease.Process,e.EventId,null,null)||!a.IsValidSourceFile(record.Source))throw new InvalidDataException("Acquisition recovery linkage invalid");
            lease.Acquisition=a;lease.File=record.Source;
            lease.Process=WindowsProcessCreationProtocol.Apply(record.Creation,a,lease.Process,sensor);
            if(a.Status.State!="captured")return lease;
            if(record.Source.Size!=a.SnapshotFile!.Size)throw new InvalidDataException("Historical source and snapshot metadata disagree");
            var path=ArtifactPath(a.SnapshotId!);lease.Image=Open(path,FileMode.Open,FileAccess.Read);
            var identity=NativeFileIdentity.Read(lease.Image);
            if(!NativeFileIdentity.Same(a.SnapshotFile!,identity)||lease.Image.Length!=a.SnapshotFile!.Size||Convert.ToHexString(SHA256.HashData(lease.Image))!=a.SnapshotSha256||!NativeFileIdentity.Same(identity,NativeFileIdentity.Read(lease.Image)))throw new InvalidDataException("Acquisition snapshot failed identity/hash recovery check");
            lease.SnapshotFile=identity;lease.SnapshotPath=path;lease.Binding=EvidenceStatus.Captured("exact-operation-provider-process-candidate-binding");lease.BindingSourceEventId=e.EventId;lease.BindingCapturedUtc=a.PersistedUtc;return lease;
        }
        catch{lease.Dispose();throw;}
    }
    internal ActorLease Capture(AgentEvent e,string provider,Func<byte[],int,byte[]> send,Action<string> health)
    {
        lock(gate)
        {
            var existing=Restore(e);if(existing!=null)return existing;
            var raw=send(WindowsStagedActorProtocol.CompanionRequest(e,provider),88);
            var a=WindowsStagedActorProtocol.Companion(raw,e,provider);var source=new FileIdentityEvidence{Status=EvidenceStatus.Unavailable("operation-bound-source-metadata-unavailable")};
            if(a.ProcessGeneration==null){var missing=new Record(1,sensor,a,source);Save(EventPath(e.EventId),missing);return Lease(missing,e);}
            var proactive=LinkProcessAcquisition(e,a);
            if(proactive!=null){Save(EventPath(e.EventId),proactive);return Lease(proactive,e);}
            var candidate=CandidatePath(a);
            if(File.Exists(candidate))
            {
                var prior=Read(candidate);var p=prior.Acquisition;
                if(prior.Sensor!=sensor||p.Provider!=a.Provider||p.EventInstance!=a.EventInstance||p.ProviderStatus!=a.ProviderStatus||p.ProcessGeneration!=a.ProcessGeneration||p.CandidateId!=a.CandidateId||p.ProcessId!=a.ProcessId||p.ProcessCreatedFileTime!=a.ProcessCreatedFileTime)throw new InvalidDataException("Candidate acquisition identity collision");
                var reused=prior with{Acquisition=p with{SourceEventId=e.EventId,EventSequence=a.EventSequence,BindingKind=a.BindingKind}};
                using(var verified=Lease(reused,e)){}Save(EventPath(e.EventId),reused);return Lease(reused,e);
            }
            Record record;WindowsCreationRecord? creation=null;
            try
            {
                // The operation owns an independent immutable blob reference. Read
                // through that exact event even after candidate-table TTL expiry.
                // An old driver without this command fails visibly; no path fallback.
                byte[] Request(uint op,uint offset=0,uint count=0)=>a.BindingKind=="bytes-pinned"?WindowsStagedActorProtocol.OperationRequest(a,op,offset,count):WindowsStagedActorProtocol.CandidateRequest(a,op,offset,count);
                var metadata=send(Request(13),WindowsStagedActorProtocol.HeaderBytes);
                (a,source)=WindowsStagedActorProtocol.Metadata(metadata,a);var length=WindowsStagedActorProtocol.U32(metadata,8);
                var sourceIdentity=WindowsStagedActorProtocol.QuerySourceIdentity(Request(26),send);
                (a,source)=WindowsStagedActorProtocol.SourceIdentity(a,source,sourceIdentity.Reply,sourceIdentity.Failure,a.BindingKind=="bytes-pinned");
                creation=WindowsProcessCreationProtocol.Query(Request(27),a,send);
                CheckQuota(length+65536);var id=Guid.NewGuid().ToString("N");var artifact=ArtifactPath(id);
                string hash;
                using(var file=Open(artifact,FileMode.CreateNew,FileAccess.ReadWrite))
                {
                    using var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    for(uint offset=0;offset<length;)
                    {
                        var count=Math.Min(65536u,length-offset);var bytes=send(Request(10,offset,count),checked((int)(144+count)));
                        WindowsStagedActorProtocol.CheckReply(bytes,a,length,offset,count,metadata);file.Write(bytes,144,(int)count);digest.AppendData(bytes,144,(int)count);offset+=count;
                    }
                    file.Flush(true);hash=Convert.ToHexString(digest.GetHashAndReset());
                }
                using(var file=Open(artifact,FileMode.Open,FileAccess.Read))
                {
                    var identity=NativeFileIdentity.Read(file);
                    if(file.Length!=length||Convert.ToHexString(SHA256.HashData(file))!=hash||!NativeFileIdentity.Same(identity,NativeFileIdentity.Read(file)))throw new IOException("Snapshot byte verification failed");
                    a=a with{SnapshotId=id,SnapshotSha256=hash,SnapshotFile=identity,PersistedUtc=DateTimeOffset.UtcNow,Status=EvidenceStatus.Captured("private-snapshot-flushed-and-independently-hash-verified")};
                }
                record=new(1,sensor,a,source,creation);
                using(var verified=Lease(record,e)){}Save(candidate,record);Save(EventPath(e.EventId),record);
                return Lease(record,e);
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or System.ComponentModel.Win32Exception or ArgumentException or OverflowException)
            {
                // Partial artifacts remain private for diagnosis and count against the bounded quota.
                // Preserve the operation and token evidence even when no executable can be obtained.
                a=a with{SnapshotId=null,SnapshotSha256=null,SnapshotFile=null,PersistedUtc=null,Status=new("failed","operation-bound-actor-acquisition-failed",ex is COMException?"0x"+ex.HResult.ToString("X8"):ex.GetType().Name)};
                record=new(1,sensor,a,source,creation);Save(EventPath(e.EventId),record);health("Actor acquisition failed; operation/token evidence retained: "+a.Status.NativeCode);return Lease(record,e);
            }
        }
    }
    // The source calls this only after the raw operation journal is committed.
    // A lost response can be retried with the same immutable snapshot receipt.
    internal void AcknowledgeAfterJournal(AgentEvent e,string journalPath,Func<byte[],int,byte[]> send,Action<string> health)
    {
        var expected=Path.Combine(Path.GetDirectoryName(root)!,"kernel-inbox",e.EventId+".record");
        if(!Path.GetFullPath(journalPath).Equals(expected,StringComparison.OrdinalIgnoreCase)||!File.Exists(expected))throw new InvalidDataException("Durable operation journal required before actor ACK");
        var decoded=WindowsKernelDecoder.Decode(File.ReadAllBytes(expected),sensor,p=>p,false);
        if(decoded.EventId!=e.EventId)throw new InvalidDataException("Actor ACK journal does not match event");
        using var actor=RestoreForDelivery(e,health);
        if(actor?.Image==null||actor.Acquisition is not {Status.State:"captured",RecoveryStatus:null} acquisition)return;
        var request=WindowsStagedActorProtocol.DurableAcknowledgement(acquisition);
        try
        {
            if(!send(request,request.Length).AsSpan().SequenceEqual(request))throw new InvalidDataException("Durable actor receipt differs from its claim");
            var receipt=Path.Combine(root,acquisition.SnapshotId+".ack");
            SaveImmutable(receipt,request);
        }
        catch(COMException ex){health("Durable actor snapshot retained; candidate ACK unavailable: 0x"+ex.HResult.ToString("X8"));}
    }
    private static string ExtendedWindowsPath(string path)
    {
        var full=Path.GetFullPath(path);
        return full.StartsWith(@"\\?\",StringComparison.Ordinal)?full:full.StartsWith(@"\\",StringComparison.Ordinal)?@"\\?\UNC\"+full[2..]:@"\\?\"+full;
    }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]private static extern bool MoveFileEx(string source,string destination,uint flags);
}
