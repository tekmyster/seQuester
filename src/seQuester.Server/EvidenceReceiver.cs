using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Runtime.InteropServices;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed class EvidenceUploadException(int status,string reason):Exception(reason)
{public int Status {get;}=status;}

// One writer, protected filenames generated from validated IDs, no executable loading or extraction.
public sealed class EvidenceReceiver
{
    private readonly Store store;
    private readonly string root;
    private readonly long maximum,perSensor,total;
    private readonly SemaphoreSlim gate=new(1,1);
    public EvidenceReceiver(Store store,string dataDirectory,long maximumBytes=256L*1024*1024,long perSensorBytes=1024L*1024*1024,long totalBytes=10L*1024*1024*1024)
    {
        if(maximumBytes<1||maximumBytes>1024L*1024*1024||perSensorBytes<maximumBytes||totalBytes<perSensorBytes)throw new ArgumentException("Invalid evidence quota.");
        this.store=store;maximum=maximumBytes;perSensor=perSensorBytes;total=totalBytes;
        root=Path.GetFullPath(Path.Combine(dataDirectory,"actor-evidence"));
        var webroot=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"wwwroot"))+Path.DirectorySeparatorChar;
        if((root+Path.DirectorySeparatorChar).StartsWith(webroot,OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal))throw new ArgumentException("Evidence must be outside webroot.");
        PrivateDirectory(root);store.InitializeEvidenceTransferStorage();
    }
    private static void NoLinks(string path)
    {
        for(string? p=Path.GetFullPath(path);p!=null;p=Path.GetDirectoryName(p))
            if((File.Exists(p)||Directory.Exists(p))&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new EvidenceUploadException(409,"linked-evidence-path-rejected");
    }
    private static void PrivateDirectory(string path)
    {
        NoLinks(path);
        var existed=Directory.Exists(path);
        if(OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
            foreach(var sid in new[]{new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),WindowsIdentity.GetCurrent().User!}.Distinct())
                acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            var info=new DirectoryInfo(path);var existing=info.GetAccessControl(AccessControlSections.Access);
            static string Rules(DirectorySecurity security)
            {
                if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
                var values=new List<string>();
                foreach(FileSystemAccessRule r in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
                    values.Add($"{r.IdentityReference.Value}:{r.AccessControlType}:{(int)r.FileSystemRights}:{(int)r.InheritanceFlags}:{(int)r.PropagationFlags}:{r.IsInherited}");
                values.Sort(StringComparer.Ordinal);return string.Join(";",values);
            }
            // Check permissions on every access, but do not recursively reapply
            // an identical inheritable DACL to every previously received artifact.
            if(!existing.AreAccessRulesProtected||!existing.AreAccessRulesCanonical||Rules(existing)!=Rules(acl))info.SetAccessControl(acl);
        }
        else{Directory.CreateDirectory(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);if(!existed)SyncDirectory(Path.GetDirectoryName(path)!);}
    }
    [DllImport("libc",SetLastError=true)] private static extern int open(string path,int flags);
    [DllImport("libc",SetLastError=true)] private static extern int fsync(int descriptor);
    [DllImport("libc",SetLastError=true)] private static extern int close(int descriptor);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool MoveFileEx(string source,string destination,uint flags);
    private static void SyncDirectory(string path)
    {
        if(!OperatingSystem.IsLinux())return;
        var fd=open(path,0x10000|0x80000); // O_DIRECTORY | O_CLOEXEC, read-only.
        if(fd<0)throw new IOException("Evidence directory open failed: "+Marshal.GetLastPInvokeError());
        try{if(fsync(fd)!=0)throw new IOException("Evidence directory sync failed: "+Marshal.GetLastPInvokeError());}finally{close(fd);}
    }
    private static void FinalizeFile(string source,string destination)
    {
        if(OperatingSystem.IsWindows()){if(!MoveFileEx(source,destination,8))throw new IOException("Evidence durable rename failed: "+Marshal.GetLastPInvokeError());}
        else{File.Move(source,destination,false);SyncDirectory(Path.GetDirectoryName(destination)!);}
    }
    private FileStream LockStore()
    {
        NoLinks(root);var path=Path.Combine(root,"writer.lock");NoLinks(path);
        return OpenPrivate(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    }
    private static FileStream OpenPrivate(string path,FileMode mode,FileAccess access,FileShare share)
    {
        NoLinks(path);var o=new FileStreamOptions{Mode=mode,Access=access,Share=share};
        if(!OperatingSystem.IsWindows()&&mode!=FileMode.Open)o.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        if(OperatingSystem.IsWindows()&&mode==FileMode.CreateNew)
        {
            var security=new FileSecurity();security.SetAccessRuleProtection(true,false);
                security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid,null),FileSystemRights.ExecuteFile,AccessControlType.Deny));
                foreach(var sid in new[]{new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null),WindowsIdentity.GetCurrent().User!}.Distinct())security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
            var rights=(access.HasFlag(FileAccess.Read)?FileSystemRights.Read:0)|(access.HasFlag(FileAccess.Write)?FileSystemRights.Write:0)|FileSystemRights.Synchronize;
            return new FileInfo(path).Create(mode,rights,share,4096,FileOptions.None,security);
        }
        return new FileStream(path,o);
    }
    private string PathFor(string endpoint,string evidence,string extension)
    {
        if(!EvidenceTransferLimits.Id(endpoint)||!EvidenceTransferLimits.Id(evidence))throw new EvidenceUploadException(400,"invalid-evidence-identifier");
        var directory=Path.Combine(root,endpoint);PrivateDirectory(directory);var path=Path.Combine(directory,evidence+extension);NoLinks(path);return path;
    }
    private EvidenceUploadReceipt Required(string endpoint,string id)=>store.EvidenceReceipt(endpoint,id)??throw new EvidenceUploadException(404,"evidence-not-found");
    private EvidenceUploadReceipt Progress(EvidenceUploadReceipt r)
    {
        var final=PathFor(r.SensorId,r.EvidenceId,".bin");var part=PathFor(r.SensorId,r.EvidenceId,".part");
        var size=File.Exists(final)?new FileInfo(final).Length:File.Exists(part)?new FileInfo(part).Length:0;
        if(size>r.Size||r.State=="received"&&(!File.Exists(final)||size!=r.Size))throw new EvidenceUploadException(409,"evidence-store-size-mismatch");
        return r with{ReceivedBytes=size};
    }
    public async Task<EvidenceUploadReceipt> Start(string endpoint,EvidenceUploadStart request,CancellationToken ct=default)
    {
        if(!EvidenceTransferLimits.Id(request.CompletionEventId)||request.ManifestBase64 is not {Length:>0 and <=87384})throw new EvidenceUploadException(400,"invalid-upload-manifest");
        byte[] manifest;try{manifest=Convert.FromBase64String(request.ManifestBase64);}catch(FormatException){throw new EvidenceUploadException(400,"invalid-upload-manifest");}
        if(manifest.Length>EvidenceTransferLimits.ManifestBytes)throw new EvidenceUploadException(413,"manifest-size-exceeded");
        await gate.WaitAsync(ct);try{using var owned=LockStore();
            var completion=store.EvidenceSource(endpoint,request.CompletionEventId)??throw new EvidenceUploadException(409,"completion-event-not-received");
            var f=completion.Forensics;var p=f?.Preservation;
            if(completion.Source!="Forensic enrichment"||f==null||!f.IsValid()||f.SensorId!=endpoint||f.RelatedEventId!=p?.SourceEventId||p is not {Status.State:"captured",HashMatched:true,Size:not null}||!EvidenceTransferLimits.Id(p.EvidenceId)||!EvidenceTransferLimits.Hash(p.Sha256)||!EvidenceTransferLimits.Hash(p.ManifestSha256)||p.Sha256!=f.ActorExecutable.Sha256||p.ProcessInstanceId!=f.Process.InstanceId)throw new EvidenceUploadException(409,"verified-actor-preservation-required");
            if(p.Size>maximum)throw new EvidenceUploadException(413,"actor-upload-size-exceeded");
            var original=store.EvidenceSource(endpoint,p.SourceEventId!);
            if(original==null||original.ProcessId!=completion.ProcessId||original.Process!=completion.Process||original.Forensics?.Process.InstanceId!=f.Process.InstanceId)throw new EvidenceUploadException(409,"source-event-linkage-missing");
            if(!Convert.ToHexString(SHA256.HashData(manifest)).Equals(p.ManifestSha256,StringComparison.OrdinalIgnoreCase))throw new EvidenceUploadException(422,"manifest-hash-mismatch");
            try
            {
                using var json=JsonDocument.Parse(manifest,new JsonDocumentOptions{MaxDepth=16});UniqueKeys(json.RootElement);var recorded=json.RootElement.GetProperty("Preservation").Deserialize<PreservationEvidence>();
                if(json.RootElement.GetProperty("SchemaVersion").GetInt32()!=1||recorded==null||recorded.EvidenceId!=p.EvidenceId||recorded.SourceEventId!=p.SourceEventId||recorded.ProcessInstanceId!=p.ProcessInstanceId||recorded.Sha256!=p.Sha256||recorded.Size!=p.Size||recorded.HashMatched!=true||recorded.Status.State!="captured"||json.RootElement.GetProperty("ExpectedSha256").GetString()!=p.Sha256||json.RootElement.GetProperty("Process").GetProperty("InstanceId").GetString()!=p.ProcessInstanceId)throw new EvidenceUploadException(422,"manifest-linkage-mismatch");
                var manifestProcess=json.RootElement.GetProperty("Process").Deserialize<ProcessInstanceEvidence>();
                if((manifestProcess?.Creation!=null||f.Process.Creation!=null||original.Forensics?.Process.Creation!=null)&&
                    (JsonSerializer.Serialize(manifestProcess)!=JsonSerializer.Serialize(f.Process)||JsonSerializer.Serialize(original.Forensics?.Process)!=JsonSerializer.Serialize(f.Process)))
                    throw new EvidenceUploadException(422,"process-creation-manifest-linkage-mismatch");
                var hasAcquisition=json.RootElement.TryGetProperty("ActorAcquisition",out var acquisition);
                if(hasAcquisition!=(f.ActorExecutable.Acquisition!=null))throw new EvidenceUploadException(422,"acquisition-manifest-linkage-mismatch");
                if(hasAcquisition)
                {
                    var a=acquisition.Deserialize<ActorAcquisitionEvidence>();
                    if(a==null||!a.IsValid(f.Process,f.EventId,f.RelatedEventId,p.Sha256)||a.SnapshotFile?.Size!=p.Size||
                        a.Version==2&&(!WindowsSyscallObservation.Matches(original)||!WindowsSyscallObservation.Matches(completion))||
                        JsonSerializer.Serialize(a)!=JsonSerializer.Serialize(f.ActorExecutable.Acquisition)||
                        JsonSerializer.Serialize(original.Forensics?.ActorExecutable.Acquisition)!=JsonSerializer.Serialize(a)||
                        JsonSerializer.Serialize(json.RootElement.GetProperty("ActorFile").Deserialize<FileIdentityEvidence>())!=JsonSerializer.Serialize(f.ActorExecutable.File))
                        throw new EvidenceUploadException(422,"acquisition-manifest-linkage-mismatch");
                }
                var hasNativeWork=json.RootElement.TryGetProperty("LinuxNativeWork",out var nativeWork);
                if(hasNativeWork!=(f.ActorExecutable.LinuxNativeWork!=null))throw new EvidenceUploadException(422,"linux-native-work-manifest-linkage-mismatch");
                if(hasNativeWork)
                {
                    var n=nativeWork.Deserialize<LinuxNativeWorkEvidence>();
                    if(n==null||!n.IsValid(f.EventId,f.RelatedEventId)||n.SourceEventId!=original.EventId||n.CompletionEventId!=completion.EventId||
                        JsonSerializer.Serialize(n)!=JsonSerializer.Serialize(f.ActorExecutable.LinuxNativeWork)||
                        original.Forensics?.ActorExecutable.LinuxNativeWork is {} priorWork&&JsonSerializer.Serialize(priorWork)!=JsonSerializer.Serialize(n))
                        throw new EvidenceUploadException(422,"linux-native-work-manifest-linkage-mismatch");
                }
                var hasLinux=json.RootElement.TryGetProperty("LinuxActorAcquisition",out var linuxAcquisition);
                if(hasLinux!=(f.ActorExecutable.LinuxAcquisition!=null))throw new EvidenceUploadException(422,"linux-acquisition-manifest-linkage-mismatch");
                if(hasLinux)
                {
                    var a=linuxAcquisition.Deserialize<LinuxActorAcquisitionEvidence>();var k=original.Attribution?.LinuxKernel;
                    // Raw observations can arrive before acquisition finishes.
                    // Bind to that original native record even when its initial
                    // forensic projection has no acquisition companion yet.
                    if(a==null||k==null||!LinuxKernelEvidence.Matches(original)||!LinuxKernelEvidence.Matches(completion)||!a.Matches(k)||
                        !a.IsValid(f.Process,f.EventId,f.RelatedEventId,p.Sha256,f.ActorExecutable.File)||a.SnapshotFile?.Size!=p.Size||
                        JsonSerializer.Serialize(a)!=JsonSerializer.Serialize(f.ActorExecutable.LinuxAcquisition)||
                        JsonSerializer.Serialize(k)!=JsonSerializer.Serialize(completion.Attribution?.LinuxKernel)||
                        original.Forensics?.ActorExecutable.LinuxAcquisition is {} priorLinux&&JsonSerializer.Serialize(priorLinux)!=JsonSerializer.Serialize(a)||
                        JsonSerializer.Serialize(manifestProcess)!=JsonSerializer.Serialize(f.Process)||
                        JsonSerializer.Serialize(json.RootElement.GetProperty("ActorFile").Deserialize<FileIdentityEvidence>())!=JsonSerializer.Serialize(f.ActorExecutable.File))
                        throw new EvidenceUploadException(422,"linux-acquisition-manifest-linkage-mismatch");
                }
            }catch(Exception ex)when(ex is JsonException or KeyNotFoundException or InvalidOperationException){throw new EvidenceUploadException(400,"invalid-upload-manifest");}
            var prior=store.EvidenceReceipt(endpoint,p.EvidenceId!);
            if(prior!=null)
            {
                if(prior.CompletionEventId!=completion.EventId||prior.Sha256!=p.Sha256||prior.ManifestSha256!=p.ManifestSha256||prior.Size!=p.Size)throw new EvidenceUploadException(409,"evidence-identity-conflict");
                return Progress(prior);
            }
            return store.ReserveEvidence(endpoint,completion,manifest,perSensor,total);
        }finally{gate.Release();}
    }
    public async Task<EvidenceUploadReceipt> Chunk(string endpoint,string id,long offset,byte[] bytes,CancellationToken ct=default)
    {
        if(!EvidenceTransferLimits.Id(id)||offset<0||bytes.Length is <1 or >EvidenceTransferLimits.ChunkBytes)throw new EvidenceUploadException(400,"invalid-evidence-chunk");
        await gate.WaitAsync(ct);try{using var owned=LockStore();var r=Required(endpoint,id);
            if(offset>r.Size||bytes.Length>r.Size-offset)throw new EvidenceUploadException(413,"evidence-chunk-exceeds-declared-size");
            var final=PathFor(endpoint,id,".bin");var path=File.Exists(final)?final:PathFor(endpoint,id,".part");
            using var output=OpenPrivate(path,File.Exists(path)?FileMode.Open:FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None);
            if(offset>output.Length)throw new EvidenceUploadException(409,"evidence-offset-gap");
            if(offset<output.Length)
            {
                if(offset+bytes.Length>output.Length)throw new EvidenceUploadException(409,"evidence-overlap-conflict");
                output.Position=offset;var existing=new byte[bytes.Length];output.ReadExactly(existing);
                if(!existing.AsSpan().SequenceEqual(bytes))throw new EvidenceUploadException(409,"evidence-chunk-conflict");
            }
            else
            {
                if(r.State=="received"||path==final)throw new EvidenceUploadException(409,"evidence-already-finalized");
                output.Position=offset;output.Write(bytes);output.Flush(true);
            }
            return r with{ReceivedBytes=output.Length};
        }finally{gate.Release();}
    }
    public async Task<EvidenceUploadReceipt> Finish(string endpoint,string id,CancellationToken ct=default)
    {
        if(!EvidenceTransferLimits.Id(id))throw new EvidenceUploadException(400,"invalid-evidence-identifier");
        await gate.WaitAsync(ct);try{using var owned=LockStore();var r=Required(endpoint,id);var final=PathFor(endpoint,id,".bin");var part=PathFor(endpoint,id,".part");
            var source=File.Exists(final)?final:part;
            if(!File.Exists(source)&&r.Size==0){using var empty=OpenPrivate(part,FileMode.CreateNew,FileAccess.Write,FileShare.None);empty.Flush(true);}
            if(!File.Exists(source))throw new EvidenceUploadException(409,"evidence-upload-incomplete");
            using(var file=OpenPrivate(source,FileMode.Open,FileAccess.Read,FileShare.Read))
            {
                if(file.Length!=r.Size)throw new EvidenceUploadException(409,"evidence-upload-incomplete");
                if(!Convert.ToHexString(await SHA256.HashDataAsync(file,ct)).Equals(r.Sha256,StringComparison.OrdinalIgnoreCase))throw new EvidenceUploadException(422,"artifact-hash-mismatch");
            }
            var manifest=store.EvidenceManifest(endpoint,id);var metadata=PathFor(endpoint,id,".json");
            if(!File.Exists(metadata)){var temporary=PathFor(endpoint,id,".manifest-"+Guid.NewGuid().ToString("N")+".tmp");using(var file=OpenPrivate(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){file.Write(manifest);file.Flush(true);}FinalizeFile(temporary,metadata);}
            else{using var file=OpenPrivate(metadata,FileMode.Open,FileAccess.Read,FileShare.Read);if(file.Length!=manifest.Length||!Convert.ToHexString(SHA256.HashData(file)).Equals(r.ManifestSha256,StringComparison.OrdinalIgnoreCase))throw new EvidenceUploadException(422,"stored-manifest-hash-mismatch");}
            if(source!=final)FinalizeFile(part,final);
            SyncDirectory(Path.GetDirectoryName(final)!);
            if(r.State=="received")return Progress(r);
            var completion=store.EvidenceSource(endpoint,r.CompletionEventId)??throw new EvidenceUploadException(409,"completion-event-missing");
            return store.CommitEvidence(r,completion);
        }finally{gate.Release();}
    }
    public async Task<EvidenceUploadReceipt> Status(string endpoint,string id,CancellationToken ct=default)
    {if(!EvidenceTransferLimits.Id(id))throw new EvidenceUploadException(400,"invalid-evidence-identifier");await gate.WaitAsync(ct);try{using var owned=LockStore();return Progress(Required(endpoint,id));}finally{gate.Release();}}
    public FileStream Download(string endpoint,string id,bool manifest)
    {
        if(!EvidenceTransferLimits.Id(id))throw new EvidenceUploadException(400,"invalid-evidence-identifier");
        var r=Required(endpoint,id);if(r.State!="received")throw new EvidenceUploadException(409,"evidence-not-finalized");
        var file=OpenPrivate(PathFor(endpoint,id,manifest?".json":".bin"),FileMode.Open,FileAccess.Read,FileShare.Read);
        try
        {
            if((!manifest&&file.Length!=r.Size)||!Convert.ToHexString(SHA256.HashData(file)).Equals(manifest?r.ManifestSha256:r.Sha256,StringComparison.OrdinalIgnoreCase))throw new EvidenceUploadException(422,"stored-evidence-hash-mismatch");
            file.Position=0;return file;
        }catch{file.Dispose();throw;}
    }
    private static void UniqueKeys(JsonElement element)
    {
        if(element.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var property in element.EnumerateObject()){if(!names.Add(property.Name))throw new EvidenceUploadException(400,"duplicate-manifest-key");UniqueKeys(property.Value);}}
        else if(element.ValueKind==JsonValueKind.Array)foreach(var item in element.EnumerateArray())UniqueKeys(item);
    }
}
