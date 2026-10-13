using System.Diagnostics;
using System.Security.Cryptography;
using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

public sealed class ForensicCollector(string sensor,string directory)
{
    private sealed record Cached(string Hash,SignatureEvidence Signature,ExecutableEvidence Metadata,DateTimeOffset VerifiedUtc);
    private readonly Dictionary<string,Cached> cache=new(StringComparer.Ordinal);
    private readonly Dictionary<string,long> processSequences=new(StringComparer.Ordinal);
    private readonly object gate=new();
    private readonly EvidenceStore store=new(directory);
    private readonly string epoch=Guid.NewGuid().ToString("N");
    private long sequence,hashComputations,metadataComputations,cacheHits;
    public long HashComputations=>Interlocked.Read(ref hashComputations);
    public long CacheHits=>Interlocked.Read(ref cacheHits);
    public long MetadataComputations=>Interlocked.Read(ref metadataComputations);
    public ForensicEvidence Begin(AgentEvent value,ActorLease actor)
    {
        var a=value.Attribution;var activity=EventActivity.From(value);long? perProcess=null;
        var targetUnavailable=a is {Provider:"Linux Audit",CompleteRecordSet:false,PathRole:"UNAVAILABLE"}||a?.WindowsSyscall?.TargetStatus.State=="unavailable";
        lock(gate)
        {
            if(actor.Process.InstanceId is {} id)
            {
                // Do not recycle per-process sequence numbers after eviction: omitted is safer than restarting at one.
                if(processSequences.TryGetValue(id,out var n)){perProcess=n+1;processSequences[id]=n+1;}
                else if(processSequences.Count<4096){perProcess=1;processSequences[id]=1;}
            }
        }
        var evidence=new ForensicEvidence{EventId=value.EventId,SensorId=sensor,CollectorEpoch=epoch,CollectorSequence=Interlocked.Increment(ref sequence),ProcessSequence=perProcess,MonotonicTicks=actor.CapturedMonotonicTicks,MonotonicFrequency=Stopwatch.Frequency,SourceSequence=a?.EvidenceId,ObservedUtc=value.ObservedUtc,CapturedUtc=actor.CapturedUtc,Process=actor.Process,
            ActorExecutable=new(){ObservedPath=value.Process,File=actor.File,Acquisition=actor.Acquisition,LinuxAcquisition=actor.LinuxAcquisition,LinuxNativeWork=actor.LinuxNativeWork,BindingStatus=actor.Binding,BindingSourceEventId=actor.BindingSourceEventId,BindingCapturedUtc=actor.BindingCapturedUtc,Location=a?.LinuxKernel!=null?"unknown; path-namespace-not-captured":ActorLocation(value.Process)},
            Observation=new(){Path=targetUnavailable?null:value.Path,Actions=activity.Actions,Outcome=activity.Outcome,AccessMask=a?.AccessMask,OsStatus=a?.OsStatus,BytesTransferred=a?.BytesTransferred,RenameSource=a?.RenameSource,RenameDestination=a?.RenameDestination,ExtensionBefore=a?.RenameSource is {} before?Path.GetExtension(before):null,ExtensionAfter=a?.RenameDestination is {} after?Path.GetExtension(after):null,Storage=targetUnavailable||a?.LinuxKernel!=null?"unknown":TargetLocation(value.Path),File=new(){StableId=a?.TargetStableId,Status=targetUnavailable?EvidenceStatus.Unavailable("kernel-audit-target-path-unavailable"):a?.TargetStableId!=null?EvidenceStatus.Captured("source-event"):EvidenceStatus.Unavailable("provider-does-not-supply-target-file-identity")}},
            Detection=DetectionFor(value.Trust)};
        if(a?.WindowsSyscall is {} syscall)
        {
            var n=syscall.Native;
            evidence=evidence with{Observation=evidence.Observation with{Length=n.Operation is 1 or 2?n.RequestedLength:null,
                IoStatus=new(n.Outcome=="pending"?"pending":"captured","native-syscall-submission-return; byte-count-offset-and-final-asynchronous-completion-unavailable",n.ReturnStatus)}};
        }
        if(a?.LinuxKernel?.IoObservation is {} io)
        {
            long? Number(string? text)=>long.TryParse(text,System.Globalization.NumberStyles.Integer,System.Globalization.CultureInfo.InvariantCulture,out var n)&&n>=0?n:null;
            var target=evidence.Observation with{BytesTransferred=Number(io.TransferredBytes),Offset=Number(io.OffsetBefore),Length=Number(io.RequestedBytes),PreSize=Number(io.SizeBefore),PostSize=Number(io.SizeAfter),OsStatus=io.ReturnValue,
                IoStatus=new(io.Diagnostic?"unavailable":io.Stage==1||io.Outcome=="pending"?"pending":io.CollectionError==0?"captured":"partial",
                    io.Diagnostic?"LINUX_IO_CAPTURE_DIAGNOSTIC":io.Stage==1?"LINUX_IO_RETURN_NOT_OBSERVED":io.Outcome=="pending"?"LINUX_IO_ASYNC_COMPLETION_PENDING":"LINUX_SYNCHRONOUS_VFS_RETURN",io.CollectionError==0?null:io.CollectionError.ToString(System.Globalization.CultureInfo.InvariantCulture))};
            evidence=evidence with{Observation=target};
        }
        return evidence;
    }
    internal static ForensicDetection DetectionFor(EventTrust? trust)=>new(
        trust?.Result is {Mode:"enforce",Decision.Disposition:"log-only",Decision.SuppressPopup:true,Decision.SuppressResponse:true}?"log-only":"alert",
        trust?.Result.Decision.Severity??"alert",["SQ-MONITORED-FILE-001"],["MONITORED_FILE_ACTIVITY"]);
    public ForensicEvidence LinkCompletion(ForensicEvidence completed,string eventId)=>completed with{EventId=eventId,RelatedEventId=completed.EventId,CollectorEpoch=epoch,CollectorSequence=Interlocked.Increment(ref sequence),MonotonicTicks=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency,ProcessSequence=null,Response=new("actor-evidence-collection",completed.Collection.State,completed.EventId)};
    public ForensicEvidence LinkResponse(ForensicEvidence source,string eventId,DateTimeOffset time)=>source with{EventId=eventId,RelatedEventId=source.EventId,ObservedUtc=time,CapturedUtc=time,CollectorEpoch=epoch,CollectorSequence=Interlocked.Increment(ref sequence),MonotonicTicks=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency,ProcessSequence=null,Response=source.Response with{RelatedEventId=source.EventId}};
    public ForensicEvidence Complete(AgentEvent value,ActorLease actor,ForensicEvidence pending,ForensicPolicy policy)
    {
        if(!policy.IsValid())throw new ArgumentException("Invalid forensic policy.");
        actor.CompleteMetadata(value,sensor);
        var result=pending with{Process=actor.Process};var image=result.ActorExecutable;
        if(value.Attribution?.LinuxKernel!=null)image=image with{LinuxAcquisition=actor.LinuxAcquisition,LinuxNativeWork=actor.LinuxNativeWork,BindingStatus=actor.Binding,BindingSourceEventId=actor.BindingSourceEventId,BindingCapturedUtc=actor.BindingCapturedUtc};
        try
        {
            if(actor.Image==null)image=image with{HashStatus=EvidenceStatus.Unavailable(actor.Binding.Reason)};
            else if(actor.DescriptorFile.Size is null or <0)image=image with{HashStatus=EvidenceStatus.Unavailable("actor-size-unavailable")};
            else
            {
                if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(actor.Image)))throw new IOException("Actor image changed before hashing.");
                var key=NativeFileIdentity.CacheKey(actor.DescriptorFile);Cached? entry;
                lock(gate)cache.TryGetValue(key,out entry);
                if(entry!=null&&DateTimeOffset.UtcNow-entry.VerifiedUtc<TimeSpan.FromMinutes(5))Interlocked.Increment(ref cacheHits);
                else
                {
                    // Hashing is independent of the preservation copy limit. Read only the captured size,
                    // so concurrent file growth cannot turn enrichment into an unbounded stream.
                    var hash=HashImage(actor.Image,actor.DescriptorFile.Size.Value);Interlocked.Increment(ref hashComputations);
                    var linux=value.Attribution?.LinuxKernel!=null;
                    var signature=linux?new SignatureEvidence{Status=EvidenceStatus.Unavailable("authenticode-not-applicable-to-linux-actor")}:WindowsSignature.Verify(actor.Image,actor.InspectionPath??value.Process!);
                    var metadata=linux?image with{MetadataStatus=EvidenceStatus.Unavailable("PE-version-metadata-not-applicable-to-linux-actor")}:VersionMetadata(image,actor);Interlocked.Increment(ref metadataComputations);
                    entry=new(hash,signature,metadata,DateTimeOffset.UtcNow);
                    if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(actor.Image)))throw new IOException("Actor image changed while hashing/verifying.");
                    lock(gate){while(cache.Count>=policy.CacheEntries)cache.Remove(cache.Keys.First());cache[key]=entry;}
                }
                if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(actor.Image)))throw new IOException("Actor image changed after cached lookup.");
                if(actor.Acquisition?.SnapshotSha256 is {} captured&&!captured.Equals(entry.Hash,StringComparison.OrdinalIgnoreCase))throw new IOException("Staged actor hash differs from its acquisition manifest.");
                if(actor.LinuxAcquisition?.SnapshotSha256 is {} linuxCaptured&&!linuxCaptured.Equals(entry.Hash,StringComparison.OrdinalIgnoreCase))throw new IOException("Linux actor hash differs from its acquisition manifest.");
                image=image with{Sha256=entry.Hash,Signature=entry.Signature,HashStatus=EvidenceStatus.Captured("sha256-opened-actor-image-stable-identity-cache")};
                var m=entry.Metadata;
                image=image with{CompanyName=m.CompanyName,FileDescription=m.FileDescription,ProductName=m.ProductName,ProductVersion=m.ProductVersion,FileVersion=m.FileVersion,OriginalFilename=m.OriginalFilename,InternalName=m.InternalName,MetadataStatus=m.MetadataStatus};
            }
            var preserve=policy.PreserveActorOnAlert&&pending.Detection.Disposition!="log-only"&&Rank(pending.Detection.Severity)>=Rank(policy.PreservationThreshold);
            result=result with{ActorExecutable=image,Preservation=preserve?store.Preserve(actor,value,image.Sha256,policy):new(),Collection=image.Sha256!=null?EvidenceStatus.Captured("actor-enrichment-complete; inspect-individual-field-status"):new("partial","actor-hash-unavailable")};
            if(result.Preservation.Status.State is "failed" or "unavailable")result=result with{Collection=new("partial","actor-preservation-failed")};
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or ArgumentException)
        {result=result with{ActorExecutable=image with{HashStatus=new("unavailable","actor-enrichment-failed",ex.GetType().Name)},Preservation=new(){SourceEventId=value.EventId,ProcessInstanceId=actor.Process.InstanceId,OriginalPath=value.Process,Status=new("failed","actor-enrichment-prevented-preservation")},Collection=new("partial","actor-enrichment-failed",ex.GetType().Name)};}
        var reasons=result.Detection.ReasonCodes.ToList();
        if(value.Attribution is {Provider:"Linux Audit",CompleteRecordSet:false,PathRole:"UNAVAILABLE"})reasons.Add("KERNEL_AUDIT_TARGET_PATH_UNAVAILABLE");
        if(result.Process.Creation is {Status.State:not "captured"})reasons.Add("PROCESS_CREATION_METADATA_UNAVAILABLE");
        if(result.ActorExecutable.Sha256==null)reasons.Add("ACTOR_HASH_UNAVAILABLE");
        if(result.ActorExecutable.LinuxNativeWork?.State=="PIN_INTERRUPTED_UNKNOWN")
        {reasons.Add("LINUX_NATIVE_WORK_OUTCOME_UNKNOWN");result=result with{Collection=new("partial","linux-native-work-outcome-unknown; inspect-private-artifact-status")};}
        if(result.Preservation.Status.State is "failed" or "unavailable")reasons.Add("ACTOR_PRESERVATION_FAILED");
        return result with{EnrichedUtc=DateTimeOffset.UtcNow,Detection=result.Detection with{ReasonCodes=reasons.Distinct().Take(32).ToArray()}};
    }
    private static string HashImage(FileStream image,long size)
    {
        image.Position=0;using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer=new byte[65536];var remaining=size;
        while(remaining>0){var count=image.Read(buffer,0,(int)Math.Min(remaining,buffer.Length));if(count==0)throw new IOException("Actor image shortened while hashing.");hash.AppendData(buffer,0,count);remaining-=count;}
        if(image.ReadByte()!=-1)throw new IOException("Actor image grew while hashing.");
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    private static int Rank(string severity)=>severity switch{"critical"=>3,"high"=>2,"alert" or "normal" or "warning"=>1,_=>0};
    public static string TargetLocation(string? path)
    {
        if(string.IsNullOrWhiteSpace(path))return "unknown";
        if(path.StartsWith(@"\\",StringComparison.Ordinal)||path.StartsWith("//",StringComparison.Ordinal))return "network-share";
        if(OperatingSystem.IsWindows())try{return new DriveInfo(Path.GetPathRoot(path)!).DriveType switch{DriveType.Fixed=>"local-fixed",DriveType.Removable=>"removable",DriveType.Network=>"network-share",_=>"other"};}catch(ArgumentException){return "unknown";}catch(IOException){return "unknown";}
        // A POSIX path alone cannot distinguish bind mounts, NFS, FUSE, or removable media.
        if(OperatingSystem.IsLinux()&&path.StartsWith('/'))try
        {
            var mount=File.ReadLines("/proc/self/mountinfo").Select(line=>line.Split(" - ")).Where(parts=>parts.Length==2).Select(parts=>(Fields:parts[0].Split(' '),Type:parts[1].Split(' ')[0])).Where(m=>m.Fields.Length>4).Select(m=>(Path:m.Fields[4].Replace("\\040"," ").Replace("\\011","\t").Replace("\\134","\\"),m.Type)).Where(m=>m.Path=="/"||path==m.Path||path.StartsWith(m.Path.TrimEnd('/')+"/",StringComparison.Ordinal)).OrderByDescending(m=>m.Path.Length).FirstOrDefault();
            return mount.Type is "nfs" or "nfs4" or "cifs" or "smb3" or "9p" or "fuse.sshfs"?"network-share":"other/unknown-local-mount";
        }catch(IOException){}
        return "unknown";
    }
    private static string ActorLocation(string? path)
    {
        if(path==null)return "unknown";
        if(!OperatingSystem.IsWindows())return "posix-location-permissions-not-a-verdict";
        var windows=Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        if(path.StartsWith(windows+@"\System32\",StringComparison.OrdinalIgnoreCase)||path.StartsWith(windows+@"\SysWOW64\",StringComparison.OrdinalIgnoreCase))return "expected-windows-system-directory-not-a-verdict";
        return "outside-windows-system-directories; writability-not-established";
    }
    private static ExecutableEvidence VersionMetadata(ExecutableEvidence image,ActorLease actor)
    {
        if(!OperatingSystem.IsWindows())return image with{MetadataStatus=EvidenceStatus.Unavailable("PE-version-metadata-not-applicable")};
        try
        {
            // FileVersionInfo has a path interface. Bind that path to the retained image before AND after reading.
            var path=actor.InspectionPath??image.ObservedPath!;
            using var check=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
            if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(check)))throw new IOException("Version metadata path replaced.");
            var version=FileVersionInfo.GetVersionInfo(path);
            using var after=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete);
            if(!NativeFileIdentity.Same(actor.DescriptorFile,NativeFileIdentity.Read(after)))throw new IOException("Version metadata path changed.");
            static string? Bounded(string? s)=>s?.Length>256?s[..256]:s;
            return image with{CompanyName=Bounded(version.CompanyName),FileDescription=Bounded(version.FileDescription),ProductName=Bounded(version.ProductName),ProductVersion=Bounded(version.ProductVersion),FileVersion=Bounded(version.FileVersion),OriginalFilename=Bounded(version.OriginalFilename),InternalName=Bounded(version.InternalName),MetadataStatus=EvidenceStatus.Captured("path-checked-before-and-after-version-query; not-a-verdict")};
        }
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or ArgumentException){return image with{MetadataStatus=new("unavailable","PE-version-metadata-unavailable",ex.GetType().Name)};}
    }
}
