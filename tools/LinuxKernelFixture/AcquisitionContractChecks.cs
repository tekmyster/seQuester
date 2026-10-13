using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class AcquisitionContractChecks
{
    // Contract replay uses actual archived native status/bytes, and measures a
    // new private analysis copy on this host. It is not a live sensor capture.
    public static List<AgentEvent> Run(byte[] archive,JsonElement[] records,IReadOnlyList<AgentEvent> observations,string root,string sensor,Action<bool,string> check)
    {
        var artifacts=new Dictionary<string,byte[]>();
        using(var zip=new GZipStream(new MemoryStream(archive),CompressionMode.Decompress))
        using(var tar=new TarReader(zip))
            while(tar.GetNextEntry() is {} entry)if(System.Text.RegularExpressions.Regex.IsMatch(entry.Name,@"^evidence-[0-9]+\.bin$"))
            {
                if(entry.EntryType!=TarEntryType.RegularFile||entry.Length is <=0 or >4194304||artifacts.ContainsKey(entry.Name))throw new InvalidDataException("Invalid archive copy");
                using var data=new MemoryStream();entry.DataStream!.CopyTo(data);artifacts.Add(entry.Name,data.ToArray());
            }
        var copies=Path.Combine(root,"acquisition-contract-replay");Directory.CreateDirectory(copies);
        var collector=new ForensicCollector(sensor,copies);var results=new List<AgentEvent>();
        for(var index=0;index<records.Length;index++)
        {
            var record=records[index];if(!record.TryGetProperty("Artifact",out var name))continue;
            var observation=observations[index];var k=observation.Attribution!.LinuxKernel!;
            var status=LinuxActorLeaseStatus.Decode(LeaseProtocolChecks.Encode(record.GetProperty("FinalStatus"))).ToEvidence();
            check(status.Ready&&status.Matches(k),"canonical native acquisition status agrees with archived observation: "+index);
            var bytes=artifacts[name.GetString()!];var hash=Convert.ToHexString(SHA256.HashData(bytes));
            var id=Guid.NewGuid().ToString("N");var path=Path.Combine(copies,id+".bin");
            using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(bytes);output.Flush(true);}
            FileIdentityEvidence privateFile;using(var input=File.OpenRead(path))privateFile=NativeFileIdentity.Read(input);
            var acquisition=new LinuxActorAcquisitionEvidence{SourceEventId=observation.EventId,NativeObservationSha256=k.NativeObservationSha256,NativeStatus=status,SnapshotId=id,SnapshotSha256=hash,SnapshotFile=privateFile,
                PersistedUtc=DateTimeOffset.UtcNow,SizeMatchesEarlierObservation=status.Size==k.ActorSize,Status=EvidenceStatus.Captured("archived-native-contract-replay; not-live-sensor-capture")};
            var sourceFile=new FileIdentityEvidence{StableId=status.SourceStableId,Size=bytes.Length,Status=EvidenceStatus.Captured("native-device-inode; source-timestamps-unavailable")};
            using var actor=ActorLease.Capture(observation,sensor);
            actor.Image=File.OpenRead(path);actor.SnapshotFile=privateFile;actor.SnapshotPath=path;actor.File=sourceFile;actor.LinuxAcquisition=acquisition;
            actor.Binding=EvidenceStatus.Captured("archived-full-native-tuple-replay");actor.BindingSourceEventId=observation.EventId;actor.BindingCapturedUtc=acquisition.PersistedUtc;
            var begun=collector.Begin(observation,actor);check(begun.ActorExecutable.LinuxAcquisition==acquisition,"common collector retains Linux acquisition companion: "+index);
            var completed=collector.Complete(observation,actor,begun,new());var image=completed.ActorExecutable;
            check(image.Sha256==hash&&completed.Preservation is {Status.State:"captured",HashMatched:true}&&completed.Preservation.Sha256==hash,"common collector hashes and preserves exact archived actor bytes: "+index);
            var manifestPath=Path.Combine(copies,completed.Preservation.ManifestRelativePath!.Replace('/',Path.DirectorySeparatorChar));
            var preservedPath=Path.Combine(copies,completed.Preservation.ArtifactRelativePath!.Replace('/',Path.DirectorySeparatorChar));
            using(var manifest=JsonDocument.Parse(File.ReadAllBytes(manifestPath)))
                check(JsonSerializer.Serialize(manifest.RootElement.GetProperty("LinuxActorAcquisition").Deserialize<LinuxActorAcquisitionEvidence>())==JsonSerializer.Serialize(acquisition)&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(preservedPath)))==hash,"immutable forensic manifest links acquisition and independently verified preserved bytes: "+index);
            check(image.Signature.Status.Reason=="authenticode-not-applicable-to-linux-actor"&&completed.Observation.HashPolicy=="not-hashed-by-forensic-collector","Linux actor evidence does not fabricate Windows verification or hash target content: "+index);
            var f=collector.LinkCompletion(completed,Guid.NewGuid().ToString("N"));
            var completion=observation with{EventId=f.EventId,Source="Forensic enrichment",Operation="Archived actor acquisition contract replay",Forensics=f};
            check(f.IsValid()&&LinuxKernelEvidence.Matches(completion),"versioned acquisition keeps source/private identity and exact hash: "+index);
            check(sourceFile.StableId!=privateFile.StableId&&sourceFile.ChangeMarker==null&&sourceFile.ModifiedUtc==null,"snapshot metadata cannot be attributed to original source: "+index);
            check(!acquisition.WhitelistEligible,"acquired backing bytes cannot authorize whitelist: "+index);
            results.Add(completion);
            if(results.Count!=1)continue;
            bool Valid(LinuxActorAcquisitionEvidence a)=>a.IsValid(f.Process,f.EventId,f.RelatedEventId,hash,sourceFile)&&a.Matches(k);
            check(!Valid(acquisition with{Version=2})&&!Valid(acquisition with{NativeObservationSha256=new string('0',64)})&&!Valid(acquisition with{SourceEventId=Guid.NewGuid().ToString("N")}),"wrong schema, raw digest and source event rejected");
            check(!Valid(acquisition with{WhitelistEligible=true})&&!Valid(acquisition with{SnapshotSha256=new string('0',64)})&&!Valid(acquisition with{SizeMatchesEarlierObservation=!(status.Size==k.ActorSize)}),"false trust, wrong hash and conflicting observed size rejected");
            check(!Valid(acquisition with{NativeStatus=status with{ProviderEpoch="0"}})&&!Valid(acquisition with{NativeStatus=status with{SelfExecId="0"}})&&!Valid(acquisition with{NativeStatus=status with{ProcessStartNs="0"}}),"provider epoch, exec generation and process lifetime mismatch rejected");
            check(!Valid(acquisition with{NativeStatus=status with{TaskStartNs="0"}})&&!Valid(acquisition with{NativeStatus=status with{Cookie="0"}})&&!Valid(acquisition with{NativeStatus=status with{AssociationGeneration="0"}}),"task lifetime, event cookie and association mismatch rejected");
            check(!Valid(acquisition with{NativeStatus=status with{Bytes="0"}})&&!Valid(acquisition with{NativeStatus=status with{State=4,Error=-110}})&&!Valid(acquisition with{NativeStatus=status with{WriteLease=1}}),"incomplete, failed and unreleased native copies rejected");
            check(!Valid(acquisition with{SnapshotFile=privateFile with{Size=privateFile.Size+1}})&&!Valid(acquisition with{PersistedUtc=null})&&!Valid(acquisition with{RecoveryStatus=new("failed","missing")}),"incorrect private copy, absent durable time and failed recovery cannot retain usable hash");
            var failed=acquisition with{Status=new("failed","native-copy-unavailable"),SnapshotId=null,SnapshotSha256=null,SnapshotFile=null,PersistedUtc=null,SizeMatchesEarlierObservation=null};
            check(failed.IsValid(f.Process,f.EventId,f.RelatedEventId,null,sourceFile)&&failed.Matches(k),"unavailable acquisition remains valid evidence without fabricated copy or hash");
            check(!LinuxKernelEvidence.Matches(completion with{Forensics=f with{ActorExecutable=image with{LinuxAcquisition=null}}}),"Linux hash needs its versioned native acquisition evidence");
            check(!LinuxKernelEvidence.Matches(completion with{Attribution=null}),"Linux acquisition cannot survive removal of originating native observation");
            var wide=status with{ProviderEpoch="18446744073709551615",Cookie="18446744073709551615",SelfExecId="18446744073709551615",Inode="18446744073709551615"};
            using var json=JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(wide));
            check(wide.IsValid()&&new[]{"ProviderEpoch","Cookie","SelfExecId","Inode"}.All(key=>json.RootElement.GetProperty(key).ValueKind==JsonValueKind.String&&json.RootElement.GetProperty(key).GetString()=="18446744073709551615"),"full unsigned identities remain exact decimal strings in SIEM JSON");
            check(!(wide with{ProviderEpoch="01"}).IsValid()&&!(wide with{ProviderEpoch=null!}).IsValid()&&!(wide with{Id="18446744073709551615"}).IsValid(),"invalid decimal and out-of-range lease identities rejected safely");
        }
        check(results.Count==38,"all 38 archived actor acquisitions project to valid transport records");return results;
    }
}
