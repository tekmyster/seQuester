using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class LinuxActorMatchChecks
{
    internal static void Run(string eventsPath,string root)
    {
        var bytes=File.ReadAllBytes(eventsPath);
        const string accepted="7FA2B9563EA76D0A1924ABE7C2A978E9FE8F650D3EBAF7BFA64073B464FA8460";
        if(Convert.ToHexString(SHA256.HashData(bytes))!=accepted||Directory.Exists(root))throw new ArgumentException("Exact accepted R32 events and fresh output required");
        Directory.CreateDirectory(root);var checks=new List<string>();
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);Console.WriteLine("PASS: "+name);}
        var document=JsonNode.Parse(bytes)!;
        var originals=document["Originals"]!.Deserialize<AgentEvent[]>()!;
        var completions=document["Completions"]!.Deserialize<AgentEvent[]>()!;
        Check(originals.Length==5&&completions.Length==5,"five accepted native original/completion pairs");
        foreach(var e in originals)
        {
            var (facts,reason)=LinuxKernelActorMatchEvidence.Inspect(e);var k=e.Attribution!.LinuxKernel!;var a=e.Forensics!.ActorExecutable.LinuxAcquisition!;
            Check(facts!=null&&reason=="LINUX_MATCH_FACTS_CAPTURED","native matching facts: "+e.EventId);
            Check(facts!.Executable==k.ActorPath.Text&&facts.Executable!=e.Process&&facts.ExecutablePathSha256==Convert.ToHexString(SHA256.HashData(Convert.FromBase64String(k.ActorPath.BytesBase64!))),"exact path bytes, not JSON display: "+e.EventId);
            Check(facts.Sha256==a.SnapshotSha256&&facts.SnapshotStableId==a.SnapshotFile!.StableId&&facts.ProcessId==e.ProcessId&&facts.FileSystemUid==k.FileSystemUid&&facts.ProcessStartNs==k.ProcessStartNs,"snapshot hash, credentials and process lifetime: "+e.EventId);
            Check(facts.ActorDevice==k.ActorDevice&&facts.ActorInode==k.ActorInode&&facts.Size.ToString(System.Globalization.CultureInfo.InvariantCulture)==k.ActorSize&&
                facts.ExecutablePathBytesBase64==k.ActorPath.BytesBase64&&facts.ExecutablePathByteLength==Convert.FromBase64String(facts.ExecutablePathBytesBase64).Length&&
                facts.CredentialNamespace==k.CredentialNamespace&&facts.CredentialIdEncoding==k.CredentialEncoding&&facts.OperationObservation=="OPEN_REQUEST"&&facts.OperationOutcome=="NOT_OBSERVED",
                "explicit source identity, path bytes, credential and operation semantics: "+e.EventId);
            Check(e.Trust==null&&!k.WhitelistEligible&&!a.WhitelistEligible&&e.Forensics.Process.StartedUtc==null,"inspection does not grant trust or invent wall-clock start: "+e.EventId);
            Check(JsonSerializer.Deserialize<LinuxKernelActorMatchEvidence>(JsonSerializer.Serialize(facts))==facts,"matching facts round trip: "+e.EventId);
            using var unavailable=ActorLease.Unavailable(e,"descriptor-not-held");
            Check(unavailable.AcquiredLinuxMatchEvidence(e).Evidence==null,"historical event without held private descriptor cannot acquire live match: "+e.EventId);
        }
        foreach(var e in completions)Check(LinuxKernelActorMatchEvidence.Inspect(e).Evidence==null,"completion cannot mint a new original decision: "+e.EventId);
        Check(LinuxKernelActorMatchEvidence.Inspect(null).Evidence==null,"missing event remains unavailable");
        var baseline=originals[0];
        const string kernel="Attribution.LinuxKernel.",actor="Forensics.ActorExecutable.",acquisition=actor+"LinuxAcquisition.",work=actor+"LinuxNativeWork.";
        AgentEvent Change(string field,JsonNode? value)
        {
            var n=JsonSerializer.SerializeToNode(baseline)!;var parts=field.Split('.');var cursor=n;
            foreach(var part in parts[..^1])cursor=cursor[part]!;
            cursor[parts[^1]]=value;return n.Deserialize<AgentEvent>()!;
        }
        void Reject(string field,JsonNode? value,string name)=>Check(LinuxKernelActorMatchEvidence.Inspect(Change(field,value)).Evidence==null,name);
        Reject("ProcessId",baseline.ProcessId+1,"PID substitution");
        Reject("Forensics.Process.StartKey","another-process","reused PID with different process lifetime");
        Reject(kernel+"TaskStartNs","1","accessing thread lifetime mismatch");
        Reject(kernel+"SelfExecId","999","same PID after another exec");
        Reject(kernel+"ProviderEpoch","1","different provider boot epoch");
        Reject(kernel+"Cookie","1","different operation cookie");
        Reject(kernel+"Lease",999,"different native lease");
        Reject(kernel+"AssociationAfter","999","exec association changes during capture");
        Reject(kernel+"AssociationErrorBefore",-1,"tainted prior association");
        Reject(kernel+"AssociationErrorAfter",-1,"tainted final association");
        Reject(kernel+"ActorInode","1","executable replaced at the same path");
        Reject(kernel+"ActorDevice",1,"source device mismatch");
        Reject(kernel+"ActorSize","1","source observed size mismatch");
        Reject(acquisition+"NativeStatus.Device","1","lease source device mismatch");
        Reject(acquisition+"NativeStatus.Inode","1","lease source inode mismatch");
        Reject(acquisition+"NativeStatus.Size","1","lease source size mismatch");
        Reject(actor+"File.StableId","linux-kernel-device:1:inode:1","acquisition source identity mismatch");
        Reject(actor+"File.Size",1,"acquisition source size mismatch");
        Reject(kernel+"NativeObservationSha256",new string('A',64),"raw observation digest substitution");
        Reject(kernel+"PriorResult",-13,"preceding LSM denial not authorized as ordinary open");
        Reject(kernel+"CredentialError",-1,"credential collection failure");
        Reject(kernel+"FileSystemUid",null,"missing filesystem UID");
        Reject(kernel+"CredentialNamespace","OTHER","unqualified credential namespace");
        Reject(actor+"BindingStatus.State","unavailable","missing actor binding");
        Reject(actor+"ObservedPath","/tmp/same-name","actor display path contradicts operation evidence");
        Reject(actor+"BindingCapturedUtc","2026-10-01T00:00:00Z","binding time contradicts private receipt");
        Reject(actor+"Sha256",new string('B',64),"actor hash disagrees with retained snapshot");
        Reject(acquisition+"SnapshotSha256",null,"unknown snapshot hash");
        Reject(acquisition+"SnapshotFile.ChangeMarker",null,"private copy identity missing change marker");
        Reject(acquisition+"SnapshotFile.Size",1,"private copy length mismatch");
        Reject(acquisition+"SourceEventId",Guid.NewGuid().ToString("N"),"copy from another event");
        Reject(acquisition+"SizeMatchesEarlierObservation",false,"source size changed between observation and copy");
        Reject(acquisition+"RecoveryStatus",JsonSerializer.SerializeToNode(new EvidenceStatus("failed","copy-changed")),"recovery detected changed or missing copy");
        Reject(acquisition+"NativeStatus.Bytes","0","short native copy");
        Reject(acquisition+"NativeStatus.WriteLease",1,"native copy has not returned its write exclusion");
        Reject(acquisition+"NativeStatus.State",5,"native preservation failure");
        Reject(work+"CollectorSequence",999,"native work from another observation");
        Reject(work+"AuthorizationGeneration",99,"native work authorized under another source generation");
        Reject(work+"ReturnOutcome","unresolved","unresolved native method outcome");
        Reject(work+"Method.DropReceiptCommitObserved",false,"native release receipt missing");
        Reject(work+"Method.ErrorKind","IOException","native method error");
        Reject(work+"Method.LatestStatus.Size","1","latest status contradicts preserved size");
        Reject(work+"Method.LatestStatus.Device","1","native work source device mismatch");
        Reject(work+"Method.LatestStatus.Inode","1","native work source inode mismatch");
        Reject(work+"Method",null,"method observations unavailable");
        Reject("Source","Linux Audit","audit metadata cannot substitute for the native operation");

        LinuxKernelPathEvidence PathBytes(byte[] b,string state="captured")=>new(){State=state,NativeResult=b.Length+1,BytesBase64=Convert.ToBase64String(b)};
        foreach(var path in new[]{"/tmp/actor (deleted)","/tmp/../actor","/tmp/./actor","relative","/tmp/a\nb","/tmp/a\\b","/tmp/a*b","/tmp/a?b","/tmp/a\"b","/"})
            Check(LinuxKernelActorMatchEvidence.MatchingPath(PathBytes(Encoding.UTF8.GetBytes(path)))==null,"unsupported or ambiguous matching path: "+JsonSerializer.Serialize(path));
        Check(LinuxKernelActorMatchEvidence.MatchingPath(PathBytes([47,255],"invalid_utf8"))==null,"invalid UTF-8 path never decoded with replacement");
        Check(LinuxKernelActorMatchEvidence.MatchingPath(PathBytes(Encoding.UTF8.GetBytes("/tmp/"+new string('x',1020))))==null,"overlong path cannot become truncated matching identity");
        foreach(var path in new[]{"/tmp/Notepad.exe","/tmp/notepad.exe","/tmp/é","/tmp/e\u0301","/tmp/actor (deleted) suffix"})
            Check(LinuxKernelActorMatchEvidence.MatchingPath(PathBytes(Encoding.UTF8.GetBytes(path)))==path,"ordinal path retained without normalization: "+path);
        var fsuidCase=originals.Single(e=>e.Attribution!.LinuxKernel!.FileSystemUid==65534);
        Check(LinuxKernelActorMatchEvidence.Inspect(fsuidCase).Evidence!.FileSystemUid==65534,"native unprivileged filesystem UID retained");
        var alternateFsuid=baseline with{User="uid:321 (initial user namespace)",Attribution=baseline.Attribution! with{FileSystemUserId=321,LinuxKernel=baseline.Attribution!.LinuxKernel! with{FileSystemUid=321}},
            Forensics=baseline.Forensics! with{Process=baseline.Forensics!.Process with{EventSubject=baseline.Forensics.Process.EventSubject with{FileSystemUid=321},EffectiveThreadContext=baseline.Forensics.Process.EffectiveThreadContext! with{FileSystemUid=321}}}};
        Check(LinuxKernelActorMatchEvidence.Inspect(alternateFsuid).Evidence?.FileSystemUid==321&&alternateFsuid.Attribution.UserId==0&&alternateFsuid.Attribution.EffectiveUserId==0,
            "synthetic distinct filesystem UID is never replaced by real/effective UID");
        var baselineEncoding=JsonSerializer.SerializeToUtf8Bytes(baseline);
        var reference=LinuxKernelActorMatchEvidence.Inspect(baseline).Evidence;
        for(var i=0;i<1000;i++)if(LinuxKernelActorMatchEvidence.Inspect(baseline).Evidence!=reference)throw new Exception("Repeated immutable evidence changed");
        Check(baselineEncoding.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(baseline)),"1000 repeated inspections preserve original evidence bytes and disposition");
        var result=new{Passed=true,Checks=checks.Count,InputSha256=accepted,NativeOriginals=originals.Length,NativeCompletions=completions.Length,
            Scope="Matching-fact consistency and synthetic negative mutations of accepted native records. No new live-source authority, policy suppression, native operation or production deployment."};
        File.WriteAllText(System.IO.Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
