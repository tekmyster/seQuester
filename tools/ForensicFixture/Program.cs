using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(args.Contains("--hold")){Console.WriteLine("ready");Console.ReadLine();return;}
if(args.Contains("--receiver-starvation")){WindowsReceiverChecks.Child();return;}
var root=Path.Combine(Environment.GetEnvironmentVariable("RF_FORENSIC_QA_ROOT")??(OperatingSystem.IsWindows()?@"D:\Codex\RansomFree\forensics-20260925\native":"/var/tmp/sequester-forensic-qa"),Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var count=0;void Check(bool condition,string name){if(!condition)throw new Exception("FAIL "+name);Console.WriteLine("PASS "+name);count++;}
var sensor=Guid.NewGuid().ToString("N");var collector=new ForensicCollector(sensor,root);
var actor=Environment.ProcessPath!;
if(OperatingSystem.IsWindows()){WindowsReceiverChecks.Run(Check);WindowsRetentionChecks.Run(root,sensor,actor,Check);}
AgentEvent Event(string? path=null,int? pid=null)=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)",Path.Combine(root,"target.txt"),Environment.UserName,path??actor,pid??Environment.ProcessId,OperatingSystem.IsWindows()?"Windows audit 4663":"Linux Audit")
{Attribution=new(){Provider=OperatingSystem.IsWindows()?"Windows Security Audit":"Linux Audit",Level="Full attribution",Basis="controlled native fixture event",UserSid=OperatingSystem.IsWindows()?"S-1-5-18":null,LogonId="0x3e7",Syscall=OperatingSystem.IsWindows()?null:"c000003e:read",Outcome="Success",EventTimeCredentials=true,UserId=OperatingSystem.IsLinux()?123u:null,EffectiveUserId=OperatingSystem.IsLinux()?456u:null}};
File.WriteAllText(Path.Combine(root,"target.txt"),"target data must not be copied or hashed by the actor collector");
var e=Event();using var lease=ActorLease.Capture(e,sensor);
Check(lease.Image!=null,"native actor handle retained: "+JsonSerializer.Serialize(lease.Binding));
Check(lease.Process.InstanceId!=null&&lease.Process.StartKey!=null,"durable process instance identity");
Check(lease.Process.CommandLine is {Length:>0}&&lease.Process.CommandLineStatus.State=="captured","native command line captured with provenance");
Check(lease.File.StableId!=null&&lease.File.ChangeMarker!=null,"native stable image identity and invalidation marker");
Check(lease.File.AccessedUtc!=null&&lease.File.ChangedUtc!=null,"native file access and metadata-change timestamps retained");
Check(lease.Process.ProcessSessionId!=null&&lease.Process.SessionStatus.State=="captured","native process session ID has an explicit collection basis");
Check(lease.Process.ParentStatus.Reason!="parent-not-collected"&&(lease.Process.ParentStartedUtc==null||lease.Process.ParentStartedUtc<=lease.Process.StartedUtc),"parent identity is collected or explicitly unavailable and never newer than child");
var pending=collector.Begin(e,lease);var complete=collector.Complete(e,lease,pending,new());
File.WriteAllText(Path.Combine(root,"native-evidence.json"),JsonSerializer.Serialize(complete,new JsonSerializerOptions{WriteIndented=true}));
Check(complete.IsValid(),"versioned bounded forensic envelope");
var legacy=System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(complete))!;
foreach(var field in new[]{"ParentExecutablePath","ParentStatus","ProcessSessionId","SessionStatus"})legacy["Process"]!.AsObject().Remove(field);
foreach(var field in new[]{"AccessedUtc","ChangedUtc"})legacy["ActorExecutable"]!["File"]!.AsObject().Remove(field);
Check(legacy.Deserialize<ForensicEvidence>()!.IsValid(),"historical schema-one evidence without additive metadata remains readable");
Check(!(complete with{Process=complete.Process with{Owner=null!}}).IsValid(),"malformed null security context rejected safely");
Check(!(complete with{Process=complete.Process with{ParentStatus=null!}}).IsValid(),"malformed parent collection status rejected safely");
Check(!(complete with{ActorExecutable=complete.ActorExecutable with{Sha256="unknown"}}).IsValid(),"unknown hash cannot masquerade as a valid digest");
Check(complete.ActorExecutable.Sha256 is {Length:64},"actor SHA256 captured");
Check(complete.Preservation.Status.State=="captured"&&complete.Preservation.HashMatched==true,"actor executable preserved and hash verified");
Check(complete.Preservation.OriginalPath==actor&&complete.Observation.HashPolicy=="not-hashed-by-forensic-collector","preserves actor rather than target");
var preserved=Path.Combine(root,complete.Preservation.ArtifactRelativePath!);
Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(preserved)))==complete.ActorExecutable.Sha256,"independent preserved copy SHA256 verification");
Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(root,complete.Preservation.ManifestRelativePath!))))==complete.Preservation.ManifestSha256,"metadata chain hash and event linkage");
Check(complete.Process.ThreadToken.Sid==null&&complete.Process.Impersonating==null,"unavailable actor thread token is not manufactured");
if(OperatingSystem.IsWindows())Check(complete.Process.EventSubject.Sid=="S-1-5-18"&&complete.Process.Owner.Sid!=null,"synthetic audited subject remains separate from native process owner");
else Check(complete.Process.EventSubject.EffectiveUid==456&&complete.Process.Owner.EffectiveUid!=null,"synthetic event credentials remain separate from native procfs owner");
for(var i=0;i<100;i++)collector.Complete(e,lease,collector.Begin(e,lease),new(PreserveActorOnAlert:false));
Check(collector.HashComputations==1&&collector.CacheHits==100,"100 repeated events reuse stable hash/signature cache");
Check(collector.MetadataComputations==1,"100 repeated events reuse immutable executable metadata without reopening its path");
Check(collector.Begin(e,lease).ProcessSequence==102,"per-process order preserved");
Check(ActorLease.Correlate(sensor,10,"one")!=ActorLease.Correlate(sensor,10,"two"),"PID reuse changes process correlation ID");
using(var stale=ActorLease.Capture(e with{ObservedUtc=DateTimeOffset.UtcNow.AddYears(-5)},sensor))
{
    Check(stale.Image==null,"native PID newer than event rejected");
    if(OperatingSystem.IsLinux())Check(stale.Binding.Reason==LinuxProcessBindingException.StartAmbiguous&&stale.Process.StartKey==null&&stale.Process.InstanceId==null,"actual Linux unsafe birth ordering keeps explicit reason and no fabricated instance");
}
if(OperatingSystem.IsLinux())
{
    using var mismatch=ActorLease.Capture(Event(Path.Combine(root,"same-pid-wrong-image")),sensor);
    Check(mismatch.Image==null&&mismatch.Binding.Reason==LinuxProcessBindingException.ImageMismatch,"actual living Linux PID cannot bind an image different from the historical event");
    Check(mismatch.Process.StartKey==null&&mismatch.Process.InstanceId==null&&mismatch.Process.Status.Reason==LinuxProcessBindingException.ImageMismatch,"image mismatch clears provisional process identity and preserves the reason");
}
using(var missing=ActorLease.Capture(Event(Path.Combine(root,"missing"),int.MaxValue),sensor))
{var result=collector.Complete(e,missing,collector.Begin(e,missing),new());Check(result.ActorExecutable.Sha256==null&&result.Preservation.Status.State=="unavailable","exited/unavailable actor records failure without invented hash");}
using(var missing=ActorLease.Capture(Event(Path.Combine(root,"missing"),int.MaxValue),sensor))
{var result=collector.Complete(e,missing,collector.Begin(e,missing),new());Check(result.Detection.ReasonCodes.Contains("ACTOR_HASH_UNAVAILABLE")&&result.Detection.ReasonCodes.Contains("ACTOR_PRESERVATION_FAILED"),"unavailable hash and preservation have stable SIEM reason codes");}
var wrong=new EvidenceStore(root).Preserve(lease,e,new string('0',64),new());Check(wrong.Status.State=="failed"&&wrong.HashMatched==false,"mismatched preserved copy never accepted");
var blocked=Path.Combine(root,"blocked");File.WriteAllText(blocked,"existing user data");var failed=new EvidenceStore(blocked).Preserve(lease,e,complete.ActorExecutable.Sha256,new());Check(failed.Status.State=="failed"&&File.ReadAllText(blocked)=="existing user data","preservation failure visible and existing data retained");
var rename=Event() with{Attribution=e.Attribution! with{RenameSource="/data/old.doc",RenameDestination="/data/new.enc"}};var renameEvidence=collector.Begin(rename,lease).Observation;
Check(renameEvidence.RenameSource=="/data/old.doc"&&renameEvidence.RenameDestination=="/data/new.enc"&&renameEvidence.ExtensionAfter==".enc","rename source destination and extensions retained");
Check(ForensicCollector.TargetLocation(@"\\server\share\target")=="network-share","UNC network target classified without opening network");
Check(ForensicCollector.TargetLocation(Path.Combine(root,"target.txt"))!="network-share","local target distinguished from network");
var replace=Path.Combine(root,"replacement.bin");File.WriteAllText(replace,"first");FileIdentityEvidence first;
using(var f=File.OpenRead(replace))first=NativeFileIdentity.Read(f);
File.Move(replace,replace+".old");File.WriteAllText(replace,"other");
using(var f=File.OpenRead(replace))Check(!NativeFileIdentity.Same(first,NativeFileIdentity.Read(f)),"replacement at same path invalidates cache identity");
using(var f=new FileStream(replace,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
{var before=NativeFileIdentity.Read(f);File.AppendAllText(replace,"mutation");Check(!NativeFileIdentity.Same(before,NativeFileIdentity.Read(f)),"in-place image modification invalidates cache identity");}
if(OperatingSystem.IsWindows())
{
    using(var identity=System.Security.Principal.WindowsIdentity.GetCurrent())
    System.Security.Principal.WindowsIdentity.RunImpersonated(identity.AccessToken,()=>
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        using var effective=System.Security.Principal.WindowsIdentity.GetCurrent(true);
        using var capture=ActorLease.Capture(Event(),sensor);
        Check(effective!=null&&capture.Process.Owner.Sid==identity.User!.Value&&capture.Process.Impersonating==null,"native impersonating thread does not become fabricated actor-thread evidence when provider lacks actor TID");
    });
    var system=Environment.GetFolderPath(Environment.SpecialFolder.System);
    using(var f=File.OpenRead(actor)){var signature=WindowsSignature.Verify(f,actor);Check(signature.Present==false&&signature.Valid==false,"native unsigned apphost verification");}
    var signed=Path.Combine(system,"cmd.exe");SignatureEvidence verified;
    using(var f=File.OpenRead(signed))verified=WindowsSignature.Verify(f,signed);
    File.WriteAllText(Path.Combine(root,"signed-evidence.json"),JsonSerializer.Serialize(verified));
    Check(verified.Present==true&&verified.Signer!=null,"native signed Windows image signer collected: "+verified.TrustStatus);
    Check(verified.Valid==true,"native signed Windows image validates under cache-only trust policy");
    var broken=Path.Combine(root,"broken.bin");File.Copy(signed,broken);using(var f=new FileStream(broken,FileMode.Open,FileAccess.ReadWrite)){f.Position=4096;var b=f.ReadByte();f.Position=4096;f.WriteByte((byte)(b^1));}
    using(var f=File.OpenRead(broken)){var signature=WindowsSignature.Verify(f,broken);Check(signature.Valid==false&&signature.TrustStatus!=null,"native tampered image fails trust verification");}
    foreach(var file in new[]{"notepad.exe","WindowsPowerShell/v1.0/powershell.exe","drivers/tcpip.sys","kernel32.dll"})
    {
        var path=Path.Combine(system,file);if(!File.Exists(path))continue;
        using var f=File.OpenRead(path);var signature=WindowsSignature.Verify(f,path);
        if(signature.Kind=="catalog"){Check(signature.Present==true&&signature.CatalogPath!=null,"native catalog membership and signature evidence: "+file);File.WriteAllText(Path.Combine(root,"catalog-evidence.json"),JsonSerializer.Serialize(signature));break;}
    }
    if(!File.Exists(Path.Combine(root,"catalog-evidence.json")))Console.WriteLine("PENDING native catalog-only fixture not found among installed candidates");
}
// A retained actor handle still works after the process exits. Only the controlled child is signalled.
var childInfo=new ProcessStartInfo(actor){RedirectStandardInput=true,RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true};childInfo.ArgumentList.Add("--hold");
if(Path.GetFileNameWithoutExtension(actor).Equals("dotnet",StringComparison.OrdinalIgnoreCase))childInfo.ArgumentList.Insert(0,System.Reflection.Assembly.GetExecutingAssembly().Location);
using(var child=Process.Start(childInfo)!)
{
    Check(child.StandardOutput.ReadLine()=="ready","short-lived controlled child started");
    var childEvent=Event(actor,child.Id);using var captured=ActorLease.Capture(childEvent,sensor,deferWindowsMetadata:true);Check(captured.Image!=null,"short-lived child descriptor captured before exit");
    if(OperatingSystem.IsWindows())Check(captured.Process.CommandLine==null&&captured.Process.CommandLineStatus.Reason=="optional-metadata-deferred","early image capture precedes optional command-line lookup");
    var childPending=collector.Begin(childEvent,captured);
    child.StandardInput.WriteLine();child.WaitForExit();var result=collector.Complete(childEvent,captured,childPending,new());Check(result.Preservation.HashMatched==true,"actor preservation survives process exit using retained descriptor");
    Check(result.Process.InstanceId==childPending.Process.InstanceId&&result.Process.Pid==child.Id,"delayed enrichment retains the captured child instance after exit");
    if(OperatingSystem.IsWindows())Check(result.Process.CommandLineStatus.Reason!="optional-metadata-deferred"&&captured.MetadataHandle==null,"post-exit optional metadata is explicit and retained process handle is released");
}
if(OperatingSystem.IsWindows())
{
    using var deferred=ActorLease.Capture(Event(),sensor,true);
    var deferredEvent=Event();var deferredPending=collector.Begin(deferredEvent,deferred);
    var delayed=collector.Complete(deferredEvent,deferred,deferredPending,new(PreserveActorOnAlert:false));
    Check(delayed.Process.CommandLine is {Length:>0}&&delayed.Process.CommandLineStatus.State=="captured","deferred metadata populates the immutable completion for a live process");
    Check(deferredPending.Process.CommandLine==null,"completion enrichment does not mutate the saved original");
    using var brokenMetadata=ActorLease.Capture(Event(),sensor,true);
    brokenMetadata.DeferredMetadata=()=>throw new IOException("controlled optional metadata failure");
    var failureEvent=Event();var kept=collector.Complete(failureEvent,brokenMetadata,collector.Begin(failureEvent,brokenMetadata),new());
    Check(kept.Process.Status.State=="partial"&&kept.Preservation.HashMatched==true&&brokenMetadata.MetadataHandle==null,"optional metadata failure retains verified executable and releases process handle");
    var calls=0;var inbox=new WindowsKernelActorInbox(1);
    var held=ActorLease.Capture(Event(),sensor,true);var retainedStream=held.Image!;
    Check(inbox.TryCapture("first",()=>{calls++;return held;})&&inbox.TryCapture("first",()=>throw new Exception("duplicate capture")),"native early-handle retry reuses one owned lease");
    Check(!inbox.TryCapture("overflow",()=>throw new Exception("unbounded capture"))&&calls==1,"early-handle capacity rejects allocation before opening another executable");
    using var transferred=inbox.Take("first");inbox.Dispose();
    Check(ReferenceEquals(transferred,held)&&inbox.Take("first")==null&&retainedStream.CanRead,"early lease transfers once and survives inbox shutdown");
    var abandoned=ActorLease.Capture(Event(),sensor,true);var abandonedStream=abandoned.Image!;var cleanup=new WindowsKernelActorInbox(1);
    cleanup.TryCapture("abandoned",()=>abandoned);cleanup.Dispose();
    Check(!abandonedStream.CanRead&&abandoned.MetadataHandle==null,"shutdown closes every undelivered executable and process handle");
    var cleanupId=Guid.NewGuid().ToString("N");var cleanupFile=Path.Combine(root,cleanupId+".prepared");File.WriteAllText(cleanupFile,"already durably delivered");
    var cleanupHealth=new List<string>();
    using(var locked=new FileStream(cleanupFile,FileMode.Open,FileAccess.Read,FileShare.None))
    {WindowsKernelSource.CleanupPrepared(root,cleanupId,cleanupHealth.Add);Check(cleanupHealth.Count==1&&File.Exists(cleanupFile),"locked delivered-event cache reports cleanup failure without retrying publication");}
    WindowsKernelSource.CleanupPrepared(root,cleanupId,cleanupHealth.Add);
    Check(!File.Exists(cleanupFile)&&cleanupHealth.Count==1,"delivered-event cache cleanup succeeds after lock release");
}
if(!Path.GetFileNameWithoutExtension(actor).Equals("dotnet",StringComparison.OrdinalIgnoreCase))
{
    // Rename only a newly created QA apphost; its embedded managed DLL remains in the owned fixture directory.
    var renamed=Path.Combine(Path.GetDirectoryName(actor)!,"renamed-actor-"+Guid.NewGuid().ToString("N")+(OperatingSystem.IsWindows()?".exe":""));File.Copy(actor,renamed);
    if(!OperatingSystem.IsWindows())File.SetUnixFileMode(renamed,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
    var info=new ProcessStartInfo(renamed){RedirectStandardInput=true,RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true};info.ArgumentList.Add("--hold");
    using var child=Process.Start(info)!;
    try
    {
        Check(child.StandardOutput.ReadLine()=="ready","renamed executable starts as controlled test actor");
        var observation=Event(renamed,child.Id);using var renamedLease=ActorLease.Capture(observation,sensor);var result=collector.Complete(observation,renamedLease,collector.Begin(observation,renamedLease),new());
        Check(result.ActorExecutable.Sha256==complete.ActorExecutable.Sha256&&result.ActorExecutable.ObservedPath==renamed,"renamed executable keeps its bytes/hash and actual image path");
        Check(result.Preservation.HashMatched==true,"renamed actor is preserved without inferring legitimacy from name");
    }
    finally{child.StandardInput.WriteLine();child.WaitForExit();}

    // Use only a new owned apphost with a harmless overlay; copy-size policy must not disable actor hashing.
    var large=Path.Combine(Path.GetDirectoryName(actor)!,"large-actor-"+Guid.NewGuid().ToString("N")+(OperatingSystem.IsWindows()?".exe":""));
    File.Copy(actor,large);using(var extra=new FileStream(large,FileMode.Append)){extra.Write(new byte[2*1024*1024]);}
    if(!OperatingSystem.IsWindows())File.SetUnixFileMode(large,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
    var largeInfo=new ProcessStartInfo(large){RedirectStandardInput=true,RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true};largeInfo.ArgumentList.Add("--hold");
    using var largeChild=Process.Start(largeInfo)!;
    try
    {
        Check(largeChild.StandardOutput.ReadLine()=="ready","large owned actor starts for preservation-limit test");
        var observation=Event(large,largeChild.Id);using var largeLease=ActorLease.Capture(observation,sensor);
        var result=collector.Complete(observation,largeLease,collector.Begin(observation,largeLease),new(MaximumActorMiB:1));
        using var original=File.OpenRead(large);
        Check(result.ActorExecutable.Sha256==Convert.ToHexString(SHA256.HashData(original)),"actor above preservation size limit still receives verified SHA256");
        Check(result.Preservation.Status.State=="failed"&&result.Preservation.Status.Reason=="actor-exceeds-preservation-size-limit"&&result.Preservation.ArtifactRelativePath==null,"oversize preservation has a distinct failure and never copies the target");
    }
    finally{largeChild.StandardInput.WriteLine();largeChild.WaitForExit();}
}
var queueRoot=Path.Combine(root,"queue");var spool=new EventSpool(queueRoot,sensor);
await using(var pipeline=new ForensicPipeline(sensor,queueRoot,message=>throw new Exception(message)))
{pipeline.Submit(e,new(PreserveActorOnAlert:false),spool.Enqueue,spool.Enqueue);}
var batch=spool.Peek();Check(batch.Events.Length==2&&batch.Events[0].Forensics!.Collection.State=="pending"&&batch.Events[1].Forensics!.RelatedEventId==e.EventId,"durable observation precedes immutable linked completion");
var rejected=false;try{spool.Acknowledge(batch,new(2,0){AttributionVersion=1});}catch(InvalidDataException){rejected=true;}Check(rejected&&spool.Peek().Events.Length==2,"old server receipt cannot discard forensic envelope");
spool.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1});Check(spool.Peek().Events.Length==0,"capable server acknowledgement drains evidence");
var observed=new System.Collections.Concurrent.ConcurrentBag<AgentEvent>();var completedEvents=new System.Collections.Concurrent.ConcurrentBag<AgentEvent>();
using(var busy=new ManualResetEventSlim(false))using(var release=new ManualResetEventSlim(false))
{
    await using var pipeline=new ForensicPipeline(sensor,Path.Combine(root,"volume"),message=>throw new Exception(message));
    pipeline.Submit(Event(),new(PreserveActorOnAlert:false),observed.Add,done=>{busy.Set();release.Wait();completedEvents.Add(done);});
    Check(busy.Wait(TimeSpan.FromSeconds(10)),"volume test holds only its own enrichment callback");
    try{for(var i=0;i<80;i++)pipeline.Submit(Event(),new(PreserveActorOnAlert:false),observed.Add,completedEvents.Add);}
    finally{release.Set();}
}
Check(observed.Count==81&&observed.All(x=>x.Forensics!.IsValid()),"high-volume bounded worker retains every original observation");
Check(observed.Count(x=>x.Forensics!.Collection.Reason=="enrichment-queue-capacity-exceeded")==49&&completedEvents.Count==32,"queue pressure is explicit unavailable evidence with bounded retained handles");
Check(observed.Select(x=>x.Forensics!.CollectorSequence).Distinct().Count()==81,"monotonic collector order does not reuse sequence values under pressure");
Check(observed.Where(x=>x.Forensics!.Collection.Reason=="enrichment-queue-capacity-exceeded").All(x=>x.Forensics!.Detection.ReasonCodes.Contains("ENRICHMENT_QUEUE_CAPACITY_EXCEEDED")),"queue pressure produces stable SIEM reason codes for retained observations");
var failures=new List<AgentEvent>();var errors=new List<string>();var failedEvent=Event();
await using(var pipeline=new ForensicPipeline(sensor,Path.Combine(root,"worker-failure"),errors.Add))
{pipeline.Submit(failedEvent,new(CacheEntries:0),failures.Add,failures.Add);}
Check(errors.Count==1&&failures.Count==2&&failures[1].Forensics!.Collection.State=="failed"&&failures[1].Forensics!.RelatedEventId==failedEvent.EventId,"unexpected enrichment failure emits an immutable linked failure completion");
Check(failures[1].Forensics!.IsValid()&&failures[1].Forensics!.Detection.ReasonCodes.Contains("ACTOR_ENRICHMENT_FAILED")&&failures[1].Forensics!.ActorExecutable.Sha256==null,"failed completion remains valid SIEM evidence without fabricated hash");
Check(failures[1].Operation=="Actor forensic evidence collection failed"&&failures[1].Forensics!.Preservation.SourceEventId==failedEvent.EventId&&failures[1].Forensics!.Response.Status=="failed","failure operation, response status and preservation source linkage agree");
Console.WriteLine($"PASS {count} checks; artifacts: {root}");
