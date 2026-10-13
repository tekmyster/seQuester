using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

[assembly:System.Runtime.Versioning.SupportedOSPlatform("windows")]

if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Windows native snapshot identity/signature fixture");
if(args is ["--raw-crash-child",var crashDirectory,var nonce])
{
    var full=Path.GetFullPath(crashDirectory);
    if(!full.StartsWith(@"D:\Codex\RansomFree\windows-token-20260930\actor-intake-fixture-",StringComparison.OrdinalIgnoreCase)||!Guid.TryParseExact(nonce,"N",out _)||File.ReadAllText(Path.Combine(full,"nonce"))!=nonce)throw new ArgumentException("Invalid owned crash fixture");
    var eventValue=JsonSerializer.Deserialize<AgentEvent>(File.ReadAllBytes(Path.Combine(full,"input-event.json")))!;
    var payload=File.ReadAllBytes(Path.Combine(full,"input-record.bin"));
    var childJournal=new WindowsKernelOperationJournal(Path.Combine(full,"kernel-inbox"));
    WindowsKernelSource.Intake(childJournal,eventValue,payload,()=>
    {
        File.WriteAllText(Path.Combine(full,"collector-entered.json"),JsonSerializer.Serialize(new{Pid=Environment.ProcessId,Started=Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc(),Nonce=nonce}));
        using var stopped=new ManualResetEventSlim();stopped.Wait();
    },()=>throw new Exception("Crash cut unexpectedly reached ACK"),_=>throw new Exception("Crash cut unexpectedly reached delivery"),_=>{});
    return;
}
if(args is not ["--ready-priority"]&&args.Length!=0&&(args.Length!=2||args[0] is not ("--server" or "--syscall")))throw new ArgumentException("Expected no arguments, --ready-priority, --server <server.dll>, or --syscall <native-records.bin>");
var root=Path.Combine(args is ["--syscall",_] or ["--ready-priority"] ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex"):@"D:\Codex\RansomFree\windows-token-20260930","actor-intake-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
if(args is ["--syscall",var nativeRecords]){await SyscallActorChecks.Run(root,nativeRecords);return;}
var count=0;void Check(bool passed,string name){if(!passed)throw new Exception("FAIL "+name);Console.WriteLine("PASS "+name);count++;}
void Reject(Action action,string name){try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException or IOException){Check(true,name);return;}throw new Exception("FAIL accepted: "+name);}
// Reproduce live NVR pressure: native delivery must keep its captured actor and
// durable observation when all 32 enrichment permits are occupied.
using(var enteredCapacity=new ManualResetEventSlim())using(var releaseCapacity=new ManualResetEventSlim())
{
    var completedCapacity=new System.Collections.Concurrent.ConcurrentQueue<AgentEvent>();
    await using var pipelineCapacity=new ForensicPipeline(Guid.NewGuid().ToString("N"),Path.Combine(root,"capacity-retry"),_=>{});
    AgentEvent CapacityEvent()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)",Path.Combine(root,"capacity-target"),null,null,null,"Windows minifilter");
    var firstCapacity=CapacityEvent();var blockingCapacity=ActorLease.Unavailable(firstCapacity,"capacity-fixture");
    blockingCapacity.DeferredMetadata=()=>{enteredCapacity.Set();if(!releaseCapacity.Wait(30000))throw new TimeoutException("Owned capacity barrier expired");};
    try
    {
        pipelineCapacity.Submit(firstCapacity,new(),_=>{},completedCapacity.Enqueue,blockingCapacity,deferAtCapacity:true);
        Check(enteredCapacity.Wait(5000),"capacity fixture actually holds the enrichment worker");
        for(var slot=1;slot<32;slot++){var value=CapacityEvent();pipelineCapacity.Submit(value,new(),_=>{},completedCapacity.Enqueue,ActorLease.Unavailable(value,"capacity-fixture"),deferAtCapacity:true);}
        var delayedCapacity=CapacityEvent();using var delayedActor=ActorLease.Unavailable(delayedCapacity,"capacity-fixture");
        var descriptorPath=Path.Combine(root,"capacity-retained-descriptor.bin");File.WriteAllBytes(descriptorPath,new byte[]{1,2,3,4});
        delayedActor.Image=new FileStream(descriptorPath,FileMode.Open,FileAccess.Read,FileShare.Read);delayedActor.File=NativeFileIdentity.Read(delayedActor.Image);
        var originalCount=0;var completionCount=0;
        try{pipelineCapacity.Submit(delayedCapacity,new(),_=>originalCount++, _=>completionCount++,delayedActor,deferAtCapacity:true);throw new Exception("Accepted full durable queue");}
        catch(ForensicQueueCapacityException){Check(originalCount==0&&completionCount==0&&delayedActor.Image?.ReadByte()==1,"full queue emits nothing and preserves exact caller-owned actor descriptor");}
        // Ordinary non-durable producers retain their existing explicit overflow behavior.
        AgentEvent? overflowCapacity=null;var overflowValue=CapacityEvent();pipelineCapacity.Submit(overflowValue,new(),e=>overflowCapacity=e,_=>{},ActorLease.Unavailable(overflowValue,"capacity-fixture"));
        Check(overflowCapacity?.Forensics?.Collection.Reason=="enrichment-queue-capacity-exceeded","non-durable source overflow behavior remains explicit");
        releaseCapacity.Set();var deadlineCapacity=Stopwatch.StartNew();
        while(completedCapacity.Count<32&&deadlineCapacity.ElapsedMilliseconds<15000)await Task.Delay(20);
        Check(completedCapacity.Count==32,"all occupied capacity permits return after worker release");
        delayedActor.Image!.Position=0;
        pipelineCapacity.Submit(delayedCapacity,new(),e=>{Check(e.EventId==delayedCapacity.EventId,"capacity retry keeps original event identity");originalCount++;},e=>{Check(e.Forensics?.RelatedEventId==delayedCapacity.EventId,"capacity retry completion links the same event");completionCount++;},delayedActor,deferAtCapacity:true);
        while(completionCount==0&&deadlineCapacity.ElapsedMilliseconds<20000)await Task.Delay(20);
        Check(originalCount==1&&completionCount==1,"deferred event completes exactly once after capacity returns");
    }
    finally{releaseCapacity.Set();}
}
// A slow diagnostic call must not occupy the receiver's execution thread, and
// connection ownership must survive until that call has actually returned.
using(var entered=new ManualResetEventSlim())using(var release=new ManualResetEventSlim())using(var disposingEntered=new ManualResetEventSlim())using(var cancelled=new CancellationTokenSource())
{
    var errors=new System.Collections.Concurrent.ConcurrentQueue<string>();
    var diagnostic=new WindowsKernelDiagnosticWorker(()=>{entered.Set();release.Wait();},errors.Enqueue,cancelled.Token);
    Task? disposing=null;
    try
    {
        Check(entered.Wait(TimeSpan.FromSeconds(5)),"supplementary diagnostic worker enters independently");
        var rawReceiver=WindowsKernelSource.StartReceiver(()=>File.WriteAllText(Path.Combine(root,"receiver-progress.txt"),"raw receiver progressed"));
        Check(rawReceiver.Wait(TimeSpan.FromSeconds(5))&&File.Exists(Path.Combine(root,"receiver-progress.txt")),"blocked diagnostic I/O cannot monopolize the operation receiver thread");
        cancelled.Cancel();disposing=Task.Factory.StartNew(()=>{disposingEntered.Set();diagnostic.Dispose();},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
        if(!disposingEntered.Wait(TimeSpan.FromSeconds(5)))throw new TimeoutException("Diagnostic disposer did not start");
        Check(!disposing.Wait(100),"connection cleanup waits for outstanding diagnostic request");
        release.Set();Check(disposing.Wait(TimeSpan.FromSeconds(5))&&errors.IsEmpty,"diagnostic ownership releases after request returns");
    }
    finally{release.Set();if(disposing==null)diagnostic.Dispose();else disposing.GetAwaiter().GetResult();}
}
using(var failed=new ManualResetEventSlim())using(var resumed=new ManualResetEventSlim())using(var cancelled=new CancellationTokenSource())
{
    var attempts=0;var errors=new System.Collections.Concurrent.ConcurrentQueue<string>();
    using var diagnostic=new WindowsKernelDiagnosticWorker(()=>{if(Interlocked.Increment(ref attempts)==1)throw new IOException("controlled diagnostic persistence failure");resumed.Set();},message=>{errors.Enqueue(message);failed.Set();},cancelled.Token);
    Check(failed.Wait(TimeSpan.FromSeconds(5))&&resumed.Wait(TimeSpan.FromSeconds(5))&&errors.Single().StartsWith("Windows kernel diagnostic journal gap:",StringComparison.Ordinal),"diagnostic failure is explicit and does not prevent later draining");
    cancelled.Cancel();
}
var server=new Store(Path.Combine(root,"server"));var code=server.CreateCode();
var enrollment=server.Enroll(new(code.Code,"controlled-staged-intake-fixture","fixture"))!;var sensor=enrollment.EndpointId;
ThreadContextChecks.Run(root,sensor,Check);
var bytes=File.ReadAllBytes(Path.Combine(Environment.SystemDirectory,"cmd.exe"));
var expected=Convert.ToHexString(SHA256.HashData(bytes));
var e=Wire.Event(root);var wire=new Wire(e,bytes);var health=new List<string>();var dir=Path.Combine(root,"sensor");
if(args is ["--ready-priority"]){CheckReadyPriority();Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=count,Root=root,LiveQualified=false}));return;}
await CheckRawDurability();
await CheckRawCrashRecovery();
CheckReadyProtocol();
CheckProactiveStore();
CheckProactiveRecovery();
CheckAcknowledgementOutcomeRecovery();
CheckSourceVolumeIdentity();
CheckReadyCursor();
CheckReadyPriority();
CheckCreationMetadata();
CheckQuotaDirectoryAccounting();
var intake=new WindowsStagedActorStore(dir,sensor);var collector=new ForensicCollector(sensor,dir);
using var actor=intake.Capture(e,wire.Provider,wire.Send,health.Add);
Check(wire.Acks==0&&actor.Image!=null&&actor.Acquisition?.SnapshotSha256==expected,"snapshot capture cannot ACK before the separate operation journal is durable (synthetic wire)");
Reject(()=>intake.AcknowledgeAfterJournal(e,Path.Combine(dir,"missing.record"),wire.Send,health.Add),"candidate ACK rejects a missing or unrelated operation journal");
Check(actor.File.StableId==null&&actor.SnapshotFile?.StableId!=null&&actor.Acquisition?.SourceIdentityStatus.State=="unavailable","source file identity stays separate from snapshot identity");
Check(actor.Process.EventSubject.Sid=="S-1-5-20"&&actor.Process.Owner.Sid=="S-1-5-18"&&actor.Process.ThreadToken.Sid=="S-1-5-20","snapshot does not replace operation-time token contexts");
var original=e with{Forensics=collector.Begin(e,actor)};
var verifiedIdentity=actor.AcquiredTrustIdentity(e);
Check(verifiedIdentity?.Sha256==expected,"held verified snapshot supplies exact actor SHA-256 for whitelist matching");
Check(actor.AcquiredTrustIdentity(Wire.Next(e))==null&&actor.AcquiredTrustIdentity(e with{Process=e.Process+".different"})==null&&actor.AcquiredTrustIdentity(e with{Attribution=e.Attribution! with{WindowsKernel=e.Attribution.WindowsKernel! with{ProcessId=77}}})==null,"stale event, changed path and reused process identity cannot borrow a snapshot whitelist hash");
server.InitializeTrustStorage();var ruleNow=DateTimeOffset.UtcNow;
var hashRule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account-and-process",["read"],"log-only",ruleNow.AddMinutes(-5),ruleNow.AddHours(1)){Name="Verified actor hash fixture",Enabled=true,OperatingSystem="windows",Authority="QA",AccountKind="sid",AccountId="S-1-5-20",Executable=e.Process,Sha256=expected};
server.PublishTrustPolicy(new(0,"enforce",[hashRule],[],"unused"),"qa");Directory.CreateDirectory(Path.Combine(root,"trust"));var trustCache=new TrustPolicyCache(Path.Combine(root,"trust"),sensor,"https://qa.invalid");trustCache.Save(server.TrustAssignment(sensor),DateTimeOffset.UtcNow);
var verified=verifiedIdentity!.Value;var trust=TrustEventEvaluation.Evaluate(trustCache,sensor,null,"windows",e,new("QA","S-1-5-20",e.Process,expected,Verified:true,AccountKind:"sid"),DateTimeOffset.UtcNow,"windows-operation-bound-snapshot-v1",verified.CreatedUtc,verified.CheckedUtc);
var trusted=e with{Trust=trust};trusted=trusted with{Forensics=collector.Begin(trusted,actor)};var stored=new StoredEvent(1,sensor,DateTimeOffset.UtcNow,trusted);
Check(trust.IsValid()&&trust.Result.Decision.LogOnly&&server.ClassifyTrust(stored)==TrustEventClassification.LogOnly,"server independently validates path, actor SHA-256, exact acquisition and impersonated user whitelist");
Check(server.ClassifyTrust(stored with{Event=trusted with{Trust=trust with{Actor=trust.Actor with{Sha256=new string('0',64)}}}})==TrustEventClassification.PolicyUnknown,"renamed or substituted actor bytes do not inherit a whitelisted hash");
Check(server.ClassifyTrust(stored with{Event=trusted with{Forensics=null}})==TrustEventClassification.PolicyUnknown,"hash whitelist claim without acquisition evidence cannot suppress alerts");
Check(!TrustEventEvaluation.Evaluate(trustCache,sensor,null,"windows",e with{Attribution=e.Attribution! with{WindowsKernel=e.Attribution.WindowsKernel! with{Major=4}}},trust.Actor,DateTimeOffset.UtcNow,"windows-operation-bound-snapshot-v1",verified.CreatedUtc,verified.CheckedUtc).Result.Decision.LogOnly,"read whitelist still alerts on writes by the same verified actor");
var result=collector.Complete(e,actor,original.Forensics!,new());
Check(result.IsValid()&&result.Preservation.HashMatched==true&&result.ActorExecutable.Sha256==expected,"snapshot forensic enrichment and actor preservation validate");
Check(result.ActorExecutable.ObservedPath==e.Process&&result.ActorExecutable.File.StableId==null,"original observed path retained without attributing copy's ID to actor");
Check(result.ActorExecutable.Signature.Valid==true&&result.ActorExecutable.MetadataStatus.State=="captured","signature and version checks use private copy even when original path is nonexistent");
Check(result.Observation.HashPolicy=="not-hashed-by-forensic-collector"&&!File.Exists(e.Path),"target file never opened or hashed by acquisition");
using(var recovered=new WindowsStagedActorStore(dir,sensor).Restore(e))Check(recovered?.Image!=null&&recovered.Acquisition==actor.Acquisition,"restart recovers exact event, metadata and verified bytes");
var later=Wire.Next(e);wire.EventValue=later;
using(var reused=intake.Capture(later,wire.Provider,wire.Send,health.Add))
{
    Check(wire.MetadataReads==1&&reused.Acquisition?.SourceEventId==later.EventId&&reused.Acquisition.SnapshotId==actor.Acquisition!.SnapshotId,"later exact operation reuses bytes with its own event linkage");
    for(int i=0;i<100;i++)collector.Complete(later,reused,collector.Begin(later,reused),new(PreserveActorOnAlert:false));
    Check(collector.HashComputations==1&&collector.CacheHits==100,"100 enrichments reuse stable snapshot hash/signature cache");
}
var completed=e with{EventId=Guid.NewGuid().ToString("N"),Source="Forensic enrichment",Forensics=collector.LinkCompletion(result,Guid.NewGuid().ToString("N"))};completed=completed with{EventId=completed.Forensics!.EventId};
Check(completed.Forensics!.IsValid(),"linked completion preserves acquisition schema");
var spool=new EventSpool(Path.Combine(root,"queue"),sensor);spool.Enqueue(original);spool.Enqueue(completed);var batch=spool.Peek();
Reject(()=>spool.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=4}),"old server receipt cannot discard acquisition evidence");
Check(spool.Count==2,"missing acquisition acknowledgement retains complete queue");
spool.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=4,ActorAcquisitionVersion=1,ProcessCreationVersion=1});Check(spool.Count==0,"explicit acquisition acknowledgement drains queue");
foreach(var mutation in new Func<ActorAcquisitionEvidence,ActorAcquisitionEvidence>[] {a=>a with{Version=2},a=>a with{ProcessId=a.ProcessId+1},a=>a with{ProcessCreatedFileTime=a.ProcessCreatedFileTime+1},a=>a with{SourceEventId=Guid.NewGuid().ToString("N")},a=>a with{ProviderScope="os-uuid"},a=>a with{SnapshotSha256=new string('0',64)},a=>a with{SnapshotFile=null},a=>a with{Status=null!}})
    Check(!(result with{ActorExecutable=result.ActorExecutable with{Acquisition=mutation(result.ActorExecutable.Acquisition!)}}).IsValid(),"contradictory acquisition schema rejected");
var receiver=new EvidenceReceiver(server,Path.Combine(root,"server"));server.Ingest(sensor,new([original,completed]));
var manifest=File.ReadAllBytes(Path.Combine(dir,result.Preservation.ManifestRelativePath!));
var receipt=await receiver.Start(sensor,new(completed.EventId,Convert.ToBase64String(manifest)));
using(var file=File.OpenRead(Path.Combine(dir,result.Preservation.ArtifactRelativePath!))){var buffer=new byte[65536];long offset=0;int n;while((n=file.Read(buffer))>0){await receiver.Chunk(sensor,receipt.EvidenceId,offset,buffer.AsSpan(0,n).ToArray());offset+=n;}}
receipt=await receiver.Finish(sensor,receipt.EvidenceId);
using(var download=receiver.Download(sensor,receipt.EvidenceId,false))Check(Convert.ToHexString(SHA256.HashData(download))==expected,"central receiver persists and returns identical actor bytes");
using(var download=receiver.Download(sensor,receipt.EvidenceId,true))using(var json=JsonDocument.Parse(download))Check(json.RootElement.GetProperty("ActorAcquisition").Deserialize<ActorAcquisitionEvidence>()==actor.Acquisition,"central manifest preserves exact source/copy provenance");
await CheckClientCapability(batch);
// Tamper with provenance while recomputing the manifest digest. Hash validation
// alone must not let a manifest claim a different provider from its saved event.
var changedManifest=JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(manifest)!;
changedManifest["ActorAcquisition"]=JsonSerializer.SerializeToElement(actor.Acquisition! with{Provider=new string('A',32)});
var mismatched=JsonSerializer.SerializeToUtf8Bytes(changedManifest);
var badCompletion=completed with{EventId=Guid.NewGuid().ToString("N"),Forensics=completed.Forensics! with{Preservation=completed.Forensics.Preservation with{ManifestSha256=Convert.ToHexString(SHA256.HashData(mismatched))}}};
badCompletion=badCompletion with{Forensics=badCompletion.Forensics! with{EventId=badCompletion.EventId}};server.Ingest(sensor,new([badCompletion]));
try{await receiver.Start(sensor,new(badCompletion.EventId,Convert.ToBase64String(mismatched)));throw new Exception("Mismatched provenance accepted");}catch(EvidenceUploadException ex)when(ex.Status==422){Check(true,"central receiver rejects altered provenance even with matching manifest digest");}
if(args.Length==2&&args[0]=="--server")await CheckHttp(args[1]);

// A changed provider/generation/start key cannot retrieve the existing snapshot.
foreach(var field in new[]{"provider","generation","candidate","pid","start"})
{
    var changed=Wire.Next(e);var w=new Wire(changed,bytes){UnavailableBytes=true};
    switch(field){case "provider":w.Provider=new string('A',32);break;case "generation":w.Generation++;break;case "candidate":w.Candidate++;break;case "pid":changed=changed with{ProcessId=123457,Attribution=changed.Attribution! with{WindowsKernel=changed.Attribution.WindowsKernel! with{ProcessId=123457}}};w.EventValue=changed;break;case "start":changed=changed with{Attribution=changed.Attribution! with{WindowsKernel=changed.Attribution.WindowsKernel! with{ProcessCreatedFileTime=changed.Attribution.WindowsKernel!.ProcessCreatedFileTime+1}}};w.EventValue=changed;break;}
    using var rejected=intake.Capture(changed,w.Provider,w.Send,health.Add);
    Check(rejected.Image==null&&rejected.Acquisition?.Status.State=="failed"&&w.Acks==0,"no stale snapshot inherited after "+field+" change");
}
foreach(var corrupt in new[]{"provider","generation","candidate","pid","start","size","metadata"})
{
    var ev=Wire.Next(e);var w=new Wire(ev,bytes){CorruptChunk=corrupt};var isolated=new WindowsStagedActorStore(Path.Combine(root,"bad-"+corrupt),sensor);
    using var rejected=isolated.Capture(ev,w.Provider,w.Send,health.Add);var f=collector.Complete(ev,rejected,collector.Begin(ev,rejected),new());
    Check(rejected.Image==null&&w.Acks==0&&f.IsValid()&&f.Process.ThreadToken.Sid=="S-1-5-20"&&f.ActorExecutable.Sha256==null,"bad "+corrupt+" reply retains tokens and explicit acquisition failure without ACK");
}
var missingEvent=Wire.Next(e);var missingWire=new Wire(missingEvent,bytes){MissingBinding=true};
using(var missing=new WindowsStagedActorStore(Path.Combine(root,"missing"),sensor).Capture(missingEvent,missingWire.Provider,missingWire.Send,health.Add))
    Check(missing.Image==null&&missing.Acquisition?.Status.State=="unavailable"&&missing.Process.Pid==e.ProcessId&&missingWire.MetadataReads==0,"unavailable companion is preserved without PID/path fallback");
var liveEvent=Wire.Next(e);var liveWire=new Wire(liveEvent,bytes){Exited=false};
using(var live=new WindowsStagedActorStore(Path.Combine(root,"live"),sensor).Capture(liveEvent,liveWire.Provider,liveWire.Send,health.Add))Check(live.Image!=null&&liveWire.Acks==0,"live candidate remains available for subsequent operation binding");
var expiryEvent=Wire.Next(later);var expiryWire=new Wire(expiryEvent,bytes){GenerationOnly=true,UnavailableBytes=true};
using(var cached=intake.Capture(expiryEvent,expiryWire.Provider,expiryWire.Send,health.Add))Check(cached.Image!=null&&cached.Acquisition?.BindingKind=="process-generation-only"&&expiryWire.MetadataReads==0,"version-two exact generation can reuse a previously verified copy after byte expiry");
var uncached=Wire.Next(e);var uncachedWire=new Wire(uncached,bytes){GenerationOnly=true,UnavailableBytes=true};
using(var missing=new WindowsStagedActorStore(Path.Combine(root,"generation-only-miss"),sensor).Capture(uncached,uncachedWire.Provider,uncachedWire.Send,health.Add))Check(missing.Image==null&&missing.Acquisition?.Status.State=="failed","generation-only observation without prior bytes cannot invent an executable");
var quotaEvent=Wire.Next(e);var quotaWire=new Wire(quotaEvent,bytes);
using(var limited=new WindowsStagedActorStore(Path.Combine(root,"quota"),sensor,16384).Capture(quotaEvent,quotaWire.Provider,quotaWire.Send,health.Add))Check(limited.Image==null&&quotaWire.Acks==0,"quota failure preserves event metadata without acknowledging missing bytes");
using(var entered=new ManualResetEventSlim())using(var release=new ManualResetEventSlim())
{
    var next=Wire.Next(expiryEvent);var blockedWire=new Wire(next,bytes);
    var blocked=Task.Factory.StartNew(()=>{using var lease=intake.Capture(next,blockedWire.Provider,(request,length)=>{entered.Set();if(!release.Wait(TimeSpan.FromSeconds(10)))throw new IOException("Fixture release timed out");return blockedWire.Send(request,length);},health.Add);},TaskCreationOptions.LongRunning);
    try
    {
        if(!entered.Wait(TimeSpan.FromSeconds(5)))throw new Exception("Fixture capture did not enter");
        var restore=Task.Factory.StartNew(()=>{using var saved=intake.Restore(e);return saved?.Acquisition?.SnapshotSha256==expected;},TaskCreationOptions.LongRunning);
        Check(restore.Wait(TimeSpan.FromSeconds(2))&&restore.Result,"durable-event recovery does not wait for another candidate's blocked transfer");
    }
    finally{release.Set();await blocked;}
}
actor.Dispose();var snapshot=Path.Combine(dir,"kernel-actor-intake",result.ActorExecutable.Acquisition!.SnapshotId+".bin");File.Move(snapshot,snapshot+".original");File.WriteAllBytes(snapshot,bytes);
Reject(()=>{using var bad=intake.Restore(e);},"same bytes at replaced snapshot path fail stable identity recovery");
using(var failed=intake.RestoreForDelivery(e,health.Add))
{
    Check(failed?.Image==null&&failed?.Acquisition?.RecoveryStatus?.State=="failed"&&failed.Acquisition.SnapshotSha256==expected,"delivery retains historical acquisition metadata but rejects substituted snapshot bytes");
    var f=collector.Complete(e,failed!,collector.Begin(e,failed!),new());
    Check(f.IsValid()&&f.ActorExecutable.Sha256==null&&f.Preservation.Status.State!="captured"&&f.Process.ThreadToken.Sid=="S-1-5-20","recovery failure remains a valid alert with original impersonated identity and no fabricated artifact");
}
using(var missing=intake.RestoreForDelivery(Wire.Next(Wire.Next(expiryEvent)),health.Add))
    Check(missing!=null&&missing.Image==null&&missing.Binding.State=="failed","missing recovery manifest supplies an unavailable lease instead of allowing live-path fallback");
File.WriteAllText(Path.Combine(root,"acceptance.json"),JsonSerializer.Serialize(new{Passed=true,Checks=count,HttpTested=args.Length==2,Scope="Synthetic native wire; real Windows identity, signature, durable storage and server ingestion. Real native-driver integration remains a separate gate.",Root=root},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS {count} checks; artifacts: {root}");

async Task CheckRawDurability()
{
    // Synthetic, already-decoded payload: this tests storage/ordering, not the
    // native decoder. Actual token bytes are independently checked in VM runs.
    var raw=Enumerable.Range(0,WindowsKernelDecoder.EventBytes).Select(i=>(byte)i).ToArray();
    var inbox=new WindowsKernelOperationJournal(Path.Combine(root,"raw-first"),2);
    var errors=new List<string>();var acknowledged=false;var deliveries=0;
    void Ready(string path){if(inbox.Schedule(path))Interlocked.Increment(ref deliveries);}
    using(var entered=new ManualResetEventSlim())using(var release=new ManualResetEventSlim())
    {
        var work=WindowsKernelSource.StartReceiver(()=>WindowsKernelSource.Intake(inbox,e,raw,()=>{entered.Set();if(!release.Wait(TimeSpan.FromSeconds(10)))throw new IOException("Fixture collection release timed out");},()=>acknowledged=true,Ready,errors.Add));
        try
        {
            if(!entered.Wait(TimeSpan.FromSeconds(5)))throw new TimeoutException("Raw-first fixture did not enter collection");
            Check(File.ReadAllBytes(inbox.RecordPath(e.EventId)).SequenceEqual(raw)&&!acknowledged&&deliveries==0,"raw access bytes are readable from disk while actor collection is blocked; ACK/delivery wait");
        }
        finally{release.Set();await work;}
    }
    Check(acknowledged&&deliveries==1&&errors.Count==0,"successful collection acknowledges and schedules exactly once in this process");
    WindowsKernelSource.Intake(inbox,e,raw,()=>throw new Exception("Scheduled event collected twice"),()=>{},Ready,errors.Add);
    Check(deliveries==1,"reconnect leaves an already scheduled raw record with its existing delivery owner");
    var different=(byte[])raw.Clone();different[100]^=1;
    Reject(()=>WindowsKernelSource.Intake(inbox,e,different,()=>throw new Exception("Collision reached collection"),()=>throw new Exception("Collision acknowledged"),Ready,errors.Add),"same raw identity with different bytes is rejected before collection or ACK");
    Check(File.ReadAllBytes(inbox.RecordPath(e.EventId)).SequenceEqual(raw),"raw identity collision leaves original evidence intact");
    inbox.Complete(inbox.RecordPath(e.EventId));
    var quotaEvent=Wire.Next(e);var quotaWire=new Wire(quotaEvent,bytes);
    var tiny=new WindowsStagedActorStore(Path.Combine(root,"raw-first-quota"),sensor,1);
    WindowsKernelSource.Intake(inbox,quotaEvent,raw,()=>{using var actor=tiny.Capture(quotaEvent,quotaWire.Provider,quotaWire.Send,errors.Add);},()=>{},Ready,errors.Add);
    using(var unavailable=tiny.RestoreForDelivery(quotaEvent,errors.Add))
        Check(deliveries==2&&File.ReadAllBytes(inbox.RecordPath(quotaEvent.EventId)).SequenceEqual(raw)&&quotaWire.Acks==0&&unavailable is {Image:null}&&unavailable.Process.ThreadToken.Sid=="S-1-5-20"&&errors.Any(x=>x.StartsWith("Actor intake incomplete;",StringComparison.Ordinal)),"exhausted actor store still delivers raw operation with original token and explicit unavailable artifact");
    var ackLost=Wire.Next(quotaEvent);
    Reject(()=>WindowsKernelSource.Intake(inbox,ackLost,raw,()=>{},()=>throw new IOException("Controlled lost native ACK response"),Ready,errors.Add),"native ACK transport error remains visible");
    Check(deliveries==3&&File.Exists(inbox.RecordPath(ackLost.EventId)),"lost native ACK response does not strand the raw delivery until restart");
    var full=Wire.Next(ackLost);
    Reject(()=>WindowsKernelSource.Intake(inbox,full,raw,()=>throw new Exception("Full raw inbox reached collection"),()=>throw new Exception("Full raw inbox acknowledged"),Ready,errors.Add),"full raw inbox withholds native ACK and does not collect");
    Check(deliveries==3&&!File.Exists(inbox.RecordPath(full.EventId)),"raw capacity failure leaves both pending records intact");
    var recovered=new WindowsKernelOperationJournal(Path.Combine(root,"raw-first"),2);
    Check(recovered.Schedule(recovered.RecordPath(quotaEvent.EventId))&&!recovered.Prepare(quotaEvent.EventId,raw),"restart recovery owns a raw record even when acquisition never committed");
    // Complete and re-prepare are serialized; either the current delivery keeps
    // ownership or the native retry gets a new durable at-least-once record.
    using(var go=new ManualResetEventSlim())
    {
        var finish=Task.Run(()=>{go.Wait();recovered.Complete(recovered.RecordPath(quotaEvent.EventId));});
        var retry=Task.Run(()=>{go.Wait();return recovered.Prepare(quotaEvent.EventId,raw);});
        go.Set();await Task.WhenAll(finish,retry);
        Check(retry.Result?File.ReadAllBytes(recovered.RecordPath(quotaEvent.EventId)).SequenceEqual(raw):!File.Exists(recovered.RecordPath(quotaEvent.EventId)),"concurrent recovery completion and native retry leave a coherent delivery owner or durable replay");
    }
}

async Task CheckRawCrashRecovery()
{
    var path=Path.Combine(root,"raw-crash");Directory.CreateDirectory(path);var nonce=Guid.NewGuid().ToString("N");
    var payload=Wire.RawRecord(root);var observed=WindowsKernelDecoder.Decode(payload,sensor,p=>p,false);
    File.WriteAllBytes(Path.Combine(path,"input-event.json"),JsonSerializer.SerializeToUtf8Bytes(observed));
    File.WriteAllBytes(Path.Combine(path,"input-record.bin"),payload);File.WriteAllText(Path.Combine(path,"nonce"),nonce);
    var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true};
    foreach(var argument in new[]{"--raw-crash-child",path,nonce})start.ArgumentList.Add(argument);
    using var child=Process.Start(start)??throw new IOException("Crash fixture launch failed");
    try
    {
        var marker=Path.Combine(path,"collector-entered.json");var wait=Stopwatch.StartNew();
        while(!File.Exists(marker)&&!child.HasExited&&wait.Elapsed<TimeSpan.FromSeconds(20))await Task.Delay(100);
        if(!File.Exists(marker))throw new IOException("Crash fixture did not reach committed-raw cut");
        // The writer closes the marker before waiting. Retry one short partial-read
        // window without treating an arbitrary process as our child.
        JsonElement identity=default;
        for(var attempt=0;attempt<10;attempt++)try{identity=JsonDocument.Parse(File.ReadAllBytes(marker)).RootElement.Clone();break;}catch(JsonException){await Task.Delay(50);}
        if(identity.ValueKind!=JsonValueKind.Object||identity.GetProperty("Pid").GetInt32()!=child.Id||identity.GetProperty("Started").GetInt64()!=child.StartTime.ToUniversalTime().ToFileTimeUtc()||identity.GetProperty("Nonce").GetString()!=nonce)throw new IOException("Owned crash fixture identity mismatch");
        child.Kill();await child.WaitForExitAsync();
        var recovered=new WindowsKernelOperationJournal(Path.Combine(path,"kernel-inbox"));
        var saved=File.ReadAllBytes(recovered.RecordPath(observed.EventId));var decoded=WindowsKernelDecoder.Decode(saved,sensor,p=>p,false);
        Check(saved.SequenceEqual(payload)&&decoded.EventId==observed.EventId&&JsonSerializer.Serialize(decoded.Attribution!.WindowsKernel!.ThreadEffective)==JsonSerializer.Serialize(observed.Attribution!.WindowsKernel!.ThreadEffective),"abrupt collector exit after raw commit retains exact decodable event and thread token");
        Check(recovered.Schedule(recovered.RecordPath(decoded.EventId))&&!recovered.Prepare(decoded.EventId,payload),"fresh recovery schedules raw evidence left by an abruptly terminated collector");
        var failedStore=new WindowsStagedActorStore(path,sensor);using var unavailable=failedStore.RestoreForDelivery(decoded,_=>{});
        var forensic=new ForensicCollector(sensor,path);var pending=forensic.Begin(decoded,unavailable!);
        var result=forensic.Complete(decoded,unavailable!,pending,new());
        Check(result.IsValid()&&result.Process.Pid==decoded.ProcessId&&result.Process.ThreadToken.Sid=="S-1-5-20"&&result.ActorExecutable.Sha256==null&&result.Preservation.Status.State!="captured","crash recovery reports missing executable explicitly and retains original process/token evidence");
        File.WriteAllText(Path.Combine(path,"recovered.json"),JsonSerializer.Serialize(result));
    }
    finally{if(!child.HasExited){child.Kill();await child.WaitForExitAsync();}}
}

void CheckReadyProtocol()
{
    const string provider="11111111222233334444555555555555";const ulong instance=77;
    void N(byte[] b,int offset,uint value)=>WindowsStagedActorProtocol.Put32(b,offset,value);
    void Q(byte[] b,int offset,ulong value)=>WindowsStagedActorProtocol.Put(b,offset,value);
    byte[] Page(ulong after,ulong highest,uint flags=0)
    {
        var b=new byte[WindowsReadyActorProtocol.PageBytes];N(b,0,1);N(b,4,(uint)b.Length);Convert.FromHexString(provider).CopyTo(b,8);N(b,24,0x40020056);N(b,28,flags);Q(b,32,instance);
        var oldest=highest>=256?highest-255:1;Q(b,40,oldest);Q(b,48,highest);N(b,68,256);
        if((flags&1)!=0){Q(b,56,oldest-1);return b;}
        var count=(uint)Math.Min(16UL,highest-after);N(b,64,count);Q(b,56,after+count);
        for(var i=0;i<count;i++)
        {
            var o=72+i*80;Q(b,o,after+(uint)i+1);Q(b,o+8,(ulong)(500+i));Q(b,o+16,(ulong)(100-i));Q(b,o+24,(ulong)(1000+i));Q(b,o+32,134000000000000000);Q(b,o+40,999999);
            N(b,o+48,4096);N(b,o+52,(flags&2)!=0?5u:1u);N(b,o+56,0x100021);N(b,o+60,0x100021);N(b,o+64,2);Q(b,o+72,(ulong)(900+i));
        }
        return b;
    }
    var raw=Page(0,2);var page=WindowsReadyActorProtocol.Decode(raw,provider,instance,0);
    Check(page.Actors[0].Candidate==100&&page.Actors[1].Candidate==99&&page.NextSequence==2,"ready feed orders publication independently of candidate admission IDs (synthetic page)");
    var key=page.Actors[0].Request(13);Check(key.Length==72&&WindowsStagedActorProtocol.U32(key,4)==19&&WindowsStagedActorProtocol.U64(key,24)==500&&WindowsStagedActorProtocol.U64(key,32)==100,"ready discovery requests bytes only through the existing complete immutable candidate key");
    var request=WindowsReadyActorProtocol.Request(provider,16,7);Check(request.Length==40&&WindowsStagedActorProtocol.U64(request,24)==16&&WindowsStagedActorProtocol.U32(request,32)==7,"ready page request carries explicit cursor and bounded page length");
    foreach(var offset in new[]{0,4,8,24,28,32,40,48,56,64,68,72,124,136,152,232})
    {
        var changed=(byte[])raw.Clone();changed[offset]^=0x80;
        Reject(()=>WindowsReadyActorProtocol.Decode(changed,provider,instance,0),"ready page rejects changed field/unused row at "+offset);
    }
    var oversized=(byte[])raw.Clone();N(oversized,120,8388609);Reject(()=>WindowsReadyActorProtocol.Decode(oversized,provider,instance,0),"ready page refuses images over the explicit byte cap");
    var duplicate=(byte[])raw.Clone();Q(duplicate,160,500);Reject(()=>WindowsReadyActorProtocol.Decode(duplicate,provider,instance,0),"one process generation cannot be published twice in a page");
    duplicate=(byte[])raw.Clone();Q(duplicate,168,100);Reject(()=>WindowsReadyActorProtocol.Decode(duplicate,provider,instance,0),"one candidate cannot inherit a second ready sequence");
    var reset=WindowsReadyActorProtocol.Decode(Page(0,300,1),provider,instance,0);
    Check(reset.CursorResetRequired&&reset.Actors.Length==0&&reset.NextSequence==44&&reset.OldestRetained==45,"rolled publication journal reports an explicit missing range without silently skipping it");
    var continued=WindowsReadyActorProtocol.Decode(Page(44,300),provider,instance,44);
    Check(continued.Actors.Length==16&&continued.Actors[0].ReadySequence==45&&continued.NextSequence==60,"explicit cursor reset resumes at the retained floor");
    var expired=Page(0,1);N(expired,124,2);Check(WindowsReadyActorProtocol.Decode(expired,provider,instance,0).Actors[0].State==2,"expired candidate remains a discovery outcome without claiming available bytes");
    var acked=Page(0,1);N(acked,124,3);Check(WindowsReadyActorProtocol.Decode(acked,provider,instance,0).Actors[0].State==3,"acknowledged candidate remains independently discoverable as metadata");
    Check(WindowsReadyActorProtocol.Decode(Page(0,2,2),provider,instance,0).ProviderInactive,"provider shutdown is explicit and rows cannot claim retrievable bytes");
    var end=WindowsReadyActorProtocol.Decode(Page(ulong.MaxValue,ulong.MaxValue,4),provider,instance,ulong.MaxValue);
    Check(end.SequenceExhausted&&end.NextSequence==ulong.MaxValue&&end.Actors.Length==0,"ready sequence exhaustion does not wrap into an earlier identity");
    Check(WindowsReadyActorProtocol.Decode(Page(0,0),provider,instance,0).Actors.Length==0,"empty initial ready feed is valid");
    Reject(()=>WindowsReadyActorProtocol.Request(provider,0,17),"ready request cannot exceed bounded page size");
    Reject(()=>WindowsReadyActorProtocol.Decode(raw,new string('A',32),instance,0),"old provider cannot consume a new provider's page");
}

void CheckProactiveStore()
{
    var directory=Path.Combine(root,"proactive");var store=new WindowsStagedActorStore(directory,sensor);var initial=Wire.Event(root);var native=new Wire(initial,bytes);
    var k=initial.Attribution!.WindowsKernel!;
    var ready=new WindowsReadyActor(native.Provider,0x40020056,Convert.ToUInt64(k.Instance,16),1,native.Generation,native.Candidate,k.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    Check(store.CaptureReady(ready,native.Send,health.Add)=="captured"&&native.Acks==1,"proactive snapshot commits before candidate ACK without inventing a file operation (synthetic wire)");
    var files=Path.Combine(directory,"kernel-actor-intake");var index=Directory.GetFiles(files,"*.process.json").Single();
    Check(Directory.GetFiles(files,"*.event.json").Length==0&&File.Exists(index+".wal"),"proactive process record has a separate prepare/commit journal and no synthetic event manifest");
    var snapshot=Directory.GetFiles(files,"*.bin").Single();
    Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(snapshot)))==expected,"proactive private artifact preserves exact actor bytes");
    var later=Wire.Next(initial) with{ObservedUtc=DateTimeOffset.UtcNow};native.EventValue=later;native.GenerationOnly=true;native.UnavailableBytes=true;var reads=native.MetadataReads;
    using(var lease=store.Capture(later,native.Provider,native.Send,health.Add))
    {
        var forensic=new ForensicCollector(sensor,directory);var f=forensic.Complete(later,lease,forensic.Begin(later,lease),new());
        Check(lease.Image!=null&&native.MetadataReads==reads&&lease.Acquisition?.SourceEventId==later.EventId&&lease.Acquisition.BindingKind=="process-generation-only","first later operation links exact previously committed generation after native bytes expire");
        Check(f.IsValid()&&f.Preservation.HashMatched==true&&f.ActorExecutable.Sha256==expected&&f.Process.ThreadToken.Sid=="S-1-5-20"&&f.Process.Owner.Sid=="S-1-5-18","proactive bytes preserve independently captured later thread and process tokens");
        Check(lease.AcquiredTrustIdentity(later)?.Sha256==expected,"proactive full-key link supplies the existing verified snapshot whitelist hash");
    }
    var restarted=new WindowsStagedActorStore(directory,sensor);var afterRestart=Wire.Next(later);native.EventValue=afterRestart;
    using(var restored=restarted.Capture(afterRestart,native.Provider,native.Send,health.Add))
        Check(restored.Image!=null&&restored.Acquisition?.SnapshotSha256==expected,"restart revalidates proactive commit and snapshot before linking a later real event");
    foreach(var field in new[]{"provider","instance","generation","candidate","pid","start"})
    {
        var different=Wire.Next(initial);var other=new Wire(different,bytes){GenerationOnly=true,UnavailableBytes=true};
        switch(field){case "provider":other.Provider=new string('A',32);break;case "instance":different=different with{Attribution=different.Attribution! with{WindowsKernel=different.Attribution.WindowsKernel! with{Instance="ABCDEF0123456789"}}};other.EventValue=different;break;case "generation":other.Generation++;break;case "candidate":other.Candidate++;break;case "pid":different=different with{ProcessId=123457,Attribution=different.Attribution! with{WindowsKernel=different.Attribution.WindowsKernel! with{ProcessId=123457}}};other.EventValue=different;break;case "start":different=different with{Attribution=different.Attribution! with{WindowsKernel=different.Attribution.WindowsKernel! with{ProcessCreatedFileTime=k.ProcessCreatedFileTime+1}}};other.EventValue=different;break;}
        using var missing=store.Capture(different,other.Provider,other.Send,health.Add);
        Check(missing.Image==null&&missing.Acquisition?.Status.State!="captured","proactive cache refuses changed "+field+" without borrowing another executable");
    }
    Reject(()=>store.CaptureReady(ready with{ByteLength=ready.ByteLength+1},native.Send,health.Add),"same proactive key cannot silently change its published metadata");
    var wal=File.ReadAllBytes(index+".wal");var prepareLength=BinaryPrimitives.ReadInt32LittleEndian(wal.AsSpan(12));var preparedFrameLength=16+prepareLength+32;
    File.Move(index,index+".original");File.Move(index+".wal",index+".wal.original");File.WriteAllBytes(index+".wal",wal[..preparedFrameLength]);
    var acknowledgements=native.Acks;
    Check(new WindowsStagedActorStore(directory,sensor).CaptureReady(ready,native.Send,health.Add)=="failed"&&native.Acks==acknowledgements,"PREPARE without COMMIT cannot authorize candidate ACK or a successful acquisition");
    var failedEvent=Wire.Next(afterRestart);native.EventValue=failedEvent;
    using(var failed=new WindowsStagedActorStore(directory,sensor).Capture(failedEvent,native.Provider,native.Send,health.Add))
        Check(failed.Image==null&&failed.Acquisition?.Status.State!="captured","incomplete proactive commit cannot resolve a later event to orphaned bytes");
    var unavailable=new WindowsStagedActorStore(Path.Combine(root,"proactive-expired"),sensor);
    Check(unavailable.CaptureReady(ready with{State=2},(_,_)=>throw new Exception("Expired discovery requested bytes"),health.Add)=="unavailable","expired discovery persists an explicit unavailable result without any byte request");
    var limited=new WindowsStagedActorStore(Path.Combine(root,"proactive-quota"),sensor,16384);var fresh=new Wire(initial,bytes);
    Check(limited.CaptureReady(ready,fresh.Send,health.Add)=="failed"&&fresh.Acks==0,"proactive quota failure records failure and never ACKs uncaptured bytes");
}

void CheckQuotaDirectoryAccounting()
{
    var directory=Path.Combine(root,"quota-directory-accounting");var store=new WindowsStagedActorStore(directory,sensor,bytes.Length+2L*1024*1024);
    var files=Path.Combine(directory,"kernel-actor-intake");
    for(var n=0;n<10000;n++)File.WriteAllBytes(Path.Combine(files,$"historical-{n:D5}.failed.tmp"),new byte[8]);
    var native=new Wire(Wire.Event(root),bytes);var k=native.EventValue.Attribution!.WindowsKernel!;
    var ready=new WindowsReadyActor(native.Provider,0x40020056,Convert.ToUInt64(k.Instance,16),1,native.Generation,native.Candidate,k.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    Check(store.CaptureReady(ready,native.Send,health.Add)=="captured"&&native.Acks==1,"large historical intake directory preserves current quota admission and verified ACK");
    using(var changed=new FileStream(Path.Combine(files,"historical-00000.failed.tmp"),FileMode.Open,FileAccess.Write)){changed.SetLength(bytes.Length+2L*1024*1024);}
    native.EventValue=Wire.Next(native.EventValue);native.Generation++;native.Candidate++;
    var later=ready with{ReadySequence=2,Generation=native.Generation,Candidate=native.Candidate,Pid=native.EventValue.ProcessId!.Value,Created=native.EventValue.Attribution!.WindowsKernel!.ProcessCreatedFileTime!.Value};
    var previous=native.Acks;try{store.CaptureReady(later,native.Send,health.Add);throw new Exception("Growing failed file omitted from quota");}catch(IOException){}
    Check(native.Acks==previous&&Directory.GetFiles(files,"*.failed.tmp").Length==10000,"quota rescans current sizes including grown failed files, retains evidence, and withholds ACK");
}

void CheckProactiveRecovery()
{
    var directory=Path.Combine(root,"proactive-recovery");var store=new WindowsStagedActorStore(directory,sensor);var native=new Wire(Wire.Event(root),bytes);
    var k=native.EventValue.Attribution!.WindowsKernel!;
    var ready=new WindowsReadyActor(native.Provider,0x40020056,Convert.ToUInt64(k.Instance,16),1,native.Generation,native.Candidate,k.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    var messages=new List<string>();
    byte[] LostReply(byte[] request,int length){var response=native.Send(request,length);if(WindowsStagedActorProtocol.U32(request,4)==21)throw new COMException("Controlled lost committed ACK reply",unchecked((int)0x80004005));return response;}
    Check(store.CaptureReady(ready,LostReply,messages.Add)=="captured"&&native.Acks==1&&messages.Single().Contains("ACK unavailable"),"lost proactive ACK reply retains committed bytes with explicit health");
    var files=Path.Combine(directory,"kernel-actor-intake");var index=Directory.GetFiles(files,"*.process.json").Single();var reads=native.MetadataReads;
    Check(!Directory.GetFiles(files,"*.ack").Any(),"lost ACK response cannot claim a saved acknowledgement");
    var recovered=new WindowsStagedActorStore(directory,sensor);
    Check(recovered.CaptureReady(ready with{State=3},native.Send,messages.Add)=="captured"&&native.Acks==1,"restart respects saved acknowledgement retry backoff");
    using var intent=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(files,"*.ack-intent.json").Single()));var queued=intent.RootElement.GetProperty("QueuedUtc").GetDateTimeOffset();
    recovered.RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,native.Send,messages.Add,queued.AddSeconds(2));
    Check(native.Acks==2&&native.MetadataReads==reads&&Directory.GetFiles(files,"*.ack").Length==1,"durable ACK outbox retries after restart without cursor replay or recopying bytes");
    Check(store.CaptureReady(ready with{State=2},(_,_)=>throw new Exception("Saved receipt unexpectedly contacted native provider"),messages.Add)=="captured","verified saved ACK avoids repeated native acknowledgement");
    File.Move(index,index+".pre-recovery");
    Check(new WindowsStagedActorStore(directory,sensor).CaptureReady(ready with{State=2},(_,_)=>throw new Exception("Committed WAL recovery contacted expired native bytes"),messages.Add)=="captured"&&File.ReadAllBytes(index).SequenceEqual(File.ReadAllBytes(index+".pre-recovery")),"COMMIT without materialized index recovers exact acquisition from verified WAL");
    var ack=Directory.GetFiles(files,"*.ack").Single();var claim=File.ReadAllBytes(ack);claim[80]^=1;File.WriteAllBytes(ack,claim);
    Reject(()=>store.CaptureReady(ready,native.Send,messages.Add),"corrupted saved ACK cannot be silently replaced or accepted");
    var damaged=Path.Combine(root,"proactive-corrupt-commit");var damagedStore=new WindowsStagedActorStore(damaged,sensor);var damagedWire=new Wire(native.EventValue,bytes);
    Check(damagedStore.CaptureReady(ready,damagedWire.Send,messages.Add)=="captured","separate corrupt-commit fixture has valid initial acquisition");
    var damagedIndex=Directory.GetFiles(Path.Combine(damaged,"kernel-actor-intake"),"*.process.json").Single();var wal=File.ReadAllBytes(damagedIndex+".wal");wal[^1]^=1;File.WriteAllBytes(damagedIndex+".wal",wal);
    Reject(()=>damagedStore.CaptureReady(ready,(_,_)=>throw new Exception("Corrupt commit reached provider"),messages.Add),"corrupt COMMIT checksum rejects existing index before native ACK");
    File.Move(damagedIndex,damagedIndex+".pre-corruption");var acks=damagedWire.Acks;
    Check(new WindowsStagedActorStore(damaged,sensor).CaptureReady(ready,damagedWire.Send,messages.Add)=="failed"&&damagedWire.Acks==acks,"corrupt COMMIT cannot recover index or acknowledge bytes");
    foreach(var scenario in new[]{"exhausted","deadline","provider","rollback"})
    {
        var trial=Path.Combine(root,"proactive-ack-"+scenario);var outbox=new WindowsStagedActorStore(trial,sensor);var w=new Wire(native.EventValue,bytes);
        byte[] Fail(byte[] request,int length){var response=w.Send(request,length);if(WindowsStagedActorProtocol.U32(request,4)==21)throw new COMException("Controlled ACK transport failure",unchecked((int)0x80004005));return response;}
        Check(outbox.CaptureReady(ready,Fail,messages.Add)=="captured","ACK "+scenario+" fixture preserves initial copy");
        var owned=Path.Combine(trial,"kernel-actor-intake");using var savedIntent=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(owned,"*.ack-intent.json").Single()));var at=savedIntent.RootElement.GetProperty("QueuedUtc").GetDateTimeOffset();
        var provider=scenario=="provider"?new string('A',32):native.Provider;
        foreach(var seconds in scenario=="exhausted"?new[]{2,5,10}:scenario=="deadline"?new[]{31}:scenario=="rollback"?new[]{-1}:new[]{2})outbox.RetryProcessAcknowledgements(provider,ready.OperationInstance,Fail,messages.Add,at.AddSeconds(seconds));
        using var outcome=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(owned,"*.ack-outcome.json").Single()));
        var expectedOutcome=scenario switch{"exhausted"=>"ACK_TRANSPORT_EXHAUSTED","deadline"=>"ACK_RETRY_WINDOW_EXPIRED","provider"=>"ACK_PROVIDER_CHANGED",_=>"ACK_CLOCK_ROLLBACK"};
        Check(outcome.RootElement.GetProperty("Outcome").GetString()==expectedOutcome&&w.Acks==(scenario=="exhausted"?4:1),"ACK "+scenario+" has bounded exact attempts and an explicit durable terminal outcome");
        outbox.RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,(_,_)=>throw new Exception("Terminal ACK contacted provider"),messages.Add,at.AddSeconds(20));
        Check(Directory.GetFiles(owned,"*.bin").Length==1,"terminal ACK "+scenario+" retains the single committed actor copy");
    }
    var rejectedDirectory=Path.Combine(root,"proactive-ack-invalid-parameter");var rejectedStore=new WindowsStagedActorStore(rejectedDirectory,sensor);var rejectedWire=new Wire(native.EventValue,bytes);
    byte[] InvalidParameter(byte[] request,int length)
    {
        if(WindowsStagedActorProtocol.U32(request,4)==21)Marshal.ThrowExceptionForHR(unchecked((int)0x80070057));
        return rejectedWire.Send(request,length);
    }
    Check(rejectedStore.CaptureReady(ready,InvalidParameter,messages.Add)=="captured","actual INVALID_PARAMETER exception retains the committed actor and an ACK result");
    var rejectedFiles=Path.Combine(rejectedDirectory,"kernel-actor-intake");
    using(var result=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(rejectedFiles,"*.ack-attempt-1.result.json").Single())))
        Check(result.RootElement.GetProperty("Outcome").GetString()=="ACK_REPLY_UNAVAILABLE"&&result.RootElement.GetProperty("NativeCode").GetString()=="0x80070057","ACK failure preserves HRESULT even when Marshal maps it to ArgumentException");
    using(var intentRecord=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(rejectedFiles,"*.ack-intent.json").Single())))
        new WindowsStagedActorStore(rejectedDirectory,sensor).RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,rejectedWire.Send,messages.Add,intentRecord.RootElement.GetProperty("QueuedUtc").GetDateTimeOffset().AddSeconds(2));
    Check(rejectedWire.Acks==1&&Directory.GetFiles(rejectedFiles,"*.ack").Length==1&&Directory.GetFiles(rejectedFiles,"*.bin").Length==1,"restart retries the exact rejected claim without inventing success or recopying the executable");
    Reject(()=>store.CaptureReady(ready with{Provider=null!},native.Send,messages.Add),"null ready-provider metadata is an explicit invalid-data failure");
    foreach(var malformed in new[]{"ready","provider","sensor","timestamp"})
    {
        var trial=Path.Combine(root,"proactive-semantic-commit-"+malformed);var trialStore=new WindowsStagedActorStore(trial,sensor);var trialWire=new Wire(native.EventValue,bytes);
        Check(trialStore.CaptureReady(ready,trialWire.Send,messages.Add)=="captured","semantic "+malformed+" fixture begins with verified acquisition");
        var owned=Path.Combine(trial,"kernel-actor-intake");var processIndex=Directory.GetFiles(owned,"*.process.json").Single();var walPath=processIndex+".wal";var valid=File.ReadAllBytes(walPath);
        File.WriteAllBytes(walPath+".valid-copy",valid);
        var payload=System.Text.Json.Nodes.JsonNode.Parse(valid.AsSpan(16,BinaryPrimitives.ReadInt32LittleEndian(valid.AsSpan(12))))!;
        if(malformed=="ready")payload["Ready"]=null;
        else if(malformed=="provider")payload["Ready"]!["Provider"]=null;
        else if(malformed=="sensor")payload["Sensor"]="another-sensor";
        else payload["RecordedUtc"]="0001-01-01T00:00:00+00:00";
        var prepared=JsonSerializer.SerializeToUtf8Bytes(payload);
        byte[] Frame(uint kind,byte[] content)
        {
            var frame=new byte[16+content.Length+32];"SQACQ001"u8.CopyTo(frame);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8),kind);BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(12),content.Length);content.CopyTo(frame,16);SHA256.HashData(frame.AsSpan(0,16+content.Length)).CopyTo(frame,16+content.Length);return frame;
        }
        var invalid=Frame(1,prepared).Concat(Frame(2,SHA256.HashData(prepared))).ToArray();File.WriteAllBytes(walPath,invalid);File.Move(processIndex,processIndex+".valid-copy");var priorAcks=trialWire.Acks;
        Check(new WindowsStagedActorStore(trial,sensor).CaptureReady(ready,trialWire.Send,messages.Add)=="failed"&&trialWire.Acks==priorAcks,"checksummed but malformed "+malformed+" COMMIT fails explicitly before native acknowledgement");
        using var failure=JsonDocument.Parse(File.ReadAllBytes(processIndex));
        Check(failure.RootElement.GetProperty("Reason").GetString()=="proactive-acquisition-InvalidDataException"&&File.ReadAllBytes(walPath).SequenceEqual(invalid)&&Directory.GetFiles(owned,"*.bin").Length==1,"malformed "+malformed+" keeps original metadata and bytes with a durable failure reason");
    }
}

void CheckSourceVolumeIdentity()
{
    var directory=Path.Combine(root,"source-volume");var ev=Wire.Event(root);var native=new Wire(ev,bytes){SourceVolume=true};var store=new WindowsStagedActorStore(directory,sensor);
    using var actor=store.Capture(ev,native.Provider,native.Send,_=>{});var acquisition=actor.Acquisition!;
    var identity="windows-volume-guid:"+Wire.VolumeGuid.ToString("N").ToUpperInvariant()+":file-index:00000000000004D2";
    Check(actor.Image!=null&&actor.File.StableId==identity&&actor.SnapshotFile!.StableId!=identity&&acquisition.SourceIdentityStatus.State=="captured","original volume GUID/file index remains distinct from private snapshot identity");
    var collector=new ForensicCollector(sensor,directory);var observation=collector.Begin(ev,actor);
    Check(observation.IsValid()&&observation.ActorExecutable.File.StableId==identity,"existing versioned forensic schema retains captured original file identity");
    Check(!(observation with{ActorExecutable=observation.ActorExecutable with{File=actor.File with{StableId=identity.Replace("04D2","04D3")}}}).IsValid(),"source descriptor with another file index is rejected");
    using(var restored=new WindowsStagedActorStore(directory,sensor).Restore(ev))Check(restored?.File.StableId==identity&&restored.Image!=null,"restart verifies original source descriptor separately from copied executable bytes");
    var reply=native.Send(WindowsStagedActorProtocol.OperationRequest(acquisition,26),224);
    foreach(var offset in new[]{0,4,8,12,16,32,40,48,56,64,72,168,200,204,208,216})
    {
        var altered=reply.ToArray();altered[offset]^=1;
        Reject(()=>WindowsStagedActorProtocol.SourceIdentity(acquisition,actor.File,altered,null,true),"source volume reply rejects altered identity/format offset "+offset);
    }
    var k=ev.Attribution!.WindowsKernel!;var ready=new WindowsReadyActor(native.Provider,0x40020056,Convert.ToUInt64(k.Instance,16),1,native.Generation,native.Candidate,k.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    var proactiveDirectory=Path.Combine(root,"source-volume-proactive");var proactive=new WindowsStagedActorStore(proactiveDirectory,sensor);
    Check(proactive.CaptureReady(ready,native.Send,_=>{})=="captured","proactive acquisition commits original source volume reply in its checked WAL");
    using var linked=new WindowsStagedActorStore(proactiveDirectory,sensor).Capture(ev,native.Provider,native.Send,_=>{});
    Check(linked.File.StableId==identity&&linked.Acquisition?.SourceIdentityStatus.State=="captured","later exact operation recovers the proactive source descriptor without a current-path lookup");
    var unavailable=reply.ToArray();WindowsStagedActorProtocol.Put32(unavailable,8,0xC0000010);WindowsStagedActorProtocol.Put32(unavailable,12,0);unavailable.AsSpan(72,128).Clear();WindowsStagedActorProtocol.Put32(unavailable,200,0);
    var metadata=native.Send(WindowsStagedActorProtocol.OperationRequest(acquisition,13),144);var raw=WindowsStagedActorProtocol.Metadata(metadata,acquisition with{SourceIdentityStatus=EvidenceStatus.Unavailable("not-collected")});
    var missing=WindowsStagedActorProtocol.SourceIdentity(raw.Acquisition,raw.Source,unavailable,null,true);
    Check(missing.Source.StableId==null&&missing.Acquisition.SourceIdentityStatus.NativeCode=="0xC0000010","unavailable volume retains real OS status without inventing a stable descriptor");
    actor.Dispose();linked.Dispose();
    foreach(var recovery in new[]{(Store:store,Directory:directory,Acquisition:acquisition),(Store:proactive,Directory:proactiveDirectory,Acquisition:linked.Acquisition!)})
    {
        var snapshot=Path.Combine(recovery.Directory,"kernel-actor-intake",recovery.Acquisition.SnapshotId+".bin");
        File.Move(snapshot,snapshot+".original");File.WriteAllBytes(snapshot,bytes);
        using var failed=recovery.Store.RestoreForDelivery(ev,_=>{});
        Check(failed?.Image==null&&failed?.Acquisition?.RecoveryStatus?.State=="failed"&&failed.Acquisition.SnapshotSha256==expected&&failed.File.StableId==identity&&failed.File.Size==bytes.Length,"replacement of captured-source snapshot retains historical original identity and hash without usable bytes");
        var recoveryCollector=new ForensicCollector(sensor,recovery.Directory);
        var recovered=recoveryCollector.Complete(ev,failed!,recoveryCollector.Begin(ev,failed!),new());
        Check(recovered.IsValid()&&recovered.ActorExecutable.Sha256==null&&recovered.ActorExecutable.Acquisition?.SnapshotSha256==expected&&recovered.ActorExecutable.File.StableId==identity&&recovered.Preservation.Status.State!="captured"&&recovered.Process.ThreadToken.Sid=="S-1-5-20"&&failed!.AcquiredTrustIdentity(ev)==null,"historical source metadata survives failed recovery while trust, current hash and preservation remain unavailable");
        var manifest=Path.Combine(recovery.Directory,"kernel-actor-intake",ev.EventId+".event.json");var validManifest=File.ReadAllBytes(manifest);
        File.WriteAllBytes(manifest+".valid-source-copy",validManifest);
        foreach(var corruption in new[]{"file-index","status"})
        {
            var invalid=System.Text.Json.Nodes.JsonNode.Parse(validManifest)!;
            if(corruption=="file-index")invalid["Source"]!["StableId"]=identity.Replace("04D2","04D3");else invalid["Source"]!["Status"]=null;
            File.WriteAllBytes(manifest,JsonSerializer.SerializeToUtf8Bytes(invalid));
            using var rejected=recovery.Store.RestoreForDelivery(ev,_=>{});
            Check(rejected is {Image:null,Acquisition:null,Binding.State:"failed"}&&rejected.File.StableId==null&&rejected.Process.ThreadToken.Sid=="S-1-5-20","invalid historical source "+corruption+" fails closed without losing operation-time token evidence");
        }
    }
}

void CheckAcknowledgementOutcomeRecovery()
{
    var native=new Wire(Wire.Event(root),bytes);var k=native.EventValue.Attribution!.WindowsKernel!;
    var ready=new WindowsReadyActor(native.Provider,0x40020056,Convert.ToUInt64(k.Instance,16),1,native.Generation,native.Candidate,k.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    foreach(var scenario in new[]{"json","claim","unproven","state","expired"})
    {
        var directory=Path.Combine(root,"outcome-recovery-"+scenario);var store=new WindowsStagedActorStore(directory,sensor);var wire=new Wire(native.EventValue,bytes);var messages=new List<string>();
        byte[] LostReply(byte[] request,int length){var response=wire.Send(request,length);if(WindowsStagedActorProtocol.U32(request,4)==21)throw new COMException("Controlled missing ACK response",unchecked((int)0x80004005));return response;}
        Check(store.CaptureReady(ready,LostReply,messages.Add)=="captured","damaged outcome "+scenario+" begins with a retained snapshot and pending ACK intent");
        var files=Path.Combine(directory,"kernel-actor-intake");using var intent=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(files,"*.ack-intent.json").Single()));var value=intent.RootElement;
        var id=value.GetProperty("SnapshotId").GetString()!;var at=value.GetProperty("QueuedUtc").GetDateTimeOffset();var claim=value.GetProperty("ClaimSha256").GetString()!;var outcomePath=Path.Combine(files,id+".ack-outcome.json");
        var corrupted=scenario=="json"?"{":JsonSerializer.Serialize(new{Version=1,SnapshotId=id,ClaimSha256=scenario=="claim"?new string('A',64):claim,Attempt=1,RecordedUtc=at,Outcome=scenario=="state"?"ACK_REPLY_UNAVAILABLE":"ACK_CONFIRMED",NativeCode=(string?)null});
        File.WriteAllText(outcomePath,corrupted);var damaged=File.ReadAllBytes(outcomePath);var damagedHash=Convert.ToHexString(SHA256.HashData(damaged));var reads=wire.MetadataReads;
        var recovered=new WindowsStagedActorStore(directory,sensor);
        recovered.RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,wire.Send,messages.Add,at.AddSeconds(scenario=="expired"?31:2));
        var repair=Directory.GetFiles(files,"*.ack-outcome-recovery-*.json").Single();using var terminal=JsonDocument.Parse(File.ReadAllBytes(repair));
        Check(terminal.RootElement.GetProperty("ReplacesOutcomeSha256").GetString()==damagedHash&&File.ReadAllBytes(outcomePath).SequenceEqual(damaged),"damaged outcome "+scenario+" is retained byte-for-byte with a hash-linked immutable repair");
        Check(terminal.RootElement.GetProperty("Outcome").GetString()==(scenario=="expired"?"ACK_RETRY_WINDOW_EXPIRED":"ACK_CONFIRMED")&&wire.Acks==(scenario=="expired"?1:2)&&wire.MetadataReads==reads,"damaged outcome "+scenario+" cannot suppress an eligible exact retry or extend its deadline");
        new WindowsStagedActorStore(directory,sensor).RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,(_,_)=>throw new Exception("Verified repaired terminal repeated native ACK"),messages.Add,at.AddSeconds(35));
        Check(messages.Any(x=>x.StartsWith("Invalid actor ACK terminal record retained;",StringComparison.Ordinal)),"damaged outcome "+scenario+" emits explicit health during recovery");
    }
    var history=Path.Combine(root,"ack-index-history");var historicalStore=new WindowsStagedActorStore(history,sensor);var historicalWire=new Wire(native.EventValue,bytes);
    for(var i=0;i<16;i++)
    {
        historicalWire.Generation=native.Generation+(ulong)i;historicalWire.Candidate=native.Candidate+(ulong)i;
        Check(historicalStore.CaptureReady(ready with{Generation=historicalWire.Generation,Candidate=historicalWire.Candidate},historicalWire.Send,_=>{})=="captured","ACK history fixture confirms independent claim "+i);
    }
    var restarted=new WindowsStagedActorStore(history,sensor);restarted.RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,(_,_)=>throw new Exception("Completed history contacted provider"),_=>{});
    var historicalIntent=Directory.GetFiles(Path.Combine(history,"kernel-actor-intake"),"*.ack-intent.json").First();
    using(var held=new FileStream(historicalIntent,FileMode.Open,FileAccess.Read,FileShare.None))
        for(var i=0;i<100;i++)restarted.RetryProcessAcknowledgements(native.Provider,ready.OperationInstance,(_,_)=>throw new Exception("Completed history contacted provider"),_=>{});
    Check(restarted.AcknowledgementIndexLoads==1,"one hundred idle retry ticks do not reopen historical control records or rehash historical binaries after validated startup");
}

void CheckReadyPriority()
{
    var directory=Path.Combine(root,"ready-priority");var store=new WindowsStagedActorStore(directory,sensor);
    var native=new Wire(Wire.Event(root),bytes);var k=native.EventValue.Attribution!.WindowsKernel!;
    var instance=Convert.ToUInt64(k.Instance,16);var files=Path.Combine(directory,"kernel-actor-intake");
    var capturedBeforeExpired=false;var pageRequests=0;
    byte[] Feed(byte[] request,int length)
    {
        var command=WindowsStagedActorProtocol.U32(request,4);
        if(command==3){var b=new byte[48];WindowsStagedActorProtocol.Put32(b,0,4);WindowsStagedActorProtocol.Put(b,8,instance);return b;}
        if(command!=25){
            if(command==21)capturedBeforeExpired=!Directory.GetFiles(files,"*.process.json").Any(p=>JsonDocument.Parse(File.ReadAllBytes(p)).RootElement.GetProperty("State").GetString()=="unavailable");
            return native.Send(request,length);
        }
        pageRequests++;if(WindowsStagedActorProtocol.U32(request,32)!=16)throw new InvalidDataException("Discovery must request the existing bounded 16-row page");
        var after=WindowsStagedActorProtocol.U64(request,24);var page=new byte[WindowsReadyActorProtocol.PageBytes];
        void N(int o,uint v)=>WindowsStagedActorProtocol.Put32(page,o,v);void Q(int o,ulong v)=>WindowsStagedActorProtocol.Put(page,o,v);
        N(0,1);N(4,(uint)page.Length);Convert.FromHexString(native.Provider).CopyTo(page,8);N(24,0x40020056);Q(32,instance);Q(40,1);Q(48,3);Q(56,3);N(68,256);
        if(after==0){N(64,3);for(var i=0;i<3;i++){
            var o=72+i*80;var live=i==2;Q(o,(ulong)i+1);Q(o+8,native.Generation+(live?0UL:(ulong)i+1));Q(o+16,native.Candidate+(live?0UL:(ulong)i+1));
            Q(o+24,(ulong)k.ProcessId!+(live?0UL:(ulong)i+1));Q(o+32,(ulong)k.ProcessCreatedFileTime!);Q(o+40,999999);N(o+48,(uint)bytes.Length);N(o+52,live?1u:2u);N(o+56,0x80000020);N(o+60,0x100021);N(o+64,2);Q(o+72,1234);
        }}return page;
    }
    store.DrainReady(native.Provider,instance,Feed,_=>{});
    Check(capturedBeforeExpired,"retrievable executable is committed and acknowledged before older expired discoveries consume durable I/O");
    var records=Directory.GetFiles(files,"*.process.json").Select(p=>JsonDocument.Parse(File.ReadAllBytes(p)).RootElement.Clone()).ToArray();
    Check(records.Length==3&&records.Count(r=>r.GetProperty("State").GetString()=="unavailable")==2,"prioritization retains both older unavailable records without claiming their bytes");
    var captured=records.Single(r=>r.GetProperty("State").GetString()=="captured");var ready=captured.GetProperty("Ready");
    Check(ready.GetProperty("Pid").GetInt32()==k.ProcessId&&ready.GetProperty("Created").GetInt64()==k.ProcessCreatedFileTime,"preserved discovery keeps the exact process PID and creation time");
    Check(captured.GetProperty("Sha256").GetString()==expected&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Directory.GetFiles(files,"*.bin").Single())))==expected,"prioritized snapshot preserves actor bytes with independently matching SHA-256");
    Check(JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(files,"*.ready-cursor.json").Single())).RootElement.GetProperty("Sequence").GetUInt64()==3,"cursor advances over the full page only after all three records are materialized");
    var reads=native.MetadataReads;new WindowsStagedActorStore(directory,sensor).DrainReady(native.Provider,instance,Feed,_=>{});
    Check(pageRequests==2&&native.MetadataReads==reads&&native.Acks==1,"fresh restart neither recopies nor reacknowledges already preserved prioritized bytes");
}

void CheckReadyCursor()
{
    var directory=Path.Combine(root,"proactive-cursor");var store=new WindowsStagedActorStore(directory,sensor);var native=new Wire(Wire.Event(root),bytes);var k=native.EventValue.Attribution!.WindowsKernel!;var instance=Convert.ToUInt64(k.Instance,16);var messages=new List<string>();
    var queued=false;var rollover=false;var loseAckReply=false;var observedCursors=new List<ulong>();
    byte[] Feed(byte[] request,int length)
    {
        var command=WindowsStagedActorProtocol.U32(request,4);
        if(command==3){var b=new byte[48];WindowsStagedActorProtocol.Put32(b,0,4);WindowsStagedActorProtocol.Put(b,8,instance);WindowsStagedActorProtocol.Put32(b,40,queued?1u:0u);return b;}
        if(command!=25){var response=native.Send(request,length);if(command==21&&loseAckReply)throw new COMException("Controlled feed ACK reply loss",unchecked((int)0x80004005));return response;}
        var after=WindowsStagedActorProtocol.U64(request,24);observedCursors.Add(after);var page=new byte[WindowsReadyActorProtocol.PageBytes];
        void N(int o,uint v)=>WindowsStagedActorProtocol.Put32(page,o,v);void Q(int o,ulong v)=>WindowsStagedActorProtocol.Put(page,o,v);
        N(0,1);N(4,(uint)page.Length);Convert.FromHexString(native.Provider).CopyTo(page,8);N(24,0x40020056);Q(32,instance);N(68,256);
        if(rollover){N(28,1);Q(40,45);Q(48,300);Q(56,44);return page;}
        Q(40,1);Q(48,1);Q(56,1);
        if(after==0){N(64,1);Q(72,1);Q(80,native.Generation);Q(88,native.Candidate);Q(96,(ulong)k.ProcessId!);Q(104,(ulong)k.ProcessCreatedFileTime!);Q(112,999999);N(120,(uint)bytes.Length);N(124,1);N(128,0x80000020);N(132,0x100021);N(136,2);Q(144,1234);}
        return page;
    }
    queued=true;store.DrainReady(native.Provider,instance,Feed,messages.Add);
    Check(observedCursors.Count==0&&native.MetadataReads==0,"pending raw native operation yields proactive discovery before any feed or byte request");
    queued=false;store.DrainReady(native.Provider,instance,Feed,messages.Add);
    var files=Path.Combine(directory,"kernel-actor-intake");var cursor=Directory.GetFiles(files,"*.ready-cursor.json").Single();
    Check(JsonDocument.Parse(File.ReadAllBytes(cursor)).RootElement.GetProperty("Sequence").GetUInt64()==1&&Directory.GetFiles(files,"*.process.json").Length==1&&native.Acks==1,"ready cursor advances only after process acquisition is durably materialized");
    var reads=native.MetadataReads;new WindowsStagedActorStore(directory,sensor).DrainReady(native.Provider,instance,Feed,messages.Add);
    Check(observedCursors.SequenceEqual(new ulong[]{0,1})&&native.MetadataReads==reads&&native.Acks==1,"restart reads persisted ready cursor without recopying prior executable");
    rollover=true;store.DrainReady(native.Provider,instance,Feed,messages.Add);
    var gap=Directory.GetFiles(files,"*.ready-gap.json").Single();using var record=JsonDocument.Parse(File.ReadAllBytes(gap));
    Check(record.RootElement.GetProperty("After").GetUInt64()==1&&record.RootElement.GetProperty("OldestRetained").GetUInt64()==45&&record.RootElement.GetProperty("HighestPublished").GetUInt64()==300&&messages.Single().StartsWith("Proactive actor ready-feed gap:"),"retention rollover persists exact cursor gap and health instead of silently skipping acquisitions");
    Check(JsonDocument.Parse(File.ReadAllBytes(cursor)).RootElement.GetProperty("Sequence").GetUInt64()==44,"gap acknowledgement resumes at retained floor before requesting new entries");
    var malformed=File.ReadAllText(cursor).Replace(native.Provider,new string('A',32));File.WriteAllText(cursor,malformed);
    Reject(()=>store.DrainReady(native.Provider,instance,Feed,messages.Add),"persisted cursor for another provider cannot resume this provider's feed");
    var fair=new WindowsStagedActorStore(Path.Combine(root,"proactive-fairness"),sensor);queued=true;rollover=false;observedCursors.Clear();
    for(var i=0;i<9;i++)fair.DrainReady(native.Provider,instance,Feed,messages.Add);
    Check(observedCursors.Count==0,"continuous raw backlog receives nine priority deferrals");
    fair.DrainReady(native.Provider,instance,Feed,messages.Add);
    Check(observedCursors.SequenceEqual(new ulong[]{0}),"continuous raw backlog cannot starve the tenth bounded ready-feed opportunity");
    var durable=Path.Combine(root,"proactive-advanced-cursor-ack");var advanced=new WindowsStagedActorStore(durable,sensor);queued=false;loseAckReply=true;
    advanced.DrainReady(native.Provider,instance,Feed,messages.Add);
    var durableFiles=Path.Combine(durable,"kernel-actor-intake");var persistedCursor=Directory.GetFiles(durableFiles,"*.ready-cursor.json").Single();using var ackIntent=JsonDocument.Parse(File.ReadAllBytes(Directory.GetFiles(durableFiles,"*.ack-intent.json").Single()));
    Check(JsonDocument.Parse(File.ReadAllBytes(persistedCursor)).RootElement.GetProperty("Sequence").GetUInt64()==1&&!Directory.GetFiles(durableFiles,"*.ack").Any(),"lost ACK reply advances cursor only with a durable ACK intent and committed snapshot");
    loseAckReply=false;var before=native.MetadataReads;var queries=observedCursors.Count;
    new WindowsStagedActorStore(durable,sensor).RetryProcessAcknowledgements(native.Provider,instance,Feed,messages.Add,ackIntent.RootElement.GetProperty("QueuedUtc").GetDateTimeOffset().AddSeconds(2));
    Check(Directory.GetFiles(durableFiles,"*.ack").Length==1&&observedCursors.Count==queries&&native.MetadataReads==before,"independent restarted ACK worker completes after advanced cursor without rediscovery or byte request");
}

void CheckCreationMetadata()
{
    var creationDirectory=Path.Combine(root,"creation");var nativeEvent=Wire.Event(root);var native=new Wire(nativeEvent,bytes){CreationMetadata=true};
    var store=new WindowsStagedActorStore(creationDirectory,sensor);var collect=new ForensicCollector(sensor,creationDirectory);
    using var lease=store.Capture(nativeEvent,native.Provider,native.Send,health.Add);
    var f=collect.Complete(nativeEvent,lease,collect.Begin(nativeEvent,lease),new());
    Check(f.IsValid()&&f.Process.CommandLine==native.CreationCommand&&f.Process.Creation is {Status.State:"captured",CreatorPid:100,CreatorTid:101,FileOpenNameAvailable:true},"creation metadata survives an already exited actor and preserves exact command line/creator");
    Check(f.Process.ParentPid==100&&f.Process.ParentStartKey==f.Process.Creation!.CreatorCreatedFileTime!.Value.ToString()&&f.Process.ParentInstanceId==ActorLease.Correlate(sensor,100,f.Process.ParentStartKey)&&f.Process.ParentExecutablePath==null,"exact creator-as-parent correlation does not invent a parent image path");
    Check(f.Process.Owner.Sid=="S-1-5-18"&&f.Process.ThreadToken.Sid=="S-1-5-20"&&f.ActorExecutable.Sha256==expected,"creation metadata cannot replace operation-time principals or actor hash");
    var next=Wire.Next(nativeEvent);native.EventValue=next;native.CreationCommand="must not replace immutable metadata";
    using(var later=store.Capture(next,native.Provider,native.Send,health.Add))Check(later.Process.CommandLine==f.Process.CommandLine&&later.Process.Creation!.RawSha256==f.Process.Creation!.RawSha256,"same process reuses immutable creation proof across distinct operation sequences");
    foreach(var scenario in new[]{"designated-parent","context-mismatch","lookup-failed","empty","absent","truncated","surrogate-boundary","invalid-utf16","invalid-source","nonexact-image","pool-refused","allocation-failed","generation","start","pid","event-instance","event-sequence","length","status"})
    {
        var e2=Wire.Event(root);var wire2=new Wire(e2,bytes){CreationMetadata=true,CreationCommand=scenario is "truncated"?new string('X',3000):scenario=="surrogate-boundary"?new string('a',2047)+"\U0001F601tail":scenario=="empty"?"":scenario=="absent"?null:"child "+scenario,Generation=55};
        wire2.CreationMutation=b=>{
            void N(int o,uint v)=>WindowsStagedActorProtocol.Put32(b,o,v);void Q(int o,ulong v)=>WindowsStagedActorProtocol.Put(b,o,v);
            switch(scenario){
                case "designated-parent":Q(96,200);Q(128,0);N(92,3);break;
                case "context-mismatch":N(92,1);Q(120,0);Q(128,0);N(152,0);break;
                case "lookup-failed":N(92,3);Q(120,0);Q(128,0);N(152,0xC0000022);break;
                case "invalid-utf16":b[184]=0;b[185]=0xD8;break;
                case "invalid-source":N(160,3);N(164,9);N(168,0);b.AsSpan(184,4096).Clear();break;
                case "nonexact-image":N(92,6);break;
                case "pool-refused":case "allocation-failed":N(8,0xC000009A);N(88,0xC000009A);b.AsSpan(92).Clear();N(92,scenario=="pool-refused"?2u:3);break;
                case "generation":b[32]^=1;break;case "start":b[56]^=1;break;case "pid":b[48]^=1;break;
                case "event-instance":b[64]^=1;break;case "event-sequence":b[72]^=1;break;
                case "length":N(168,4098);break;case "status":N(92,15);break;
            }
        };
        var subdir=Path.Combine(root,"creation-"+scenario);using var actor2=new WindowsStagedActorStore(subdir,sensor).Capture(e2,wire2.Provider,wire2.Send,health.Add);
        var c2=new ForensicCollector(sensor,subdir);var f2=c2.Complete(e2,actor2,c2.Begin(e2,actor2),new());var p2=f2.Process;
        Check(f2.IsValid()&&actor2.Image!=null&&p2.ThreadToken.Sid=="S-1-5-20",scenario+" metadata outcome retains usable snapshot and operation token");
        var correct=scenario switch{
            "designated-parent"=>p2.ParentPid==200&&p2.ParentStartKey==null&&p2.ParentInstanceId==null&&p2.Creation!.CreatorCreatedFileTime!=null,
            "context-mismatch"=>p2.ParentPid==100&&p2.ParentStartKey==null&&p2.Creation!.CreatorCreatedFileTime==null&&p2.Creation.CreatorStatus.NativeCode==null,
            "lookup-failed"=>p2.ParentStartKey==null&&p2.Creation!.CreatorCreatedFileTime==null&&p2.Creation.CreatorStatus.NativeCode=="0xC0000022",
            "empty"=>p2.CommandLine==""&&p2.CommandLineStatus.State=="captured",
            "absent" or "invalid-utf16" or "invalid-source"=>p2.CommandLine==null&&p2.CommandLineStatus.State=="unavailable",
            "truncated"=>p2.CommandLine?.Length==2048&&p2.CommandLineStatus.State=="partial"&&p2.Creation!.CommandOriginalBytes==6000,
            "surrogate-boundary"=>p2.CommandLine?.Length==2047&&p2.CommandLineStatus.State=="partial"&&p2.Creation!.CommandStoredBytes==4094,
            "nonexact-image"=>p2.Creation is {FileOpenNameAvailable:false,ImageStatus.State:"partial"},
            _=>p2.Creation!.Status.State=="unavailable"&&p2.CommandLine==null&&p2.ParentStartKey==null};
        Check(correct,scenario+" process evidence is truthful and explicitly bounded");
    }
    // Exact same PID, different start/generation/candidate and different command.
    var reusedEvent=Wire.Event(root);var old=reusedEvent.Attribution!.WindowsKernel!;
    reusedEvent=reusedEvent with{Attribution=reusedEvent.Attribution with{WindowsKernel=old with{ProcessCreatedFileTime=old.ProcessCreatedFileTime+1}}};
    var reusedWire=new Wire(reusedEvent,bytes){CreationMetadata=true,CreationCommand="new-process-instance",Generation=77,Candidate=78};
    using(var reused=new WindowsStagedActorStore(creationDirectory,sensor).Capture(reusedEvent,reusedWire.Provider,reusedWire.Send,health.Add))
        Check(reused.Process.CommandLine=="new-process-instance"&&reused.Process.InstanceId!=lease.Process.InstanceId,"PID reuse and same image never borrow earlier command line or instance correlation");
    var proactiveDirectory=Path.Combine(root,"creation-proactive");var pe=Wire.Event(root);var pw=new Wire(pe,bytes){CreationMetadata=true,CreationCommand="proactive-before-any-touch"};
    var pk=pe.Attribution!.WindowsKernel!;var ready=new WindowsReadyActor(pw.Provider,0x40020056,Convert.ToUInt64(pk.Instance,16),1,pw.Generation,pw.Candidate,pk.ProcessId!.Value,pk.ProcessCreatedFileTime!.Value,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
    Check(new WindowsStagedActorStore(proactiveDirectory,sensor).CaptureReady(ready,pw.Send,health.Add)=="captured","proactive creation proof commits before byte acknowledgement");
    pw.EventValue=Wire.Next(pe);pw.GenerationOnly=true;pw.UnavailableBytes=true;
    using(var restored=new WindowsStagedActorStore(proactiveDirectory,sensor).Capture(pw.EventValue,pw.Provider,pw.Send,health.Add))Check(restored.Process.CommandLine=="proactive-before-any-touch"&&restored.Process.Creation!.RawSha256!=null,"restart and native expiry preserve checksummed per-process creation proof");
    var path=Path.Combine(creationDirectory,"kernel-actor-intake",nativeEvent.EventId+".event.json");var original=File.ReadAllText(path);
    var node=System.Text.Json.Nodes.JsonNode.Parse(original)!;node["Creation"]!["Sha256"]=new string('A',64);File.WriteAllText(path,node.ToJsonString());
    using(var corrupt=store.RestoreForDelivery(nativeEvent,health.Add))Check(corrupt!.Image!=null&&corrupt.Process.Creation!.Status.State=="failed"&&corrupt.Process.CommandLine==null&&corrupt.Process.ThreadToken.Sid=="S-1-5-20","corrupt creation proof cannot replace command/parent or discard valid actor bytes and operation tokens");
    File.Move(path,path+".corrupt-retained");File.WriteAllText(path,original);
    foreach(var mutate in new Func<WindowsProcessCreationEvidence,WindowsProcessCreationEvidence>[]{x=>x with{Version=2},x=>x with{CreatorPid=99},x=>x with{CommandStoredBytes=4098},x=>x with{ParentCreatedFileTime=null},x=>x with{RawSha256="bad"}})
        Check(!(f with{Process=f.Process with{Creation=mutate(f.Process.Creation!)}}).IsValid(),"server contract rejects contradictory creation evidence");
    var queue=new EventSpool(Path.Combine(root,"creation-receipt"),sensor);queue.Enqueue(nativeEvent with{Forensics=f});var batch=queue.Peek();
    Reject(()=>queue.Acknowledge(batch,new(1,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=4,ActorAcquisitionVersion=1}),"old receipt cannot discard newly added process-creation evidence");
    Check(queue.Count==1,"process-creation evidence remains queued after unsupported receipt");
    queue.Acknowledge(batch,new(1,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=4,ActorAcquisitionVersion=1,ProcessCreationVersion=1});Check(queue.Count==0,"explicit process-creation receipt releases exact queued event");
    var evidenceReceiver=new EvidenceReceiver(server,Path.Combine(root,"server"));
    var metadata=System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllBytes(Path.Combine(creationDirectory,f.Preservation.ManifestRelativePath!)))!;
    metadata["Process"]!["Creation"]!["CreatorTid"]=999;
    var changed=System.Text.Encoding.UTF8.GetBytes(metadata.ToJsonString());var changedHash=Convert.ToHexString(SHA256.HashData(changed));
    var completionId=Guid.NewGuid().ToString("N");
    var observed=nativeEvent with{Forensics=collect.Begin(nativeEvent,lease)};
    var completion=nativeEvent with{EventId=completionId,Source="Forensic enrichment",Forensics=collect.LinkCompletion(f with{Preservation=f.Preservation with{ManifestSha256=changedHash}},completionId)};
    server.Ingest(sensor,new([observed,completion]));
    try{evidenceReceiver.Start(sensor,new(completionId,Convert.ToBase64String(changed))).GetAwaiter().GetResult();throw new Exception("Changed creator manifest was accepted");}
    catch(EvidenceUploadException ex){Check(ex.Status==422&&ex.Message=="process-creation-manifest-linkage-mismatch","server rejects changed creator evidence even with a recomputed manifest digest");}
}

async Task CheckClientCapability(EventBatch value)
{
    foreach(var creation in new[]{false,true})
    foreach(var mode in new[]{0,1,2})
    {
        var handler=new CapabilityHandler(mode,creation);using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://localhost/")},new string('a',64));
        var rejected=false;try{await client.SendEventsAsync(value);}catch(InvalidDataException){rejected=true;}
        Check(mode==2?!rejected:rejected,"client validates "+(creation?"creation":"acquisition")+" capability and acknowledgement mode "+mode);
        Check(handler.EventPosts==(mode==0?0:1),"unsupported "+(creation?"creation":"acquisition")+" preflight prevents event transmission mode "+mode);
    }
}
async Task CheckHttp(string serverPath)
{
    var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var secret=Store.Secret();
    var start=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(serverPath));
    foreach(var name in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")||k.StartsWith("Forensics__")).ToArray())start.Environment.Remove(name);
    start.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");start.Environment["RF_ADMIN_KEY"]=secret;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["DOTNET_ENVIRONMENT"]="Development";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";start.Environment["Logging__LogLevel__Default"]="Warning";
    using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
    using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
    try
    {
        var ready=false;for(var n=0;n<150;n++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"isolated candidate HTTP server starts");
        var next=Wire.Next(later);wire.EventValue=next;using var acquired=intake.Capture(next,wire.Provider,wire.Send,health.Add);
        var observed=next with{Forensics=collector.Begin(next,acquired)};var enriched=collector.Complete(next,acquired,observed.Forensics!,new());var id=Guid.NewGuid().ToString("N");
        var done=next with{EventId=id,Source="Forensic enrichment",Forensics=collector.LinkCompletion(enriched,id)};var upload=new EvidenceUploadQueue(dir);upload.Register(observed,done);
        using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress,Timeout=TimeSpan.FromSeconds(30)},enrollment.Credential);
        Check(await upload.Pump(client)==1,"actual HTTP client sends new acquisition events, executable and manifest with verified receipt");
        Check(await new EvidenceUploadQueue(dir).Pump(client)==0,"upload restart recognizes acquisition receipt without duplicate transfer");
        using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{enriched.Preservation.EvidenceId}/artifact");request.Headers.Authorization=new("Bearer",secret);
        using var response=await http.SendAsync(request);Check(response.IsSuccessStatusCode&&Convert.ToHexString(SHA256.HashData(await response.Content.ReadAsByteArrayAsync()))==expected,"HTTP server download returns exact operation-bound executable");
        var sourceDir=Path.Combine(root,"http-source-volume");var volumeEvent=Wire.Event(root);var volumeWire=new Wire(volumeEvent,bytes){SourceVolume=true,Generation=91,CreationMetadata=true};
        using var volumeActor=new WindowsStagedActorStore(sourceDir,sensor).Capture(volumeEvent,volumeWire.Provider,volumeWire.Send,health.Add);
        var volumeCollector=new ForensicCollector(sensor,sourceDir);var volumeObserved=volumeEvent with{Forensics=volumeCollector.Begin(volumeEvent,volumeActor)};
        var volumeEnriched=volumeCollector.Complete(volumeEvent,volumeActor,volumeObserved.Forensics!,new());var volumeId=Guid.NewGuid().ToString("N");
        var volumeDone=volumeEvent with{EventId=volumeId,Source="Forensic enrichment",Forensics=volumeCollector.LinkCompletion(volumeEnriched,volumeId)};
        var volumeUpload=new EvidenceUploadQueue(sourceDir);volumeUpload.Register(volumeObserved,volumeDone);
        Check(await volumeUpload.Pump(client)==1,"HTTP server accepts source volume identity with original executable evidence");
        using var volumeRequest=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{volumeEnriched.Preservation.EvidenceId}/manifest");volumeRequest.Headers.Authorization=new("Bearer",secret);
        using var volumeResponse=await http.SendAsync(volumeRequest);Check(volumeResponse.IsSuccessStatusCode,"HTTP server returns source identity manifest");
        using var volumeManifest=JsonDocument.Parse(await volumeResponse.Content.ReadAsByteArrayAsync());
        Check(volumeManifest.RootElement.GetProperty("ActorFile").GetProperty("StableId").GetString()==volumeActor.File.StableId&&volumeManifest.RootElement.GetProperty("ActorAcquisition").GetProperty("SourceIdentityStatus").GetProperty("State").GetString()=="captured","central manifest retains original volume/file index separately from private copy");
        using var volumeArtifactRequest=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{volumeEnriched.Preservation.EvidenceId}/artifact");volumeArtifactRequest.Headers.Authorization=new("Bearer",secret);
        using var volumeArtifactResponse=await http.SendAsync(volumeArtifactRequest);Check(volumeArtifactResponse.IsSuccessStatusCode&&Convert.ToHexString(SHA256.HashData(await volumeArtifactResponse.Content.ReadAsByteArrayAsync()))==expected,"central source-identified executable download retains the exact actor hash");
        var recoveryDir=Path.Combine(root,"http-failed-source-recovery");var recoveryEvent=Wire.Event(root);var recoveryWire=new Wire(recoveryEvent,bytes){SourceVolume=true,Generation=92};
        var recoveryStore=new WindowsStagedActorStore(recoveryDir,sensor);
        using var originallyCaptured=recoveryStore.Capture(recoveryEvent,recoveryWire.Provider,recoveryWire.Send,health.Add);
        var originalId=originallyCaptured.File.StableId;var originalSnapshot=Path.Combine(recoveryDir,"kernel-actor-intake",originallyCaptured.Acquisition!.SnapshotId+".bin");
        originallyCaptured.Dispose();File.Move(originalSnapshot,originalSnapshot+".original");File.WriteAllBytes(originalSnapshot,bytes);
        using var failedActor=recoveryStore.RestoreForDelivery(recoveryEvent,health.Add);
        var failedCollector=new ForensicCollector(sensor,recoveryDir);var failedObserved=recoveryEvent with{Forensics=failedCollector.Begin(recoveryEvent,failedActor!)};
        var failedEnriched=failedCollector.Complete(recoveryEvent,failedActor!,failedObserved.Forensics!,new());var failedId=Guid.NewGuid().ToString("N");
        var failedDone=recoveryEvent with{EventId=failedId,Source="Forensic enrichment",Forensics=failedCollector.LinkCompletion(failedEnriched,failedId)};
        var failedReceipt=await client.SendEventsAsync(new([failedObserved,failedDone]));
        Check(failedReceipt.Accepted==2,"HTTP server accepts failed recovery as evidence events without requiring an artifact");
        using var failedHistoryRequest=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100");failedHistoryRequest.Headers.Authorization=new("Bearer",secret);
        using var failedHistoryResponse=await http.SendAsync(failedHistoryRequest);failedHistoryResponse.EnsureSuccessStatusCode();using var failedHistory=JsonDocument.Parse(await failedHistoryResponse.Content.ReadAsByteArrayAsync());
        var savedFailure=failedHistory.RootElement.GetProperty("items").EnumerateArray().Select(x=>x.GetProperty("event")).Single(x=>x.GetProperty("eventId").GetString()==failedId).GetProperty("forensics");
        var savedCreation=failedHistory.RootElement.GetProperty("items").EnumerateArray().Select(x=>x.GetProperty("event")).Single(x=>x.GetProperty("eventId").GetString()==volumeId).GetProperty("forensics").GetProperty("process");
        Check(savedCreation.GetProperty("commandLine").GetString()==volumeWire.CreationCommand&&savedCreation.GetProperty("creation").GetProperty("creatorPid").GetUInt64()==100&&savedCreation.GetProperty("creation").GetProperty("rawSha256").GetString()==volumeActor.Process.Creation!.RawSha256,"actual server history API retains command line, creator and raw-proof digest");
        var savedExecutable=savedFailure.GetProperty("actorExecutable");var savedAcquisition=savedExecutable.GetProperty("acquisition");
        Check(savedExecutable.GetProperty("file").GetProperty("stableId").GetString()==originalId&&savedAcquisition.GetProperty("snapshotSha256").GetString()==expected&&savedAcquisition.GetProperty("recoveryStatus").GetProperty("state").GetString()=="failed","server history retains original executable identity and historical hash with explicit recovery failure");
        Check(savedExecutable.GetProperty("sha256").ValueKind==JsonValueKind.Null&&savedFailure.GetProperty("preservation").GetProperty("status").GetProperty("state").GetString()!="captured"&&savedFailure.GetProperty("process").GetProperty("threadToken").GetProperty("sid").GetString()=="S-1-5-20","server history retains actor token without inventing current hash or preservation success");
        var extended=JsonSerializer.Deserialize<AgentEvent>(File.ReadAllBytes(Path.Combine(root,"context-v5-input.json")))!;
        var extendedReceipt=await client.SendEventsAsync(new([extended]));
        Check(extendedReceipt.Accepted==1&&extendedReceipt.WindowsKernelVersion>=5,"actual HTTP capabilities and receipt acknowledge extended thread-owner evidence");
        using var extendedRequest=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100");extendedRequest.Headers.Authorization=new("Bearer",secret);
        using var extendedResponse=await http.SendAsync(extendedRequest);extendedResponse.EnsureSuccessStatusCode();using var extendedHistory=JsonDocument.Parse(await extendedResponse.Content.ReadAsByteArrayAsync());
        var savedContext=extendedHistory.RootElement.GetProperty("items").EnumerateArray().Single(x=>x.GetProperty("event").GetProperty("eventId").GetString()==extended.EventId).GetProperty("event").GetProperty("attribution").GetProperty("windowsKernel");
        Check(savedContext.GetProperty("version").GetInt32()==5&&savedContext.GetProperty("threadOwnerPrimary").GetProperty("sid").GetString()=="S-1-5-18"&&savedContext.GetProperty("threadEffective").GetProperty("sid").GetString()=="S-1-5-20","actual database and history API retain separate owner and impersonation snapshots");
    }
    finally{if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"http-server.log"),await stdout+await stderr);}
}

sealed class CapabilityHandler(int mode,bool creation):HttpMessageHandler
{
    internal int EventPosts;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
    {
        bool capability=request.RequestUri!.AbsolutePath.EndsWith("capabilities");if(!capability)EventPosts++;
        var supported=capability?(mode>0?1:0):(mode==2?1:0);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(new{Accepted=2,Duplicates=0,AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,ForensicsVersion=1,WindowsKernelVersion=4,ProcessCreationVersion=creation?supported:1,ActorAcquisitionVersion=creation?1:supported})});
    }
}
sealed class Wire(AgentEvent e,byte[] bytes)
{
    internal static byte[] RawRecord(string root)
    {
        var raw=new byte[WindowsKernelDecoder.EventBytes];var now=DateTimeOffset.UtcNow;
        void N(int offset,uint value)=>System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(offset),value);
        void Q(int offset,ulong value)=>System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(offset),value);
        void Token(int offset,string value,uint type)
        {
            var sid=new System.Security.Principal.SecurityIdentifier(value);var bytes=new byte[sid.BinaryLength];sid.GetBinaryForm(bytes,0);
            N(offset,31);N(offset+24,(uint)bytes.Length);N(offset+32,8192);N(offset+40,type);N(offset+44,type==2?2u:0);
            Q(offset+48,1);Q(offset+56,2);Q(offset+64,3);bytes.CopyTo(raw,offset+72);
        }
        N(0,4);N(4,(uint)raw.Length);Q(8,0x0123456789ABCDEF);Q(16,1);Q(24,(ulong)now.ToFileTime());Q(32,(ulong)now.ToFileTime());Q(40,(ulong)now.AddMinutes(-1).ToFileTime());
        Q(48,123456);Q(56,77);Q(64,1);N(76,3);
        System.Text.Encoding.Unicode.GetBytes(Path.Combine(root,"untouched-crash-target")).CopyTo(raw,240);
        System.Text.Encoding.Unicode.GetBytes(Path.Combine(root,"missing-crash-actor.exe")).CopyTo(raw,1776);
        N(3312,2);N(3316,2);Token(3320,"S-1-5-18",1);Token(3464,"S-1-5-20",2);Token(3608,"S-1-5-18",1);N(3760,1);N(3768,1);N(3772,1);N(3780,123456);
        Q(3784,(ulong)Stopwatch.GetTimestamp());Q(3792,(ulong)Stopwatch.Frequency);return raw;
    }
    internal static readonly Guid VolumeGuid=new("d030bd8d-5362-4de8-a190-b13927870027");
    internal AgentEvent EventValue=e;internal string Provider="11111111222233334444555555555555";internal ulong Generation=11,Candidate=42;internal int Acks,MetadataReads;internal bool UnavailableBytes,MissingBinding,GenerationOnly,SourceVolume,Exited=true;internal string? CorruptChunk;
    internal bool CreationMetadata;internal string? CreationCommand="renamed.exe --test creation";internal Action<byte[]>? CreationMutation;
    internal static AgentEvent Next(AgentEvent e)=>e with{EventId=Guid.NewGuid().ToString("N"),Attribution=e.Attribution! with{WindowsKernel=e.Attribution.WindowsKernel! with{Sequence=e.Attribution.WindowsKernel!.Sequence+1}}};
    internal static AgentEvent Event(string root)
    {
        WindowsTokenSnapshot Token(string sid,uint type)=>new(){Captured=31,Sid=sid,TokenId="0000000000000001",AuthenticationId="0000000000000002",ModifiedId="0000000000000003",Type=type,SessionId=0,IntegrityRid=8192,Elevated=false,QueryStatus=Enumerable.Repeat("0x00000000",5).ToArray()};
        var k=new WindowsKernelEvidence{Instance="0123456789ABCDEF",Sequence=1,Major=3,ProcessId=123456,ThreadId=77,ProcessCreatedFileTime=DateTimeOffset.UtcNow.AddMinutes(-1).ToFileTime(),CompletedUtc=DateTimeOffset.UtcNow,MonotonicTicks=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency,NativePath=Path.Combine(root,"untouched-target"),NameSource="normalized",NormalizedNameStatus="0x00000000",SubjectSource="request-thread-snapshot",ThreadImpersonating=true,ThreadEffective=Token("S-1-5-20",2),CreateAuthorization=Token("S-1-5-18",1),RequestorPrimary=Token("S-1-5-18",1)};
        return new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)",k.NativePath,"S-1-5-20",Path.Combine(root,"nonexistent-original","renamed.exe"),k.ProcessId,"Windows minifilter"){Attribution=new(){Provider="Windows minifilter",UserSid="S-1-5-20",EventTimeCredentials=true,CompleteRecordSet=true,WindowsKernel=k}};
    }
    private readonly long copyTime=DateTimeOffset.UtcNow.ToFileTime();
    internal byte[] Send(byte[] request,int length)
    {
        var k=EventValue.Attribution!.WindowsKernel!;var command=WindowsStagedActorProtocol.U32(request,4);var b=new byte[length];
        void P(int o,ulong v)=>WindowsStagedActorProtocol.Put(b,o,v);void N(int o,uint v)=>WindowsStagedActorProtocol.Put32(b,o,v);
        if(command==21)
        {
            if(request.Length!=160||length!=160||WindowsStagedActorProtocol.U32(request,68)!=2||WindowsStagedActorProtocol.U64(request,24)!=Generation||WindowsStagedActorProtocol.U64(request,32)!=Candidate||WindowsStagedActorProtocol.U64(request,40)!=(ulong)k.ProcessId!||WindowsStagedActorProtocol.U64(request,48)!=(ulong)k.ProcessCreatedFileTime!||Convert.ToHexString(request.AsSpan(8,16))!=Provider||!request.AsSpan(80,32).SequenceEqual(SHA256.HashData(bytes)))throw new Exception("Invalid synthetic durable receipt");
            Acks++;return request.ToArray();
        }
        if(command==18)
        {
            if(!request.AsSpan().SequenceEqual(WindowsStagedActorProtocol.CompanionRequest(EventValue,Provider)))throw new Exception("Wrong companion request");
            N(0,GenerationOnly?2u:1);N(4,88);N(8,MissingBinding?0u:GenerationOnly?2u:1);N(12,MissingBinding||GenerationOnly?0xC0000225:0);Convert.FromHexString(Provider).CopyTo(b,16);if(!MissingBinding){P(32,Generation);P(40,Candidate);P(48,(ulong)k.ProcessId!);P(56,(ulong)k.ProcessCreatedFileTime!);}N(64,0x40020056);N(68,MissingBinding?1u:GenerationOnly?4u:0);P(72,Convert.ToUInt64(k.Instance,16));P(80,(ulong)k.Sequence);return b;
        }
        if(command is not (19 or 22)||WindowsStagedActorProtocol.U32(request,68)!=(command==22?3u:1u)||Convert.ToHexString(request.AsSpan(8,16))!=Provider||WindowsStagedActorProtocol.U64(request,24)!=Generation||WindowsStagedActorProtocol.U64(request,32)!=Candidate||WindowsStagedActorProtocol.U64(request,40)!=(ulong)k.ProcessId!||WindowsStagedActorProtocol.U64(request,48)!=(ulong)k.ProcessCreatedFileTime!)throw new Exception("Wrong candidate request");
        if(command==22&&(request.Length!=88||WindowsStagedActorProtocol.U64(request,72)!=Convert.ToUInt64(k.Instance,16)||WindowsStagedActorProtocol.U64(request,80)!=(ulong)k.Sequence))throw new Exception("Wrong operation pin request");
        var operation=WindowsStagedActorProtocol.U32(request,64);if(operation==11){Acks++;return b;}if(UnavailableBytes)throw new COMException("Candidate expired",unchecked((int)0x80070490));if(operation==13)MetadataReads++;
        if(operation==27)
        {
            if(!CreationMetadata)throw new COMException("Legacy provider has no process metadata operation",unchecked((int)0x80070057));
            if(length!=5304)throw new Exception("Wrong process creation reply size");
            N(0,1);N(4,5304);Convert.FromHexString(Provider).CopyTo(b,16);P(32,Generation);P(40,Candidate);P(48,(ulong)k.ProcessId!);P(56,(ulong)k.ProcessCreatedFileTime!);
            if(command==22){P(64,Convert.ToUInt64(k.Instance,16));P(72,(ulong)k.Sequence);}
            N(80,1);N(84,5224);N(92,7);P(96,100);P(104,100);P(112,101);P(120,(ulong)copyTime-10000000);P(128,(ulong)copyTime-10000000);P(136,(ulong)copyTime);P(144,12345);
            if(CreationCommand!=null){var text=System.Text.Encoding.Unicode.GetBytes(CreationCommand);var used=Math.Min(text.Length,4096);if(used<text.Length&&used>0&&char.IsHighSurrogate(CreationCommand[used/2-1]))used-=2;N(160,text.Length>used?2u:1);N(164,(uint)text.Length);N(168,(uint)used);text.AsSpan(0,used).CopyTo(b.AsSpan(184));}
            var image=System.Text.Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume3\renamed.exe");N(172,1);N(176,(uint)image.Length);N(180,(uint)image.Length);image.CopyTo(b,4280);
            CreationMutation?.Invoke(b);return b;
        }
        if(operation==26)
        {
            if(!SourceVolume)throw new COMException("Legacy provider has no source-volume operation",unchecked((int)0x80070057));
            if(length!=224)throw new Exception("Wrong source identity reply size");
            N(0,1);N(4,224);N(12,1);Convert.FromHexString(Provider).CopyTo(b,16);P(32,Generation);P(40,Candidate);P(48,(ulong)k.ProcessId!);P(56,(ulong)k.ProcessCreatedFileTime!);P(64,1234);
            var volume=System.Text.Encoding.Unicode.GetBytes(@"\??\Volume{"+VolumeGuid.ToString("D")+"}");volume.CopyTo(b,72);N(200,(uint)volume.Length);
            if(command==22){P(208,Convert.ToUInt64(k.Instance,16));P(216,(ulong)k.Sequence);}return b;
        }
        var offset=WindowsStagedActorProtocol.U32(request,56);var count=WindowsStagedActorProtocol.U32(request,60);
        N(0,3);N(4,144);N(8,(uint)bytes.Length);N(12,offset);N(16,count);N(20,Exited?15u:13u);N(28,0x100021);P(32,Candidate);P(40,(ulong)k.ProcessId!);P(48,(ulong)k.ProcessCreatedFileTime!);P(56,1234);P(64,(ulong)copyTime);P(72,(ulong)copyTime);P(80,(ulong)copyTime);P(88,(ulong)copyTime);P(96,(ulong)copyTime);N(104,0x80000020);N(108,2);Convert.FromHexString(Provider).CopyTo(b,120);P(136,Generation);
        if(count>0){bytes.AsSpan((int)offset,(int)count).CopyTo(b.AsSpan(144));if(CorruptChunk is {} wrong)b[wrong switch{"provider"=>120,"generation"=>136,"candidate"=>32,"pid"=>40,"start"=>48,"size"=>8,_=>72}]^=1;}return b;
    }
}
