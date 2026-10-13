using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

if(args.Length is not (2 or 3)||args.Length==3&&args[2] is not ("--pinned-delay" or "--proactive" or "--designated-parent"))throw new ArgumentException("Pass isolated server DLL and native captured events.jsonl; optional --pinned-delay, --proactive or --designated-parent for a dedicated fixture");
var pinnedDelay=args.Length==3&&args[2]=="--pinned-delay";
var proactive=args.Length==3&&args[2]=="--proactive";
var designatedParent=args.Length==3&&args[2]=="--designated-parent";
var dedicated=pinnedDelay||proactive||designatedParent;
if(dedicated)
{
    using var receipt=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(Path.GetFullPath(args[1])))!,"RESULTS.json")));
    var r=receipt.RootElement;
    if(!r.GetProperty("AccountingPassed").GetBoolean())throw new InvalidDataException("Successful dedicated native receipt required");
    if(pinnedDelay&&(r.GetProperty("Schema").GetString()!="sequester.windows-pinned-actor-delay/v1"||r.GetProperty("DelaySeconds").GetInt32()!=36))throw new InvalidDataException("Successful dedicated native delay receipt required");
    if(proactive&&(r.GetProperty("Schema").GetString()!="sequester.windows-proactive-acquisition-native/v1"||r.GetProperty("Children").GetInt32()!=1||r.GetProperty("Matches").GetInt32()!=1||!r.GetProperty("AllChildrenObserved").GetBoolean()))throw new InvalidDataException("Successful dedicated proactive acquisition receipt required");
    if(designatedParent&&(r.GetProperty("Schema").GetString()!="sequester.windows-designated-parent-native/v1"||r.GetProperty("Children").GetInt32()!=1||r.GetProperty("Matches").GetInt32()!=1||!r.GetProperty("AllChildrenObserved").GetBoolean()||r.GetProperty("DesignatedParentPid").GetInt32()==r.GetProperty("CreatorPid").GetInt32()))throw new InvalidDataException("Successful real designated-parent receipt required");
}
var root=Path.Combine(@"D:\Codex\RansomFree\windows-token-20260930","integration-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool ok,string text){if(!ok)throw new Exception(text);checks.Add(text);Console.WriteLine("PASS: "+text);}
var store=new Store(Path.Combine(root,"server"));var enrolled=store.Enroll(new(store.CreateCode().Code,"SQ-KERNEL-TEST native replay","kernel-qa"))!;
var native=File.ReadLines(args[1]).Select(line=>JsonSerializer.Deserialize<AgentEvent>(line)!).ToArray();
var staged=native.Any(e=>e.Forensics?.ActorExecutable.Acquisition!=null);
var creation=native.Any(e=>e.Forensics?.Process.Creation!=null);
var events=native.Select(e=>e with{Forensics=e.Forensics! with{SensorId=enrolled.EndpointId}}).ToArray();
Check(events.Length>0&&events.All(e=>e.Attribution!.IsValid()&&e.Forensics!.IsValid()&&WindowsKernelEvidence.Matches(e)),"native token envelopes satisfy versioned bounded contracts");
var originals=events.Where(e=>e.Source=="Windows minifilter").ToArray();
if(!dedicated)Check(originals.Any(e=>e.Attribution!.OsStatus=="0xC0000022"&&EventActivity.From(e).Outcome=="failed"),"native denied open remains failed in shared action projection");
else Check(originals.Any(e=>e.Attribution!.WindowsKernel!.Major==3&&e.Attribution.WindowsKernel.ThreadImpersonating==true),"dedicated native input contains an actual impersonated read; denied-open coverage is outside this fixture");
if(designatedParent)Check(originals.Any(e=>e.Forensics?.Process is {Creation:{CreatorPid:>0,ReportedParentPid:>0} c,ParentInstanceId:null,ParentStartedUtc:null,ParentStartKey:null,ParentStatus.Reason:"creation-designated-parent-instance-unavailable"}&&c.CreatorPid!=c.ReportedParentPid),"designated-parent evidence separates creator from parent and preserves unavailable parent instance");
var sample=originals.First();var spool=new EventSpool(Path.Combine(root,"spool"),enrolled.EndpointId);spool.Enqueue(sample);
var requiredKernelVersion=WindowsKernelEvidence.RequiredVersion(events);
try{spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,ForensicsVersion=1});throw new Exception("Legacy receipt accepted");}catch(InvalidDataException){Check(spool.Count==1,"legacy receipt cannot discard accessing-thread token evidence");}
if(requiredKernelVersion==5){try{spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=4,ActorAcquisitionVersion=staged?1:0,ProcessCreationVersion=creation?1:0});throw new Exception("Version 4 receipt accepted extended context");}catch(InvalidDataException){Check(spool.Count==1,"version 4 receipt cannot discard extended thread-owner context");}}
spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,ForensicsVersion=1,WindowsKernelVersion=requiredKernelVersion,ActorAcquisitionVersion=staged?1:0,ProcessCreationVersion=creation?1:0});Check(spool.Count==0,"kernel/acquisition/creation-aware receipt drains exact durable event");
try{spool.Enqueue(sample with{ProcessId=sample.ProcessId+1});throw new Exception("Contradictory PID accepted");}catch(ArgumentException){Check(true,"top-level PID cannot contradict kernel PID");}
Check(!(sample.Attribution!.WindowsKernel! with{ThreadEffective=null!}).IsValid(),"null token snapshot rejected safely");
Check(!(sample.Attribution.WindowsKernel.ThreadEffective with{QueryStatus=null!}).IsValid(),"null query status rejected safely");
Check(!WindowsKernelEvidence.Matches(sample with{Attribution=sample.Attribution with{UserSid="S-1-5-7"}}),"top-level user SID cannot contradict authorization evidence");
foreach(var e in originals){using var lease=ActorLease.Capture(e,enrolled.EndpointId);var k=e.Attribution!.WindowsKernel!;Check(lease.Process.EventSubject.Sid==k.Subject.Sid&&lease.Process.Owner.Sid==k.RequestorPrimary.Sid&&lease.Process.EffectiveThreadContext!.TokenId==k.ThreadEffective.TokenId&&lease.Process.ThreadId==k.ThreadId,"kernel token evidence survives later process unavailability: "+k.Sequence);}
WindowsKernelSource.SavePrepared(root,sample);var restored=WindowsKernelSource.RestorePrepared(root,sample.EventId)!;
Check(JsonSerializer.Serialize(restored)==JsonSerializer.Serialize(sample),"prepared original survives restart byte-for-byte at event serialization boundary");
Check(JsonSerializer.Serialize(WindowsKernelSource.ForDelivery(root,sample with{User="renamed account",Path=@"Z:\different-mount"}))==JsonSerializer.Serialize(sample),"retry retains the original account label and path after account/mount changes");
Check(WindowsKernelSource.IsOwnProcess(sample,sample.ProcessId!.Value,sample.Attribution!.WindowsKernel!.ProcessCreatedFileTime!.Value)&&!WindowsKernelSource.IsOwnProcess(sample,sample.ProcessId.Value,sample.Attribution.WindowsKernel.ProcessCreatedFileTime.Value+1),"sensor PID reuse never drops a different process lifetime");
try{WindowsKernelSource.SavePrepared(root,sample with{User="different"});throw new Exception("Prepared evidence overwritten");}catch(InvalidDataException){Check(true,"prepared event cannot be silently replaced");}
var checkpoint=new WindowsKernelCheckpoint(Path.Combine(root,"kernel-checkpoint.json"));
Check(checkpoint.Observe("0000000000000001",50)==null,"first provider checkpoint records ordering");
Check(new WindowsKernelCheckpoint(Path.Combine(root,"kernel-checkpoint.json")).Observe("0000000000000001",51)==null,"consumer restart preserves provider continuity checkpoint");
Check(checkpoint.Observe("0000000000000002",1)?.Contains("coverage gap")==true,"driver reload exposes unquantified coverage gap");
Check(checkpoint.Observe("0000000000000002",0)?.Contains("coverage gap")==true,"same-instance ordering reset is not silently accepted");
var rawFile=Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(args[1]))!,"lifecycle","before-disconnect.record");
if(!staged){var raw=File.ReadAllBytes(rawFile);var decoded=WindowsKernelDecoder.Decode(raw,enrolled.EndpointId,p=>p);
Check(decoded.Attribution!.WindowsKernel!.ThreadProcessId>0,"native binary includes thread creating-process identity");
System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(raw.AsSpan(32),decoded.ObservedUtc.AddMinutes(-1).ToFileTime());
Check(WindowsKernelDecoder.Decode(raw,enrolled.EndpointId,p=>p).Attribution!.WindowsKernel!.CompletedUtc<decoded.ObservedUtc,"wall-clock rollback retains event and native ordering");
System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(3464),30);
Check(WindowsKernelDecoder.Decode(raw,enrolled.EndpointId,p=>p).Attribution is {CompleteRecordSet:false,Level:"Partial attribution"},"failed thread SID collection stays explicit partial evidence");
}else Check(originals.All(e=>e.Forensics?.ActorExecutable.Acquisition!=null),"every staged native observation carries acquisition success or explicit unavailable state");
var now=DateTimeOffset.UtcNow;var trusted=originals.First(e=>e.Attribution!.WindowsKernel!.Major==3) with{ObservedUtc=now,Forensics=null};
var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account-and-process",["read"],"log-only",now.AddMinutes(-1),now.AddHours(1)){
 Name="Kernel token whitelist fixture",Enabled=true,OperatingSystem="windows",Authority="QA",AccountKind="sid",AccountId=trusted.Attribution!.UserSid,Executable=trusted.Process,ProcessMatch="event-path"};
store.InitializeTrustStorage();store.PublishTrustPolicy(new(0,"enforce",[rule],[],"unused"),"qa");
Directory.CreateDirectory(Path.Combine(root,"trust"));var trustCache=new TrustPolicyCache(Path.Combine(root,"trust"),enrolled.EndpointId,"https://qa.invalid");trustCache.Save(store.TrustAssignment(enrolled.EndpointId),DateTimeOffset.UtcNow);
var actor=new TrustActor("QA",rule.AccountId,rule.Executable,Verified:true,AccountKind:"sid");
var trust=TrustEventEvaluation.Evaluate(trustCache,enrolled.EndpointId,null,"windows",trusted,actor,DateTimeOffset.UtcNow);trusted=trusted with{Trust=trust};
var trustedStored=new StoredEvent(1,enrolled.EndpointId,DateTimeOffset.UtcNow,trusted);
Check(trust.Result.Decision.LogOnly&&store.ClassifyTrust(trustedStored)==TrustEventClassification.LogOnly,"server independently validates kernel user/process/action whitelist");
Check(store.ClassifyTrust(trustedStored with{Event=trusted with{Process=@"C:\renamed-malware.exe"}})==TrustEventClassification.PolicyUnknown,"kernel whitelist cannot hide a mismatched executable");
Check(store.ClassifyTrust(trustedStored with{Event=trusted with{Attribution=trusted.Attribution! with{CompleteRecordSet=false}}})==TrustEventClassification.PolicyUnknown,"partial kernel identity cannot suppress alerts");
if(staged)
{
    var observed=originals.First(e=>e.Attribution!.WindowsKernel!.Major==3&&e.Attribution.CompleteRecordSet&&e.Forensics?.ActorExecutable.Acquisition?.Status.State=="captured");
    var acquisition=observed.Forensics!.ActorExecutable.Acquisition!;
    var pinnedRule=rule with{Id=Guid.NewGuid().ToString("N"),Name="Native snapshot SHA-256 whitelist",Executable=observed.Process,AccountId=observed.Attribution!.UserSid,Sha256=acquisition.SnapshotSha256,ProcessMatch=null,StartsUtc=observed.ObservedUtc.AddMinutes(-1)};
    var current=store.TrustAssignment(enrolled.EndpointId).Policy;store.PublishTrustPolicy(new(current.Revision,"enforce",[pinnedRule],[],"unused"),"qa");trustCache.Save(store.TrustAssignment(enrolled.EndpointId),DateTimeOffset.UtcNow);
    var pinned=TrustEventEvaluation.Evaluate(trustCache,enrolled.EndpointId,null,"windows",observed,new("QA",pinnedRule.AccountId,observed.Process,acquisition.SnapshotSha256,Verified:true,AccountKind:"sid"),DateTimeOffset.UtcNow,"windows-operation-bound-snapshot-v1",DateTimeOffset.FromFileTime(acquisition.ProcessCreatedFileTime!.Value),acquisition.PersistedUtc);
    var pinnedEvent=observed with{Trust=pinned};var saved=new StoredEvent(1,enrolled.EndpointId,DateTimeOffset.UtcNow,pinnedEvent);
    Check(pinned.Result.Decision.LogOnly&&store.ClassifyTrust(saved)==TrustEventClassification.LogOnly,"server accepts native actor snapshot SHA-256 whitelist with exact operation linkage");
    Check(store.ClassifyTrust(saved with{Event=pinnedEvent with{Trust=pinned with{Actor=pinned.Actor with{Sha256=new string('0',64)}}}})==TrustEventClassification.PolicyUnknown,"native filename match cannot conceal a contradictory executable hash");
    Check(store.ClassifyTrust(saved with{Event=pinnedEvent with{Forensics=null}})==TrustEventClassification.PolicyUnknown,"native hash whitelist requires its forensic acquisition evidence");
}
var listen=new TcpListener(IPAddress.Loopback,0);listen.Start();var port=((IPEndPoint)listen.LocalEndpoint).Port;listen.Stop();var secret=Store.Secret();
var psi=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};psi.ArgumentList.Add(Path.GetFullPath(args[0]));
foreach(var name in psi.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())psi.Environment.Remove(name);
psi.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");psi.Environment["RF_ADMIN_KEY"]=secret;psi.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";psi.Environment["ASPNETCORE_ENVIRONMENT"]="Development";psi.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";psi.Environment["Database__Provider"]="Sqlite";
using var process=Process.Start(psi)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
try{
 var ready=false;for(var i=0;i<150;i++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"isolated packaged server starts");
 using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},enrolled.Credential);
 foreach(var e in events)spool.Enqueue(e);
 while(spool.Count>0){var batch=spool.Peek();var receipt=await client.SendEventsAsync(batch);Check(receipt.Accepted==batch.Events.Length&&receipt.WindowsKernelVersion>=WindowsKernelEvidence.RequiredVersion(batch.Events)&&(!staged||receipt.ActorAcquisitionVersion==1)&&(!creation||receipt.ProcessCreationVersion==1),"authenticated HTTP accepts bounded spool batches of native token/acquisition/creation fields");spool.Acknowledge(batch,receipt);}
 var persisted=store.Events(0,500);Check(persisted.Count==events.Length,"all native observations and forensic completions persisted");
 foreach(var e in events){var actual=persisted.Single(x=>x.Event.EventId==e.EventId).Event;Check(JsonSerializer.Serialize(actual.Attribution!.WindowsKernel)==JsonSerializer.Serialize(e.Attribution!.WindowsKernel),"all collected token snapshots and raw-frame hashes survive DB persistence: "+e.EventId);}
 if(staged)foreach(var e in events){var actual=persisted.Single(x=>x.Event.EventId==e.EventId).Event;Check(JsonSerializer.Serialize(actual.Forensics!.ActorExecutable.Acquisition)==JsonSerializer.Serialize(e.Forensics!.ActorExecutable.Acquisition),"full acquisition provenance survives DB persistence: "+e.EventId);}
 if(creation)foreach(var e in events){var actual=persisted.Single(x=>x.Event.EventId==e.EventId).Event;Check(JsonSerializer.Serialize(actual.Forensics!.Process)==JsonSerializer.Serialize(e.Forensics!.Process),"full process creation/command/parent evidence survives DB persistence: "+e.EventId);}
 // Transfer the actual native artifacts, including completions whose optional
 // metadata was deferred. Keep the downloaded capture immutable.
 var transferRoot=Path.Combine(root,"native-transfer");Directory.CreateDirectory(Path.Combine(transferRoot,"evidence","actors"));
 var upload=new EvidenceUploadQueue(transferRoot);
 var preserved=events.Where(e=>e.Source=="Forensic enrichment"&&e.Forensics!.Preservation.Status.State=="captured").ToArray();
 foreach(var completion in preserved)
 {
  var p=completion.Forensics!.Preservation;var original=originals.Single(e=>e.EventId==p.SourceEventId);
  foreach(var item in new[]{(p.ArtifactRelativePath,".bin",p.Sha256),(p.ManifestRelativePath,".json",p.ManifestSha256)})
  {
   if(item.Item1?.Replace('\\','/')!="evidence/actors/"+p.EvidenceId+item.Item2)throw new InvalidDataException("Unexpected native artifact path");
   var bytes=File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(args[1])!,item.Item1));
   Check(Convert.ToHexString(SHA256.HashData(bytes))==item.Item3,"native transfer source hash verified: "+p.EvidenceId+item.Item2);
   File.WriteAllBytes(Path.Combine(transferRoot,"evidence","actors",p.EvidenceId+item.Item2),bytes);
  }
  upload.Register(original,completion);
 }
 var received=0;
 for(var attempt=0;received<preserved.Length&&attempt<20;attempt++)received+=await upload.Pump(client);
 Check(received==preserved.Length&&received>0,"all native actor copies reach committed central receipts");
 foreach(var completion in preserved)
 {
  var p=completion.Forensics!.Preservation;
  foreach(var item in new[]{("artifact",p.Sha256),("manifest",p.ManifestSha256)})
  {
   using var download=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{enrolled.EndpointId}/{p.EvidenceId}/{item.Item1}");download.Headers.Authorization=new("Bearer",secret);
   using var downloaded=await http.SendAsync(download);downloaded.EnsureSuccessStatusCode();
   Check(Convert.ToHexString(SHA256.HashData(await downloaded.Content.ReadAsByteArrayAsync()))==item.Item2,"independent central download matches native "+item.Item1+": "+p.EvidenceId);
  }
 }
 using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500");request.Headers.Authorization=new("Bearer",secret);
 using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();using var body=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
 Check(body.RootElement.GetProperty("items").EnumerateArray().Any(x=>x.GetProperty("event").GetProperty("attribution").TryGetProperty("windowsKernel",out var token)&&token.GetProperty("threadId").GetUInt32()>0),"server history API exposes accessing thread and token details");
 if(creation)Check(body.RootElement.GetProperty("items").GetArrayLength()==events.Length+preserved.Length,"history API returns every native event and server-created transfer receipt in this bounded run");
 if(creation)foreach(var row in body.RootElement.GetProperty("items").EnumerateArray()){
  var actual=row.GetProperty("event").Deserialize<AgentEvent>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
  var sourceId=actual.Forensics!.Transfer?.CompletionEventId??actual.EventId;var expectedEvent=events.Single(e=>e.EventId==sourceId);
  Check(JsonSerializer.Serialize(actual.Forensics!.Process)==JsonSerializer.Serialize(expectedEvent.Forensics!.Process),"history API retains native creation evidence exactly: "+actual.EventId);
 }
 using var deniedFilter=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100&action=Access%20Denied");deniedFilter.Headers.Authorization=new("Bearer",secret);
 using var deniedResponse=await http.SendAsync(deniedFilter);deniedResponse.EnsureSuccessStatusCode();using var deniedBody=JsonDocument.Parse(await deniedResponse.Content.ReadAsStringAsync());
 var deniedRows=deniedBody.RootElement.GetProperty("items").EnumerateArray().ToArray();
 Check(deniedRows.Length==originals.Count(e=>e.Attribution!.OsStatus=="0xC0000022")&&deniedRows.All(x=>x.GetProperty("event").GetProperty("attribution").GetProperty("outcome").GetString()=="Failed"),"SQL denied-action filter returns all native denials without presenting completed I/O");
 using var deniedReq=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events"){Content=JsonContent.Create(new EventBatch([sample with{EventId=Guid.NewGuid().ToString("N"),ProcessId=sample.ProcessId+1,Forensics=null}]))};deniedReq.Headers.Authorization=new("Bearer",enrolled.Credential);
 using var rejected=await http.SendAsync(deniedReq);Check(rejected.StatusCode==HttpStatusCode.BadRequest,"HTTP rejects contradictory kernel attribution");
 File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Checks=checks.Count,Passed=true,Mode=pinnedDelay?"pinned-delay":proactive?"proactive":designatedParent?"designated-parent":"operation-matrix",DeniedOpenCoverageIncluded=!dedicated,NativeEvents=originals.Length,TotalEvents=events.Length,NativeArtifactPairs=preserved.Length,Input=Path.GetFullPath(args[1]),Scope="Captured isolated-VM evidence through actual HTTP, database, native binary/manifest uploads and independently hashed downloads; not production deployment",ChecksPassed=checks}));
 Console.WriteLine("PASS: "+checks.Count+" checks; "+root);
}finally{if(!process.HasExited)process.Kill(entireProcessTree:true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr.txt"),await stderr);}
