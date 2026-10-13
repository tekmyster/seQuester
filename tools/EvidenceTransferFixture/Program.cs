using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

var uiSeed=args.Length==2&&args[0]=="--ui-seed";
if(args.Length!=1&&!uiSeed)throw new ArgumentException("Pass the isolated candidate server DLL/executable, or --ui-seed with an isolated preview directory.");
var root=uiSeed?Path.GetFullPath(args[1]):Path.Combine(Environment.GetEnvironmentVariable("SEQUESTER_TRANSFER_FIXTURE_ROOT")??(OperatingSystem.IsWindows()?@"D:\Codex\RansomFree\forensic-gaps-20260925":"/var/tmp/sequester-transfer-qa"),"fixture-"+Guid.NewGuid().ToString("N"));
if(uiSeed&&(!root.StartsWith(@"D:\Codex\RansomFree\forensic-gaps-20260925\preview-",StringComparison.OrdinalIgnoreCase)||!File.Exists(Path.Combine(root,"management.db"))))throw new ArgumentException("Only an existing isolated transfer preview is allowed.");
Directory.CreateDirectory(root);
var serverRoot=uiSeed?root:Path.Combine(root,"server");var store=new Store(serverRoot);
var first=store.Enroll(new(store.CreateCode().Code,uiSeed?"QA-Upload":"transfer-qa","fixture"))!;var second=store.Enroll(new(store.CreateCode().Code,"other-qa","fixture"))!;
var checks=new List<string>();void Check(bool ok,string text){if(!ok)throw new Exception(text);checks.Add(text);Console.WriteLine("PASS: "+text);}
async Task Reject(Func<Task> call,int status,string label){try{await call();throw new Exception("Not rejected: "+label);}catch(EvidenceUploadException ex){Check(ex.Status==status,label+" "+ex.Message);}}
string Id()=>Guid.NewGuid().ToString("N");
(AgentEvent Original,AgentEvent Completed,byte[] Bytes,byte[] Manifest) Evidence(string sensor,int size=700000,string? evidenceId=null)
{
    var bytes=RandomNumberGenerator.GetBytes(size);var hash=Convert.ToHexString(SHA256.HashData(bytes));var time=DateTimeOffset.UtcNow;
    var original=new AgentEvent(Id(),time,"Content read (copy possible)",@"C:\fixture\canary.txt","fixture-user",@"C:\fixture\actor.exe",1234,"Windows audit 4663");
    var f=new ForensicEvidence{EventId=original.EventId,SensorId=sensor,CollectorEpoch=Id(),CollectorSequence=1,MonotonicTicks=1,MonotonicFrequency=Stopwatch.Frequency,ObservedUtc=time,CapturedUtc=time,Process=new(){Pid=1234,InstanceId=hash,ExecutablePath=original.Process},Observation=new(){Path=original.Path,Actions=["read"]},ActorExecutable=new(){ObservedPath=original.Process,Sha256=hash,HashStatus=EvidenceStatus.Captured("synthetic-fixture"),File=new(){Size=size,StableId="fixture:1",Status=EvidenceStatus.Captured("synthetic-fixture")}}};
    original=original with{Forensics=f};
    var p=new PreservationEvidence{EvidenceId=evidenceId??Id(),SourceEventId=original.EventId,ProcessInstanceId=hash,OriginalPath=original.Process,Sha256=hash,Size=size,PreservedUtc=time,HashMatched=true,Status=EvidenceStatus.Captured("actor-copy-hash-verified")};
    var manifest=JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,Preservation=p,Process=f.Process,ActorFile=f.ActorExecutable.File,EventObservedUtc=time,ExpectedSha256=hash});
    p=p with{ManifestSha256=Convert.ToHexString(SHA256.HashData(manifest))};
    var id=Id();var completed=original with{EventId=id,Source="Forensic enrichment",Operation="Actor forensic evidence collected",Forensics=f with{EventId=id,RelatedEventId=original.EventId,Preservation=p,EnrichedUtc=time,Collection=EvidenceStatus.Captured("fixture"),CollectorSequence=2}};
    Check(completed.Forensics.IsValid(),"synthetic preserved evidence meets schema");return(original,completed,bytes,manifest);
}
if(uiSeed)
{
    var seeded=Evidence(first.EndpointId);store.Ingest(first.EndpointId,new([seeded.Original,seeded.Completed]));var upload=new EvidenceReceiver(store,serverRoot);var id=seeded.Completed.Forensics!.Preservation.EvidenceId!;
    await upload.Start(first.EndpointId,new(seeded.Completed.EventId,Convert.ToBase64String(seeded.Manifest)));
    for(var offset=0;offset<seeded.Bytes.Length;offset+=EvidenceTransferLimits.ChunkBytes)await upload.Chunk(first.EndpointId,id,offset,seeded.Bytes[offset..Math.Min(offset+EvidenceTransferLimits.ChunkBytes,seeded.Bytes.Length)]);
    var received=await upload.Finish(first.EndpointId,id);File.WriteAllText(Path.Combine(root,"TRANSFER-SEED.json"),JsonSerializer.Serialize(received));Console.WriteLine("Isolated transfer UI seed ready.");return;
}
var item=Evidence(first.EndpointId);var evidenceId=item.Completed.Forensics!.Preservation.EvidenceId!;
var receiver=new EvidenceReceiver(store,serverRoot);var request=new EvidenceUploadStart(item.Completed.EventId,Convert.ToBase64String(item.Manifest));
await Reject(async()=>{await receiver.Start(first.EndpointId,request);},409,"transfer waits for original/completion event delivery");
store.Ingest(first.EndpointId,new([item.Original,item.Completed]));
await Reject(async()=>{await receiver.Start(second.EndpointId,request);},409,"other sensor cannot upload another sensor's event");
await Reject(async()=>{await receiver.Start(first.EndpointId,request with{ManifestBase64=Convert.ToBase64String([1,2,3])});},422,"incorrect manifest digest rejected");
var receipt=await receiver.Start(first.EndpointId,request);Check(receipt.State=="receiving"&&receipt.ReceivedBytes==0,"reservation remains unconfirmed");
await Reject(async()=>{await receiver.Chunk(first.EndpointId,evidenceId,20,[1]);},409,"offset gap rejected");
await Reject(async()=>{await receiver.Chunk(first.EndpointId,"../escape",0,[1]);},400,"path traversal ID rejected");
await Reject(async()=>{await receiver.Chunk(first.EndpointId,evidenceId,0,new byte[EvidenceTransferLimits.ChunkBytes+1]);},400,"oversized chunk rejected");
var chunk=item.Bytes[..EvidenceTransferLimits.ChunkBytes];await receiver.Chunk(first.EndpointId,evidenceId,0,chunk);
Check((await receiver.Chunk(first.EndpointId,evidenceId,0,chunk)).ReceivedBytes==chunk.Length,"same chunk retry idempotent");
await Reject(async()=>{await receiver.Chunk(first.EndpointId,evidenceId,0,[255]);},409,"conflicting duplicate rejected without overwrite");
await Reject(async()=>{await receiver.Finish(first.EndpointId,evidenceId);},409,"partial upload cannot receive receipt");
receiver=new(new Store(serverRoot),serverRoot);Check((await receiver.Start(first.EndpointId,request)).ReceivedBytes==chunk.Length,"receiver restart resumes durable byte offset");
for(var offset=chunk.Length;offset<item.Bytes.Length;offset+=EvidenceTransferLimits.ChunkBytes)await receiver.Chunk(first.EndpointId,evidenceId,offset,item.Bytes[offset..Math.Min(offset+EvidenceTransferLimits.ChunkBytes,item.Bytes.Length)]);
// Reproduce crash after private files finalize but before the DB receipt commits.
var receivedRoot=Path.Combine(serverRoot,"actor-evidence",first.EndpointId);File.Move(Path.Combine(receivedRoot,evidenceId+".part"),Path.Combine(receivedRoot,evidenceId+".bin"));
receipt=await receiver.Finish(first.EndpointId,evidenceId);Check(receipt.State=="received"&&receipt.ReceivedUtc!=null,"finalized file is independently verified and receipt committed after crash recovery");
Check((await receiver.Finish(first.EndpointId,evidenceId))==receipt,"finish retry returns identical receipt");
using(var download=receiver.Download(first.EndpointId,evidenceId,false))Check(Convert.ToHexString(SHA256.HashData(download))==receipt.Sha256,"central artifact bytes match event hash");
using(var manifest=receiver.Download(first.EndpointId,evidenceId,true))Check(Convert.ToHexString(SHA256.HashData(manifest))==receipt.ManifestSha256,"central manifest bytes match source digest");
if(OperatingSystem.IsWindows()){
    var acl=new FileInfo(Path.Combine(receivedRoot,evidenceId+".bin")).GetAccessControl();
    var deniesExecute=false;foreach(System.Security.AccessControl.FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier)))
        if(rule.IdentityReference.Value=="S-1-1-0"&&rule.AccessControlType==System.Security.AccessControl.AccessControlType.Deny&&(rule.FileSystemRights&System.Security.AccessControl.FileSystemRights.ExecuteFile)!=0)deniesExecute=true;
    Check(deniesExecute,"stored artifact explicitly denies executable access");
}
else Check(File.GetUnixFileMode(Path.Combine(receivedRoot,evidenceId+".bin"))==(UnixFileMode.UserRead|UnixFileMode.UserWrite),"Linux artifact mode is private and non-executable");
if(OperatingSystem.IsWindows()){
 FileIdentityEvidence before;using(var file=receiver.Download(first.EndpointId,evidenceId,false))before=NativeFileIdentity.Read(file);
 for(var repeat=0;repeat<100;repeat++){using var file=receiver.Download(first.EndpointId,evidenceId,false);Check(NativeFileIdentity.Same(before,NativeFileIdentity.Read(file)),"repeated evidence access preserves NTFS identity/change marker "+repeat);}
 var info=new DirectoryInfo(receivedRoot);var acl=info.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access);
 acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),System.Security.AccessControl.FileSystemRights.Read,System.Security.AccessControl.AccessControlType.Allow));info.SetAccessControl(acl);
 using(var file=receiver.Download(first.EndpointId,evidenceId,false))Check(Convert.ToHexString(SHA256.HashData(file))==receipt.Sha256,"permission repair retains original evidence bytes");
 var repaired=info.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access);
 Check(repaired.AreAccessRulesProtected&&repaired.AreAccessRulesCanonical&&!repaired.GetAccessRules(true,true,typeof(System.Security.Principal.SecurityIdentifier)).Cast<System.Security.AccessControl.FileSystemAccessRule>().Any(x=>x.IdentityReference.Value=="S-1-1-0"),"changed directory permissions are repaired instead of cached as trusted");
}
var altered=File.ReadAllBytes(Path.Combine(receivedRoot,evidenceId+".bin"));altered[0]^=1;File.WriteAllBytes(Path.Combine(receivedRoot,evidenceId+".bin"),altered);
await Reject(()=>{using var invalid=receiver.Download(first.EndpointId,evidenceId,false);return Task.CompletedTask;},422,"post-receipt stored corruption is rejected at download");
File.WriteAllBytes(Path.Combine(receivedRoot,evidenceId+".bin"),item.Bytes);
var transfer=store.Events(0,100).Single(e=>e.Event.Source=="Evidence transfer");Check(transfer.Event.Forensics?.Transfer?.ReceiptId==receipt.ReceiptId&&transfer.Event.Forensics.IsValid(),"linked server-owned receipt event persists complete SIEM envelope");
Check(transfer.Event.Forensics!.CollectorEpoch!=item.Completed.Forensics.CollectorEpoch,"server receipt does not invent a sensor ordering sequence");
try{store.Ingest(first.EndpointId,new([transfer.Event with{EventId=Id()}]));throw new Exception("Forged receipt accepted");}catch(ArgumentException){Check(true,"sensor cannot forge central possession telemetry");}
var corrupt=Evidence(first.EndpointId,32);store.Ingest(first.EndpointId,new([corrupt.Original,corrupt.Completed]));var corruptId=corrupt.Completed.Forensics!.Preservation.EvidenceId!;
await receiver.Start(first.EndpointId,new(corrupt.Completed.EventId,Convert.ToBase64String(corrupt.Manifest)));await receiver.Chunk(first.EndpointId,corruptId,0,new byte[32]);
await Reject(async()=>{await receiver.Finish(first.EndpointId,corruptId);},422,"incorrect binary digest remains unconfirmed");
Check((await receiver.Status(first.EndpointId,corruptId)).State=="receiving","corrupt bytes never acquire received status");
var duplicate=Evidence(first.EndpointId,16);var duplicateBytes=System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(duplicate.Manifest).Insert(1,"\"SchemaVersion\":1,"));
duplicate.Completed=duplicate.Completed with{Forensics=duplicate.Completed.Forensics! with{Preservation=duplicate.Completed.Forensics!.Preservation with{ManifestSha256=Convert.ToHexString(SHA256.HashData(duplicateBytes))}}};
store.Ingest(first.EndpointId,new([duplicate.Original,duplicate.Completed]));
await Reject(async()=>{await receiver.Start(first.EndpointId,new(duplicate.Completed.EventId,Convert.ToBase64String(duplicateBytes)));},400,"duplicate manifest properties rejected even when digest matches");
var quotaReceiver=new EvidenceReceiver(store,serverRoot,maximumBytes:800000,perSensorBytes:800000,totalBytes:800000);
var excess=Evidence(first.EndpointId,32);store.Ingest(first.EndpointId,new([excess.Original,excess.Completed]));
await Reject(async()=>{await quotaReceiver.Start(first.EndpointId,new(excess.Completed.EventId,Convert.ToBase64String(excess.Manifest)));},507,"reserved and finalized bytes both count toward quota");

// Exercise the actual packaged HTTP API and real durable upload client against a separate loopback listener.
var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var secret=Store.Secret();
var dll=args[0].EndsWith(".dll",StringComparison.OrdinalIgnoreCase);
var start=new ProcessStartInfo(dll?(OperatingSystem.IsWindows()?@"C:\Program Files\dotnet\dotnet.exe":"dotnet"):Path.GetFullPath(args[0])){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};if(dll)start.ArgumentList.Add(Path.GetFullPath(args[0]));
foreach(var name in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")||k.StartsWith("Forensics__")).ToArray())start.Environment.Remove(name);
start.Environment["RF_DATA_DIR"]=serverRoot;start.Environment["RF_ADMIN_KEY"]=secret;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["DOTNET_ENVIRONMENT"]="Development";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";start.Environment["Logging__LogLevel__Default"]="Warning";
using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
try
{
    var ready=false;for(var n=0;n<150;n++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"candidate server starts with upload API");
    async Task<HttpResponseMessage> Send(HttpMethod method,string url,object? body=null,string? credential=null){using var req=new HttpRequestMessage(method,url);if(body!=null)req.Content=JsonContent.Create(body);if(credential!=null)req.Headers.Authorization=new("Bearer",credential);return await http.SendAsync(req);}
    var concurrentEvents=Enumerable.Range(0,64).Select(i=>new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"read",@"C:\QA\admission-"+i+".txt","qa-user",@"C:\QA\actor.exe",1234,"owned HTTP admission fixture")).ToArray();
    var concurrentStatuses=await Task.WhenAll(concurrentEvents.Select(async e=>
    {
        using var heartbeat=await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("admission-qa","controlled HTTP writer"),first.Credential);
        using var batch=await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([e]),first.Credential);
        return heartbeat.IsSuccessStatusCode&&batch.IsSuccessStatusCode;
    }));
    Check(concurrentStatuses.All(x=>x),"64 concurrent HTTP heartbeat/event writers succeed without database-lock failures");
    Check(concurrentEvents.All(e=>store.EvidenceSource(first.EndpointId,e.EventId)==e),"all concurrently admitted HTTP events persist unchanged");
    using(var response=await Send(HttpMethod.Post,"/api/v1/agent/evidence/start",request))Check(response.StatusCode==HttpStatusCode.Unauthorized,"anonymous upload denied");
    using(var response=await Send(HttpMethod.Post,$"/api/v1/agent/evidence/{evidenceId}/status",new{},second.Credential))Check(response.StatusCode==HttpStatusCode.NotFound,"cross-sensor receipt denied");
    using(var response=await Send(HttpMethod.Get,$"/api/v1/console/actor-evidence/{first.EndpointId}/{evidenceId}/artifact"))Check(response.StatusCode==HttpStatusCode.Unauthorized,"anonymous artifact download denied");
    using(var response=await Send(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{first.EndpointId}/{evidenceId}/artifact",credential:secret))Check(response.IsSuccessStatusCode&&response.Content.Headers.ContentType?.MediaType=="application/octet-stream"&&response.Content.Headers.ContentDisposition?.DispositionType=="attachment"&&Convert.ToHexString(SHA256.HashData(await response.Content.ReadAsByteArrayAsync()))==receipt.Sha256,"authorized download is an attachment with exact bytes");
    using(var response=await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([transfer.Event]),first.Credential))Check(response.StatusCode==HttpStatusCode.BadRequest,"HTTP rejects forged server receipt");
    var clientDir=Path.Combine(root,"sensor");Directory.CreateDirectory(Path.Combine(clientDir,"evidence","actors"));var queued=Evidence(first.EndpointId,600000);var queuedId=queued.Completed.Forensics!.Preservation.EvidenceId!;
    File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",queuedId+".bin"),queued.Bytes);File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",queuedId+".json"),queued.Manifest);
    var queue=new EvidenceUploadQueue(clientDir);queue.Register(queued.Original,queued.Completed);
    using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress,Timeout=TimeSpan.FromSeconds(30)},first.Credential);
    Check(await queue.Pump(client)==1,"persistent client sends events, artifact and manifest then records verified receipt");
    Check(await new EvidenceUploadQueue(clientDir).Pump(client)==0,"client restart honors identical receipt without duplicate transfer");
    Check(File.Exists(Path.Combine(clientDir,"evidence","actors",queuedId+".bin")),"server receipt never deletes local forensic original");
    var archive=Path.Combine(clientDir,"evidence","uploads",queuedId+".uploaded.json");
    Check(File.Exists(archive)&&!File.Exists(Path.Combine(clientDir,"evidence","uploads",queuedId+".pending.json")),"validated received record leaves active queue with metadata retained");
    var archivedHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive)));
    queue.Register(queued.Original,queued.Completed);
    Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(archive)))==archivedHash&&!File.Exists(Path.Combine(clientDir,"evidence","uploads",queuedId+".pending.json")),"idempotent registration does not reactivate acknowledged evidence");
    var migrationDir=Path.Combine(root,"legacy-receipt-migration");var migration=new EvidenceUploadQueue(migrationDir);
    var legacyBytes=new Dictionary<string,string>();
    for(var n=0;n<129;n++){
        var legacy=Evidence(first.EndpointId,1);migration.Register(legacy.Original,legacy.Completed);var p=legacy.Completed.Forensics!.Preservation;
        var uploads=Path.Combine(migrationDir,"evidence","uploads");var record=Path.Combine(uploads,p.EvidenceId+".pending.json");
        legacyBytes[p.EvidenceId!]=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(record)));
        File.WriteAllText(Path.Combine(uploads,p.EvidenceId+".receipt.json"),JsonSerializer.Serialize(receipt with{SensorId=first.EndpointId,EvidenceId=p.EvidenceId!,CompletionEventId=legacy.Completed.EventId,Sha256=p.Sha256!,ManifestSha256=p.ManifestSha256!,Size=1,ReceivedBytes=1}));
    }
    Check(await migration.Pump(client)==0&&Directory.GetFiles(Path.Combine(migrationDir,"evidence","uploads"),"*.pending.json").Length==65,"legacy migration validates at most 64 records per call");
    Check(await new EvidenceUploadQueue(migrationDir).Pump(client)==0&&Directory.GetFiles(Path.Combine(migrationDir,"evidence","uploads"),"*.pending.json").Length==1,"restart continues bounded legacy migration");
    Check(await new EvidenceUploadQueue(migrationDir).Pump(client)==0&&await migration.Pump(client)==0,"fully acknowledged queue becomes idle");
    Check(legacyBytes.All(x=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(migrationDir,"evidence","uploads",x.Key+".uploaded.json"))))==x.Value),"all retired legacy metadata stays byte-identical");
    var invalidReceived=Evidence(first.EndpointId,1);migration.Register(invalidReceived.Original,invalidReceived.Completed);var invalidId=invalidReceived.Completed.Forensics!.Preservation.EvidenceId!;
    var invalidPending=Path.Combine(migrationDir,"evidence","uploads",invalidId+".pending.json");
    File.WriteAllText(Path.Combine(migrationDir,"evidence","uploads",invalidId+".receipt.json"),JsonSerializer.Serialize(receipt with{EvidenceId=invalidId,Sha256=new string('0',64)}));
    try{await migration.Pump(client);throw new Exception("Invalid receipt retired");}catch(AggregateException ex){Check(ex.InnerExceptions.OfType<EvidenceUploadAttemptException>().Single().Phase=="receipt-validation"&&File.Exists(invalidPending)&&!File.Exists(invalidPending.Replace(".pending.json",".uploaded.json")),"mismatched receipt cannot retire or hide pending evidence");}
    var continued=Evidence(first.EndpointId,16*EvidenceTransferLimits.ChunkBytes+17);var continuedId=continued.Completed.Forensics!.Preservation.EvidenceId!;
    File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",continuedId+".bin"),continued.Bytes);File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",continuedId+".json"),continued.Manifest);queue.Register(continued.Original,continued.Completed);
    Check(await queue.Pump(client)==0,"upload pump yields after its bounded chunk budget");
    Check(await new EvidenceUploadQueue(clientDir).Pump(client)==1,"next pump resumes large artifact rather than restarting bytes");
    var bad=Evidence(first.EndpointId,20,new string('0',32));var good=Evidence(first.EndpointId,21);
    foreach(var pendingItem in new[]{bad,good}){var p=pendingItem.Completed.Forensics!.Preservation;File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",p.EvidenceId+".bin"),pendingItem.Bytes);File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",p.EvidenceId+".json"),pendingItem.Manifest);queue.Register(pendingItem.Original,pendingItem.Completed);}
    File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",bad.Completed.Forensics!.Preservation.EvidenceId+".bin"),new byte[20]);
    try{await queue.Pump(client);throw new Exception("Damaged artifact not reported");}catch(AggregateException ex){
        Check(store.EvidenceReceipt(first.EndpointId,good.Completed.Forensics!.Preservation.EvidenceId!)?.State=="received","a corrupt first queue entry is reported without starving a valid later upload");
        var failure=ex.InnerExceptions.OfType<EvidenceUploadAttemptException>().Single();
        Check(failure.EvidenceId==bad.Completed.Forensics!.Preservation.EvidenceId&&failure.Phase=="local-artifact-validation"&&failure.HttpStatus==null,"corrupt artifact failure identifies exact evidence and local validation phase without inventing HTTP status");
        Check(!EvidenceUploadWorker.FailureDiagnostic(ex).Contains(clientDir)&&!EvidenceUploadWorker.FailureDiagnostic(ex).Contains(first.Credential),"upload diagnostics exclude local paths and credentials");
    }
    for(var failure=1;failure<=7;failure++){
        var blocked=Evidence(first.EndpointId,20,failure.ToString("x32"));var p=blocked.Completed.Forensics!.Preservation;
        File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",p.EvidenceId+".bin"),new byte[20]);File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",p.EvidenceId+".json"),blocked.Manifest);queue.Register(blocked.Original,blocked.Completed);
    }
    var last=Evidence(first.EndpointId,20,new string('f',32));var lastId=last.Completed.Forensics!.Preservation.EvidenceId!;
    File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",lastId+".bin"),last.Bytes);File.WriteAllBytes(Path.Combine(clientDir,"evidence","actors",lastId+".json"),last.Manifest);queue.Register(last.Original,last.Completed);
    var cursorPath=Path.Combine(clientDir,"evidence","uploads","pump-cursor.json");
    File.Move(cursorPath,cursorPath+".before-rotation",false); // isolated scheduling fixture setup only
    var rotating=new EvidenceUploadQueue(clientDir);
    try{await rotating.Pump(client);}catch(AggregateException){}
    Check(store.EvidenceReceipt(first.EndpointId,lastId)==null,"pump stops at its failure budget while retaining later work");
    try{await new EvidenceUploadQueue(clientDir).Pump(client);}catch(AggregateException){}
    Check(store.EvidenceReceipt(first.EndpointId,lastId)?.State=="received","restarted pump restores its cursor past eight persistent failures to deliver later evidence");
    var hint=JsonDocument.Parse(File.ReadAllText(cursorPath));
    Check(hint.RootElement.GetProperty("Version").GetInt32()==1&&hint.RootElement.GetProperty("EvidenceId").GetString() is {Length:32},"persisted retry position is a bounded versioned evidence ID, not a receipt");
    hint.Dispose();
    var pendingBefore=Directory.GetFiles(Path.GetDirectoryName(cursorPath)!,"*.pending.json").ToDictionary(p=>Path.GetFileName(p)!,p=>Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(p))));
    foreach(var corruptHint in new[]{"{",JsonSerializer.Serialize(new{Version=99,EvidenceId=lastId}),new string('x',1025),JsonSerializer.Serialize(new{Version=1,EvidenceId="../actor"})})
    {
        File.WriteAllText(cursorPath,corruptHint);
        try{await new EvidenceUploadQueue(clientDir).Pump(client);throw new Exception("Corrupt cursor accepted");}
        catch(EvidenceUploadAttemptException ex){Check(ex.Phase=="cursor-recovery"&&!File.Exists(cursorPath),"invalid retry hint is retained separately and reported without selecting bytes");}
        try{await new EvidenceUploadQueue(clientDir).Pump(client);}catch(AggregateException){}
        Check(File.Exists(cursorPath)&&store.EvidenceReceipt(first.EndpointId,lastId)?.State=="received","next restarted pump recovers after invalid hint without losing received evidence");
    }
    Check(pendingBefore.All(p=>File.Exists(Path.Combine(Path.GetDirectoryName(cursorPath)!,p.Key!))&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(cursorPath)!,p.Key!))))==p.Value),"retry scheduling and corruption recovery leave all pending event records byte-identical");
    using(var response=await Send(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{first.EndpointId}/{queuedId}",credential:secret)){var received=await response.Content.ReadFromJsonAsync<EvidenceUploadReceipt>();Check(received?.State=="received"&&received.Sha256==queued.Completed.Forensics.Preservation.Sha256,"actual server API confirms upload from client worker");}
    store.Revoke(second.EndpointId);using(var response=await Send(HttpMethod.Post,$"/api/v1/agent/evidence/{evidenceId}/status",new{},second.Credential))Check(response.StatusCode==HttpStatusCode.Unauthorized,"revoked sensor cannot access transfer API");
    var revokedDir=Path.Combine(root,"revoked-upload");var revoked=Evidence(second.EndpointId,20);var revokedQueue=new EvidenceUploadQueue(revokedDir);revokedQueue.Register(revoked.Original,revoked.Completed);
    using var revokedClient=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress,Timeout=TimeSpan.FromSeconds(30)},second.Credential);
    try{await revokedQueue.Pump(revokedClient);throw new Exception("Revoked upload not reported");}catch(EvidenceUploadAttemptException ex){
        Check(ex.EvidenceId==null&&ex.Phase=="capability-check"&&ex.HttpStatus==401,"capability refusal exposes actual HTTP status without guessing an unexamined evidence ID");
    }
    using var refusedReplay=new ManagementClient(new HttpClient(new ReplayRefusalHandler()){BaseAddress=http.BaseAddress},second.Credential);
    try{await revokedQueue.Pump(refusedReplay);throw new Exception("Failed replay not reported");}catch(AggregateException ex){
        var failure=ex.InnerExceptions.OfType<EvidenceUploadAttemptException>().Single();
        Check(failure.EvidenceId==revoked.Completed.Forensics!.Preservation.EvidenceId&&failure.Phase=="event-replay"&&failure.HttpStatus==500,"controlled HTTP 500 during event replay exposes evidence ID, stage and status");
        Check(EvidenceUploadWorker.FailureDiagnostic(ex).Contains("http=500")&&!EvidenceUploadWorker.FailureDiagnostic(ex).Contains(second.Credential)&&!EvidenceUploadWorker.FailureDiagnostic(ex).Contains("private-response")&&File.Exists(Path.Combine(revokedDir,"evidence","uploads",failure.EvidenceId+".pending.json")),"failed replay remains retryable and reports sanitized diagnostic context");
    }
}
finally{if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync();}File.WriteAllText(Path.Combine(root,"server.log"),await stdout+await stderr);}
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Checks=checks.Count,Passed=true,ChecksPassed=checks,Root=root},new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine($"PASS: {checks.Count} evidence transfer checks; {root}");

sealed class ReplayRefusalHandler:HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return Task.FromResult(request.RequestUri!.AbsolutePath=="/api/v1/agent/capabilities"?
            new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(new{EvidenceUploadVersion=1,AttributionVersion=1,ForensicsVersion=1,TrustVersion=1})}:
            new HttpResponseMessage(HttpStatusCode.InternalServerError){Content=new StringContent("private-response")});
    }
}
