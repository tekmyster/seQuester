using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;
if(args.Length==6&&args[0]=="owned-runtime-io-ui-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,atomicArchiveSha256:args[4],ioOperations:true,uiScript:args[5]);return;}
if(args.Length==5&&args[0]=="owned-runtime-io-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,atomicArchiveSha256:args[4],ioOperations:true);return;}
if(args.Length==6&&args[0]=="owned-runtime-atomic-ui-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,atomicArchiveSha256:args[4],uiScript:args[5]);return;}
if(args.Length==5&&args[0]=="owned-runtime-atomic-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,atomicArchiveSha256:args[4]);return;}
if(args.Length==3&&args[0]=="atomic-transport"){await AtomicTransportChecks.Run(args[1],args[2]);return;}

if(args.Length==5&&args[0]=="controlled-v2-transport"){await ControlledV2TransportChecks.Run(args[1],args[2],args[3],args[4]);return;}
if(args.Length==4&&args[0]=="native-work-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3]);return;}
if(args.Length==4&&args[0]=="serial-work-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true);return;}
if(args.Length==4&&args[0]=="owned-runtime-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true);return;}
if(args.Length==4&&args[0]=="owned-runtime-v2-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,ownedRuntimeV2:true);return;}
if(args.Length==4&&args[0]=="native-trust-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,ownedRuntimeV2:true,nativeTrust:true);return;}
if(args.Length==5&&args[0]=="native-trust-ui-transport"){await NativeWorkTransportChecks.Run(args[1],args[2],args[3],methodDetails:true,ownedRuntime:true,ownedRuntimeV2:true,nativeTrust:true,uiScript:args[4]);return;}
if(args.Length!=2)throw new ArgumentException("Pass isolated server DLL and the accepted R13 native-results.tar.gz");
const string archiveHash="1B2983D119024C298C37406BC633A4E7F4C0B20E09B67C799B39260458D1C4D1";
var root=Path.Combine(@"D:\Codex\RansomFree\windows-token-20260930","linux-transport-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();
void Check(bool ok,string name){if(!ok)throw new InvalidDataException(name);checks.Add(name);Console.WriteLine("PASS: "+name);}
void Reject(Action action,string name){try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException){Check(true,name);return;}throw new Exception("Accepted invalid evidence: "+name);}
var archive=File.ReadAllBytes(args[1]);Check(Convert.ToHexString(SHA256.HashData(archive))==archiveHash,"native archive SHA-256 matches accepted R13 receipt");
JsonDocument? native=null;
using(var zip=new GZipStream(new MemoryStream(archive),CompressionMode.Decompress))
using(var tar=new TarReader(zip))
    while(tar.GetNextEntry() is {} entry)if(entry.Name=="RESULTS.json"){
        Check(native==null&&entry.EntryType==TarEntryType.RegularFile&&entry.Length<4*1024*1024,"unique bounded regular native receipt");
        using var data=new MemoryStream();entry.DataStream!.CopyTo(data);native=JsonDocument.Parse(data.ToArray());
    }
using var document=native??throw new InvalidDataException("Native receipt absent");
var records=document.RootElement.GetProperty("Records").EnumerateArray().ToArray();
Check(document.RootElement.GetProperty("Passed").GetBoolean()&&records.Length==48,"accepted native receipt contains exactly 48 observations");
LeaseProtocolChecks.Run(archive,records,Check);
var store=new Store(Path.Combine(root,"server"));var enrolled=store.Enroll(new(store.CreateCode().Code,"SQ-LINUX-KERNEL native replay","linux-kernel-qa"))!;
var collector=Guid.NewGuid().ToString("N");var now=DateTimeOffset.UtcNow;long sequence=0;
AgentEvent Decode(byte[] bytes)=>LinuxKernelDecoder.Decode(bytes,enrolled.EndpointId,collector,++sequence,now);
var events=new List<AgentEvent>();
foreach(var record in records)
{
    // This hashes the archived Event JSON representation, not a claimed original
    // loader line: R13 retained parsed observations inside RESULTS.json.
    var raw=Encoding.UTF8.GetBytes(record.GetProperty("Event").GetRawText());var e=Decode(raw);events.Add(e);var k=e.Attribution!.LinuxKernel!;
    Check(k.NativeObservationSha256==Convert.ToHexString(SHA256.HashData(raw))&&k.IsValid()&&LinuxKernelEvidence.Matches(e),"decode archived observation "+sequence);
    Check(k.ProviderEpoch==record.GetProperty("Event").GetProperty("providerEpoch").GetUInt64().ToString(System.Globalization.CultureInfo.InvariantCulture)&&k.ProcessId==record.GetProperty("Event").GetProperty("pid").GetInt32(),"exact provider and PID "+sequence);
    Check(EventActivity.From(e) is {Outcome:"unknown",Actions:["open-request"]}&&EventHistoryPresentation.Action(e,EventActivity.From(e))=="Open Requested","pre-open never becomes a completed I/O verdict "+sequence);
}
Check(events.Select(e=>e.EventId).Distinct().Count()==48,"distinct event IDs across native observations");
Check(events.Count(e=>e.Attribution!.LinuxKernel!.RecordForm=="compact")==7,"all seven compact unavailable observations retained");
var invalidUtf8=events.Single(e=>e.Attribution!.LinuxKernel!.ActorPath.State=="invalid_utf8");
Check(invalidUtf8.Process==null&&!LocalActorEvidence.IsComplete(invalidUtf8)&&invalidUtf8.Attribution!.LinuxKernel!.ActorPath.BytesBase64!=null,"invalid UTF-8 actor remains incomplete with exact bytes retained");
var sample=events[0];var sampleRaw=records[0].GetProperty("Event").GetRawText();
AgentEvent Mutate(Action<JsonObject> mutation){var node=JsonNode.Parse(sampleRaw)!.AsObject();mutation(node);return Decode(Encoding.UTF8.GetBytes(node.ToJsonString()));}
var missing=Mutate(n=>{n["credentialFields"]=0;n["credentialError"]=-61;foreach(var key in new[]{"uid","euid","fsuid","gid","egid","fsgid"})n[key]=null;});events.Add(missing);
Check(missing.User==null&&!missing.Attribution!.EventTimeCredentials&&!LocalActorEvidence.IsComplete(missing),"unavailable credentials stay null and detection remains deliverable");
var reused=Mutate(n=>n["processStartNs"]=n["processStartNs"]!.GetValue<ulong>()+1);events.Add(reused);
var reexec=Mutate(n=>n["selfExecId"]=n["selfExecId"]!.GetValue<ulong>()+1);events.Add(reexec);
Check(reused.ProcessId==sample.ProcessId&&reused.Attribution!.ProcessStartTicks!=sample.Attribution!.ProcessStartTicks&&reexec.Attribution!.ProcessStartTicks!=sample.Attribution.ProcessStartTicks,"PID reuse and same-PID exec have different instance keys");
var reloaded=Mutate(n=>n["providerEpoch"]=n["providerEpoch"]!.GetValue<ulong>()+1);
using(var firstActor=ActorLease.Capture(sample,enrolled.EndpointId))
using(var nextActor=ActorLease.Capture(reloaded,enrolled.EndpointId))Check(firstActor.Process.InstanceId!=nextActor.Process.InstanceId,"provider reload or reboot cannot reuse an earlier process correlation");
var wide=Mutate(n=>{foreach(var key in new[]{"providerEpoch","cookie","processStartNs","selfExecId","actorInode"})n[key]=ulong.MaxValue;});events.Add(wide);
Check(wide.Attribution!.LinuxKernel!.ProviderEpoch=="18446744073709551615"&&wide.Attribution.IsValid(),"full uint64 identities survive without floating-point conversion");
static void SetPath(JsonObject n,string name,string text){var bytes=Encoding.UTF8.GetBytes(text);n[name+"Path"]=text;n[name+"PathBytesBase64"]=Convert.ToBase64String(bytes);n[name+"PathResult"]=bytes.Length+1;n[name+"PathStatus"]="captured";}
var controls=Mutate(n=>{SetPath(n,"actor","/literal\\n/line\n\t\"actor");SetPath(n,"target","/target\r\n/λ");});events.Add(controls);
Check(!controls.Process!.Any(char.IsControl)&&controls.Attribution!.LinuxKernel!.ActorPath.Text=="/literal\\n/line\n\t\"actor","control characters and literal backslashes remain distinguishable");
var maxPath=Mutate(n=>{SetPath(n,"actor","/"+new string('\u0001',4094));SetPath(n,"target","/"+new string('\u0002',4094));});events.Add(maxPath);
Check(JsonSerializer.SerializeToUtf8Bytes(maxPath).Length<=24576&&maxPath.Path.Length<=520,"two maximum native paths fit existing 24 KiB durable envelope");
var precedingDenial=Mutate(n=>n["priorResult"]=-13);events.Add(precedingDenial);
Check(precedingDenial.Attribution!.Outcome=="Unknown"&&EventActivity.From(precedingDenial).Outcome=="unknown","preceding BPF denial remains separate from final syscall outcome");
Reject(()=>Mutate(n=>n["schemaVersion"]=6),"unsupported native schema rejected");
Reject(()=>Mutate(n=>n["whitelistEligible"]=true),"lease ID alone cannot authorize a whitelist");
Reject(()=>Mutate(n=>n["actorPath"]="/renamed-malware"),"path text conflicting with native bytes rejected");
Reject(()=>Mutate(n=>n["fsuid"]=null),"credential presence mask contradiction rejected");
Reject(()=>Mutate(n=>n.Remove("processStartNs")),"missing process identity field rejected");
Reject(()=>Mutate(n=>n["providerEpoch"]=1.25),"fractional native identity rejected");
Reject(()=>Decode(Encoding.UTF8.GetBytes(sampleRaw.Insert(1,"\"schemaVersion\":5,"))),"duplicate native field rejected");
Check(!(sample.Attribution!.LinuxKernel! with{ProcessStartNs="01"}).IsValid(),"noncanonical decimal identity rejected");
Check(!(sample.Attribution.LinuxKernel! with{ActorPath=null!}).IsValid(),"null nested metadata rejected safely");
var spool=new EventSpool(Path.Combine(root,"spool"),enrolled.EndpointId);spool.Enqueue(sample);
Reject(()=>spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1}),"legacy receipt cannot discard Linux kernel evidence");
Check(spool.Count==1,"legacy receipt leaves durable event intact");
foreach(var altered in new[]{sample with{ProcessId=sample.ProcessId+1},sample with{User="root"},sample with{Process="/renamed-malware"},sample with{Path="/different"},sample with{Operation="Content written"},sample with{Attribution=null},sample with{Attribution=sample.Attribution! with{CompleteRecordSet=true}}})
    Reject(()=>spool.Enqueue(altered with{EventId=Guid.NewGuid().ToString("N")}),"contradictory derived fields rejected: "+JsonSerializer.Serialize(altered).Length);
spool.Acknowledge(spool.Peek(),new(1,0){AttributionVersion=1,LinuxKernelVersion=1});Check(spool.Count==0,"explicit Linux evidence receipt acknowledges the exact queue prefix");
using(var older=new CapabilityHandler(false,false))
using(var client=new ManagementClient(new HttpClient(older){BaseAddress=new Uri("https://fixture.invalid")},enrolled.Credential))
{
    try{await client.SendEventsAsync(new([sample]));throw new Exception("Unsupported server accepted");}catch(InvalidDataException){Check(older.EventRequests==0,"old capability blocks POST before evidence can be discarded");}
}
using(var legacyAck=new CapabilityHandler(true,false))
using(var client=new ManagementClient(new HttpClient(legacyAck){BaseAddress=new Uri("https://fixture.invalid")},enrolled.Credential))
{
    try{await client.SendEventsAsync(new([sample]));throw new Exception("Legacy ACK accepted");}catch(InvalidDataException){Check(legacyAck.EventRequests==1,"client rejects missing receipt capability after transmission");}
}
var observationCount=events.Count;var forensic=new ForensicCollector(enrolled.EndpointId,Path.Combine(root,"forensics"));
var acquisitionEvents=AcquisitionContractChecks.Run(archive,records,events,root,enrolled.EndpointId,Check);
acquisitionEvents.Add(await AcquisitionQueueChecks.Run(acquisitionEvents[0],maxPath,root,enrolled.EndpointId,Check));
var enriched=new List<AgentEvent>();
foreach(var e in events)
{
    using var actor=ActorLease.Capture(e,enrolled.EndpointId);var k=e.Attribution!.LinuxKernel!;
    Check(actor.Image==null&&actor.Binding.State=="unavailable"&&actor.Process.EventSubject.FileSystemUid==k.FileSystemUid&&actor.Process.EventSubject.FileSystemGid==k.FileSystemGid&&actor.Process.EventSubject.CredentialNamespace==k.CredentialNamespace&&actor.Process.Owner.Status.State=="unavailable"&&actor.Process.StartedUtc==null,"kernel credentials survive process exit without reopening PID or inventing owner/wall time: "+e.EventId);
    var begun=forensic.Begin(e,actor);var completed=forensic.Complete(e,actor,begun,new());
    Check(begun.IsValid()&&completed.IsValid()&&completed.ActorExecutable.HashStatus.State=="unavailable"&&completed.Preservation.Status.State=="unavailable"&&completed.Observation.Storage=="unknown","missing kernel lease yields explicit forensic hash/copy failure: "+e.EventId);
    var original=e with{Forensics=begun};enriched.Add(original);
    Check(!LinuxKernelEvidence.Matches(original with{Forensics=begun with{Process=begun.Process with{Pid=begun.Process.Pid+1}}}),"forensic PID cannot contradict native operation identity: "+e.EventId);
    Check(!LinuxKernelEvidence.Matches(original with{Forensics=begun with{Process=begun.Process with{EventSubject=begun.Process.EventSubject with{FileSystemUid=(begun.Process.EventSubject.FileSystemUid??0)+1}}}}),"forensic effective principal cannot contradict native credentials: "+e.EventId);
    var id=Guid.NewGuid().ToString("N");enriched.Add(e with{EventId=id,Source="Forensic enrichment",Operation="Actor forensic evidence partially collected",Forensics=forensic.LinkCompletion(completed,id)});
}
events=enriched.Concat(acquisitionEvents).ToList();
var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var secret=Store.Secret();
var psi=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};psi.ArgumentList.Add(Path.GetFullPath(args[0]));
foreach(var key in psi.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())psi.Environment.Remove(key);
psi.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");psi.Environment["RF_ADMIN_KEY"]=secret;psi.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";psi.Environment["ASPNETCORE_ENVIRONMENT"]="Development";psi.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";psi.Environment["Database__Provider"]="Sqlite";
using var process=Process.Start(psi)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
try
{
    var ready=false;for(var i=0;i<150;i++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"isolated server starts");
    using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},enrolled.Credential);
    foreach(var e in events)spool.Enqueue(e);
    var reopened=new EventSpool(Path.Combine(root,"spool"),enrolled.EndpointId);Check(reopened.Count==events.Count,"all native and adversarial edge cases survive spool restart");
    while(spool.Count>0){var batch=spool.Peek();var receipt=await client.SendEventsAsync(batch);Check(receipt.LinuxKernelVersion==1&&receipt.LinuxActorAcquisitionVersion==1&&receipt.Accepted==batch.Events.Length,"authenticated HTTP acknowledges exact typed Linux evidence batch");spool.Acknowledge(batch,receipt);}
    var persisted=store.Events(0,500);Check(persisted.Count==events.Count,"all native and constructed observations plus linked forensic completions persisted");
    foreach(var e in events)Check(JsonSerializer.Serialize(persisted.Single(x=>x.Event.EventId==e.EventId).Event)==JsonSerializer.Serialize(e),"complete event survives database: "+e.EventId);
    async Task<EventHistoryPage> History(string query){using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500"+query);request.Headers.Authorization=new("Bearer",secret);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();return(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;}
    var history=await History("");Check(history.Items.Count==events.Count&&history.Items.All(e=>e.Activity.Outcome=="unknown"&&e.DisplayOperation==(e.Event.Source=="Linux kernel"?"Open Requested":"Forensic Evidence")),"history exposes every observation and completion with honest pre-open status");
    foreach(var e in history.Items)Check(JsonSerializer.Serialize(e.Event)==JsonSerializer.Serialize(events.Single(x=>x.EventId==e.Event.EventId)),"history retains exact typed evidence: "+e.Event.EventId);
    Check((await History("&action=Open%20Requested")).Items.Count==observationCount&&(await History("&action=Forensic%20Evidence")).Items.Count==observationCount+acquisitionEvents.Count&&(await History("&action=File%20Opened")).Items.Count==0,"database action filters distinguish requested open, forensic enrichment and completed open");
    var forged=sample with{EventId=Guid.NewGuid().ToString("N"),ProcessId=sample.ProcessId+1};
    using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events"){Content=JsonContent.Create(new EventBatch([forged]))}){request.Headers.Authorization=new("Bearer",enrolled.Credential);using var response=await http.SendAsync(request);Check(response.StatusCode==HttpStatusCode.BadRequest&&store.Events(0,500).Count==events.Count,"server independently rejects contradictory identity without persisting it");}
    foreach(var e in events)
    {
        var alert=new Alert(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process??"Unavailable",e.User??"Unavailable",e.Source){EventId=e.EventId,ProcessId=e.ProcessId,Attribution=e.Attribution,Forensics=e.Forensics,EndpointId=enrolled.EndpointId};
        var formatted=Encoding.UTF8.GetString(SyslogClient.Format(alert,new(){Format="RFC5424"}));using var payload=JsonDocument.Parse(formatted[formatted.IndexOf('{')..]);
        Check(JsonSerializer.Serialize(payload.RootElement.GetProperty("Attribution").GetProperty("LinuxKernel").Deserialize<LinuxKernelEvidence>())==JsonSerializer.Serialize(e.Attribution!.LinuxKernel),"SIEM formatter retains versioned native evidence: "+e.EventId);
        Check(JsonSerializer.Serialize(payload.RootElement.GetProperty("Forensics").Deserialize<ForensicEvidence>())==JsonSerializer.Serialize(e.Forensics),"SIEM formatter retains exact forensic acquisition fields: "+e.EventId);
    }
    await AcquisitionUploadChecks.Run(acquisitionEvents.Take(38).ToArray(),events,root,enrolled.EndpointId,secret,store,client,http,Check);
    File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,NativeObservations=48,ConstructedEdgeObservations=observationCount-48,UnavailableLeaseCompletions=observationCount,ArchivedAcquisitionContractReplays=38,ActualLocalPreservations=38,ActualLoopbackUploads=38,AlteredManifestRejections=6,ConstructedPreservationEnvelopes=1,StoredEvents=store.Events(0,500).Count,MaximumEventBytes=events.Max(e=>JsonSerializer.SerializeToUtf8Bytes(e).Length),QueueSchema=4,ArchiveSha256=archiveHash,InputArchive=Path.GetFullPath(args[1]),Scope="Archived native replay through decoder, unavailable-lease handling, common forensic collector/preservation, queue migrations, authenticated HTTP, DB, history, SIEM formatter and actual loopback binary upload/download. Preserved-envelope edge case is constructed. No live Linux service activation, live actor lease acquisition, network SIEM delivery or production deployment."},new JsonSerializerOptions{WriteIndented=true}));
    Console.WriteLine($"PASS: {checks.Count} checks; artifacts {root}");
}
finally{if(!process.HasExited)process.Kill(entireProcessTree:true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr.txt"),await stderr);}

sealed class CapabilityHandler(bool capable,bool acknowledge):HttpMessageHandler
{
    public int EventRequests {get;private set;}
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
    {
        object result;if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities"))result=new{AttributionVersion=1,LinuxKernelVersion=capable?1:0};
        else{EventRequests++;result=new BatchReceipt(1,0){AttributionVersion=1,LinuxKernelVersion=acknowledge?1:0};}
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(result)});
    }
}
