using System.Security.Cryptography;
using System.Text.Json;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class SyscallActorChecks
{
    internal static async Task Run(string directory,string rawPath)
    {
        var count=0;void Check(bool ok,string name){if(!ok)throw new Exception(name);count++;}
        var raw=File.ReadAllBytes(rawPath);if(raw.Length!=6264)throw new InvalidDataException("Expected independently captured nine native pairs");
        var native=WindowsSyscallDecoder.Decode(raw[..408]);var serverDirectory=Path.Combine(directory,"server");var server=new Store(serverDirectory);
        var code=server.CreateCode();var enrollment=server.Enroll(new(code.Code,"syscall-unit-fixture","fixture"))!;var sensor=enrollment.EndpointId;
        var initial=Wire.Event(directory);initial=initial with{ProcessId=(int)native.ProcessId,Attribution=initial.Attribution! with{WindowsKernel=initial.Attribution.WindowsKernel! with{ProcessId=(int)native.ProcessId,ProcessCreatedFileTime=native.ProcessCreatedFileTime}}};
        var bytes=File.ReadAllBytes(Path.Combine(Environment.SystemDirectory,"cmd.exe"));var hash=Convert.ToHexString(SHA256.HashData(bytes));
        var wire=new Wire(initial,bytes){CreationMetadata=true,SourceVolume=true};var k=initial.Attribution!.WindowsKernel!;
        var epoch=Convert.ToUInt64(k.Instance,16);var ready=new WindowsReadyActor(wire.Provider,0x40020056,epoch,1,wire.Generation,wire.Candidate,(int)native.ProcessId,native.ProcessCreatedFileTime,999999,(uint)bytes.Length,1,0x80000020,0x100021,2,0,1234);
        var store=new WindowsStagedActorStore(directory,sensor);Check(store.CaptureReady(ready,wire.Send,_=>{})=="captured","synthetic proactive transport stores exact actual executable bytes");
        var o=new WindowsSyscallObservation{SourceInstance=Guid.NewGuid().ToString("N"),SourceInstanceStatus="0x00000000",Native=native,NativeTargetPath=@"\Device\HarddiskVolume3\honeypot.txt",TargetPath=@"C:\honeypot.txt",TargetQueriedUtc=DateTimeOffset.UtcNow,TargetStatus=EvidenceStatus.Captured("synthetic-target-query")};
        var nativeIntake=Path.Combine(Path.GetDirectoryName(rawPath)!,"native-intake.bin");if(File.Exists(nativeIntake)){
            var transport=File.ReadAllBytes(nativeIntake);if(transport.Length!=9*3584)throw new InvalidDataException("Wrong actual intake fixture length");
            o=WindowsSyscallSource.Observation(transport.AsSpan(3176,408).ToArray(),WindowsSyscallSource.SourceInfo(transport[..56]),transport.AsSpan(56,3120).ToArray());
        }
        var observed=WindowsSyscallEvent.Create(sensor,o);
        using var actor=store.CaptureSyscall(observed,wire.Provider,epoch,p=>p.Replace(@"\Device\HarddiskVolume3", "C:"),out var value);
        Check(actor.Image!=null&&actor.Acquisition?.Version==2&&actor.Acquisition.SyscallRecordSha256==native.RawRecordSha256,"exact generation snapshot linked to syscall raw record");
        var collector=new ForensicCollector(sensor,directory);var f=collector.Complete(value,actor,collector.Begin(value,actor),new());
        Check(f.IsValid()&&WindowsSyscallObservation.Matches(value with{Forensics=f}),"versioned forensic evidence matches raw lifetime and event");
        Check(f.ActorExecutable.Sha256==hash&&f.Preservation.HashMatched==true&&f.Preservation.Status.State=="captured","actor executable hashed and preserved with matching bytes");
        Check(f.ActorExecutable.Signature.Valid==true,"actual signed Windows executable verified using private snapshot");
        Check(f.Process.Owner.Sid=="S-1-5-18"&&f.Process.ThreadToken.Sid=="S-1-5-19"&&f.Process.Impersonating==true,"actual captured process/effective token separation survives actor enrichment");
        Check(f.Observation.HashPolicy=="not-hashed-by-forensic-collector"&&!File.Exists(value.Path),"target never opened or hashed for actor collection");
        for(var i=0;i<32;i++){
            var next=WindowsSyscallEvent.Create(sensor,o with{Native=native with{Sequence=native.Sequence+i+100}});
            using var cached=store.CaptureSyscall(next,wire.Provider,epoch,p=>p,out var nextValue);
            var result=collector.Complete(nextValue,cached,collector.Begin(nextValue,cached),new(PreserveActorOnAlert:false));
            Check(result.ActorExecutable.Sha256==hash,"unchanged verified snapshot hashes consistently under repeated activity");
        }
        Check(collector.HashComputations==1&&collector.CacheHits==32,"unchanged actor SHA256/signature cache avoids repeated expensive work");
        var indexDirectory=Path.Combine(directory,"kernel-actor-intake");var validIndex=Directory.GetFiles(indexDirectory,"*.process.json").Single();
        var corruptIndex=Path.Combine(indexDirectory,"000-damaged.process.json");File.WriteAllText(corruptIndex,"{damaged");
        var misplacedIndex=Path.Combine(indexDirectory,"001-misplaced.process.json");File.Copy(validIndex,misplacedIndex);File.Copy(validIndex+".wal",misplacedIndex+".wal");
        var recoveryHealth=new List<string>();var recoveredStore=new WindowsStagedActorStore(directory,sensor);
        using var restored=recoveredStore.CaptureSyscall(observed,wire.Provider,epoch,p=>p,out var restoredValue,recoveryHealth.Add);
        Check(restored.Image!=null&&restored.Acquisition?.SnapshotSha256==hash,"restart links committed proactive snapshot");
        Check(recoveryHealth.Count==2&&recoveryHealth.Any(x=>x.Contains("damaged"))&&recoveryHealth.Any(x=>x.Contains("misplaced")),"recovery rejects damaged and renamed index independently with visible diagnostics");
        using var absentAfterRecovery=recoveredStore.CaptureSyscall(observed,wire.Provider,epoch+1,p=>p,out _,recoveryHealth.Add);
        Check(absentAfterRecovery.Image==null&&absentAfterRecovery.Binding.Reason.Contains("recovery-records-rejected"),"missing actor after partial recovery explicitly reports rejected records");
        File.Delete(corruptIndex);File.Delete(misplacedIndex);File.Delete(misplacedIndex+".wal");
        var changed=o with{Native=native with{ProcessCreatedFileTime=native.ProcessCreatedFileTime+1}};var reused=WindowsSyscallEvent.Create(sensor,changed);
        using var wrong=store.CaptureSyscall(reused,wire.Provider,epoch,p=>p,out _);Check(wrong.Image==null,"PID reuse cannot borrow old executable bytes");
        using var wrongEpoch=store.CaptureSyscall(observed,wire.Provider,epoch+1,p=>p,out _);Check(wrongEpoch.Image==null,"different acquisition provider epoch refused");
        await using var pipeline=new ForensicPipeline(sensor,Path.Combine(directory,"pipeline"),_=>{});
        var pair=pipeline.CollectForPublication(value,actor,new());var journal=new WindowsSyscallJournal(directory,sensor);journal.Put(raw[..408],o);journal.Prepare(pair);pipeline.RegisterPublication(pair);
        File.WriteAllText(Path.Combine(directory,"ui-event.json"),JsonSerializer.Serialize(pair.Original,new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        using var spool=new EventSpool(directory,sensor);spool.Enqueue(pair.Original);spool.Enqueue(pair.Completion);journal.Complete(value.EventId);
        Check(spool.Count==2&&journal.Pending().Length==0,"preserved actor publication and upload intent integrated with durable sensor spool");
        var batch=spool.Peek();try{spool.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1,ProcessCreationVersion=1,ActorAcquisitionVersion=1});throw new Exception("Old server discarded syscall evidence");}catch(InvalidDataException){Check(spool.Count==2,"old server receipt cannot discard syscall evidence");}
        var receipt=server.Ingest(sensor,batch)!;Check(receipt.Accepted==2,"local server stores both versioned native and linked forensic events");
        using(var database=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(serverDirectory,"management.db"),Pooling=false}.ToString())){
            database.Open();using var command=database.CreateCommand();command.CommandText="DROP INDEX events_history_action_asc; CREATE INDEX events_history_action_asc ON events(sequence DESC,event_id DESC,endpoint);";command.ExecuteNonQuery();
        }
        var migrated=new Store(serverDirectory);Check(migrated.Events(0,100).Count==2,"action-index migration retains both original event payloads");
        using(var database=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(serverDirectory,"management.db"),Pooling=false}.ToString())){
            database.Open();using var command=database.CreateCommand();command.CommandText="SELECT sql FROM sqlite_master WHERE name='events_history_action_asc'";Check(((string)command.ExecuteScalar()!).Contains("Windows syscall",StringComparison.Ordinal),"old action index is replaced with syscall-aware expression");
        }
        var evidence=pair.Completion.Forensics!.Preservation;var manifest=File.ReadAllBytes(Path.Combine(directory,"pipeline",evidence.ManifestRelativePath!));
        var receiver=new EvidenceReceiver(server,serverDirectory);var upload=await receiver.Start(sensor,new(pair.Completion.EventId,Convert.ToBase64String(manifest)));
        using(var image=File.OpenRead(Path.Combine(directory,"pipeline",evidence.ArtifactRelativePath!))){var buffer=new byte[65536];long offset=0;int size;while((size=image.Read(buffer))>0){await receiver.Chunk(sensor,upload.EvidenceId,offset,buffer.AsSpan(0,size).ToArray());offset+=size;}}
        await receiver.Finish(sensor,upload.EvidenceId);
        using(var image=receiver.Download(sensor,upload.EvidenceId,false))Check(Convert.ToHexString(SHA256.HashData(image))==hash,"central receiver returns preserved executable with exact actor SHA256");
        using(var metadata=receiver.Download(sensor,upload.EvidenceId,true))using(var json=JsonDocument.Parse(metadata))Check(json.RootElement.GetProperty("ActorAcquisition").Deserialize<ActorAcquisitionEvidence>()!.SyscallRecordSha256==native.RawRecordSha256,"central manifest retains native source linkage");
        spool.Acknowledge(batch,receipt with{AttributionVersion=1,ForensicsVersion=1,ProcessCreationVersion=1,WindowsSyscallVersion=1});Check(spool.Count==0,"explicit syscall receipt allows sensor acknowledgement");
        var remaining=new List<AgentEvent>();for(var i=1;i<9;i++){
            var row=o with{Native=WindowsSyscallDecoder.Decode(raw.AsSpan(i*696,408).ToArray())};var observedRow=WindowsSyscallEvent.Create(sensor,row);
            using var unavailable=ActorLease.Capture(observedRow,sensor);remaining.Add(observedRow with{Forensics=collector.Complete(observedRow,unavailable,collector.Begin(observedRow,unavailable),new())});
        }
        await HttpCheck(serverDirectory,directory,sensor,enrollment.Credential,pair,hash,remaining.ToArray(),Check);
        var snapshot=actor.SnapshotPath!;actor.Dispose();restored.Dispose();File.Move(snapshot,snapshot+".original");File.WriteAllBytes(snapshot,bytes);
        try{using var replaced=store.CaptureSyscall(observed,wire.Provider,epoch,p=>p,out _);throw new Exception("Replaced snapshot accepted through cache");}
        catch(IOException){Check(true,"same bytes at replaced path fail stable identity validation despite cached verification");}
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,ActorIntegrationChecks=count,AcquisitionTransport="synthetic fixture",TokenEvidence="actual native capture",Executable="actual signed cmd.exe bytes",LiveIntakeQualified=false,Artifacts=directory}));
    }
    private static async Task HttpCheck(string serverDirectory,string directory,string sensor,string credential,PreparedForensicPublication pair,string hash,AgentEvent[] remaining,Action<bool,string> check)
    {
        var socket=new TcpListener(IPAddress.Loopback,0);socket.Start();var port=((IPEndPoint)socket.LocalEndpoint).Port;socket.Stop();var secret=Store.Secret();
        var start=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
        start.ArgumentList.Add(Path.GetFullPath("src/seQuester.Server/bin/Debug/net10.0/RansomFree.Server.dll"));
        foreach(var name in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")||k.StartsWith("Forensics__")).ToArray())start.Environment.Remove(name);
        start.Environment["RF_DATA_DIR"]=serverDirectory;start.Environment["RF_ADMIN_KEY"]=secret;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["DOTNET_ENVIRONMENT"]="Development";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";start.Environment["Logging__LogLevel__Default"]="Warning";
        using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
        try{
            var ready=false;for(var i=0;i<150;i++){if(process.HasExited)throw new Exception("Candidate HTTP server failed to start");try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}check(ready,"isolated candidate server API starts");
            using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress,Timeout=TimeSpan.FromSeconds(30)},credential);
            await client.HeartbeatAsync(new("fixture","controlled native evidence replay"){OperatingSystem="windows"});
            var receipt=await client.SendEventsAsync(new([pair.Original,pair.Completion]));check(receipt.WindowsSyscallVersion==1&&receipt.Duplicates==2,"actual HTTP capabilities and duplicate receipt acknowledge syscall schema");
            check((await client.SendEventsAsync(new(remaining))).Accepted==8,"candidate API accepts remaining actual native syscall scenarios with unavailable actors");
            check(await new EvidenceUploadQueue(Path.Combine(directory,"pipeline")).Pump(client)==1,"existing HTTP upload worker transfers version2 actor manifest and executable");
            using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{pair.Completion.Forensics!.Preservation.EvidenceId}/artifact");request.Headers.Authorization=new("Bearer",secret);
            using var response=await http.SendAsync(request);check(response.IsSuccessStatusCode&&Convert.ToHexString(SHA256.HashData(await response.Content.ReadAsByteArrayAsync()))==hash,"authenticated API download has exact preserved actor hash");
            using var historyRequest=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100");historyRequest.Headers.Authorization=new("Bearer",secret);
            using var historyResponse=await http.SendAsync(historyRequest);historyResponse.EnsureSuccessStatusCode();using var history=JsonDocument.Parse(await historyResponse.Content.ReadAsByteArrayAsync());
            var saved=history.RootElement.GetProperty("items").EnumerateArray().Select(x=>x.GetProperty("event")).Single(x=>x.GetProperty("eventId").GetString()==pair.Original.EventId);
            var f=saved.GetProperty("forensics");check(saved.GetProperty("attribution").GetProperty("windowsSyscall").GetProperty("native").GetProperty("rawRecordSha256").GetString()==pair.Original.Attribution!.WindowsSyscall!.Native.RawRecordSha256&&f.GetProperty("process").GetProperty("owner").GetProperty("sid").GetString()=="S-1-5-18"&&f.GetProperty("process").GetProperty("threadToken").GetProperty("sid").GetString()=="S-1-5-19","history API retains raw linkage and separate owner/impersonated identities");
            foreach(var (action,expected) in new[]{("Access Denied",6),("Operation Failed",2),("Copied/Read",1)}){
                using var filteredRequest=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100&action="+Uri.EscapeDataString(action));filteredRequest.Headers.Authorization=new("Bearer",secret);
                using var filteredResponse=await http.SendAsync(filteredRequest);filteredResponse.EnsureSuccessStatusCode();using var filtered=JsonDocument.Parse(await filteredResponse.Content.ReadAsByteArrayAsync());
                check(filtered.RootElement.GetProperty("items").EnumerateArray().Count(x=>x.GetProperty("event").GetProperty("source").GetString()=="Windows syscall")==expected,"SQL action filter classifies native "+action+" accurately");
            }
            using var osRequest=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=100&os=windows");osRequest.Headers.Authorization=new("Bearer",secret);
            using var osResponse=await http.SendAsync(osRequest);osResponse.EnsureSuccessStatusCode();using var osHistory=JsonDocument.Parse(await osResponse.Content.ReadAsByteArrayAsync());
            check(osHistory.RootElement.GetProperty("items").EnumerateArray().Count(x=>x.GetProperty("event").GetProperty("source").GetString()=="Windows syscall")==9,"Windows OS filter includes all nine syscall records after heartbeat");
        }
        finally{if(!process.HasExited)process.Kill(true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(directory,"http-server.log"),await stdout+await stderr);}
    }
}
