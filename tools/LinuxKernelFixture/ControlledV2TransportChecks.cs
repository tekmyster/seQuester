using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class ControlledV2TransportChecks
{
    internal static async Task Run(string serverDll,string archivePath,string legacySeed,string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated workspace required");Directory.CreateDirectory(root);
        var checks=0;void Check(bool ok,string label){if(!ok)throw new InvalidDataException(label);checks++;}
        var archive=File.ReadAllBytes(archivePath);
        Check(Convert.ToHexString(SHA256.HashData(archive))=="91C8BF4C03BF5E5672ECF518C458EFED06083F9C93A671987B5E870D4DCB3238","Exact accepted native R3 archive");
        var files=new Dictionary<string,byte[]>(StringComparer.Ordinal);
        using(var gzip=new GZipStream(new MemoryStream(archive),CompressionMode.Decompress))
        using(var tar=new TarReader(gzip))
            while(tar.GetNextEntry() is {} entry)
            {
                if(entry.EntryType is TarEntryType.ExtendedAttributes or TarEntryType.GlobalExtendedAttributes)continue;
                Check(entry.EntryType==TarEntryType.RegularFile&&Path.GetFileName(entry.Name)==entry.Name&&entry.Length<8*1024*1024&&!files.ContainsKey(entry.Name),"Unique bounded regular archive entry");
                using var bytes=new MemoryStream();if(entry.DataStream!=null)entry.DataStream.CopyTo(bytes);Check(bytes.Length==entry.Length,"Exact archive entry length including empty diagnostics");files.Add(entry.Name,bytes.ToArray());
            }
        using var manifest=JsonDocument.Parse(files["RESULTS.json"]);
        Check(manifest.RootElement.GetProperty("Passed").GetBoolean()&&manifest.RootElement.GetProperty("Cases").GetArrayLength()==5,"Five accepted native cases");
        var store=new Store(Path.Combine(root,"server"));var enrolled=store.Enroll(new(store.CreateCode().Code,"SQ controlled-v2 archived native replay","controlled-v2-qa"))!;
        var collector=new ForensicCollector(enrolled.EndpointId,root);var uploads=new EvidenceUploadQueue(root);
        var events=new List<AgentEvent>();var originals=new List<AgentEvent>();var copied=new List<AgentEvent>();var rawHashes=new List<string>();
        foreach(var item in manifest.RootElement.GetProperty("Cases").EnumerateArray())
        {
            var name=item.GetProperty("Name").GetString()!;var bytes=files[name+".stdout.jsonl"];var instance=Guid.NewGuid().ToString("N");long sequence=0;
            LinuxControlledLoaderProtocol.Ready? ready=null;
            var offset=0;
            while(offset<bytes.Length)
            {
                var end=Array.IndexOf(bytes,(byte)'\n',offset);Check(end>=offset,"Complete exact native frame");
                var raw=new ReadOnlyMemory<byte>(bytes,offset,end-offset);offset=end+1;using var doc=JsonDocument.Parse(raw);var record=doc.RootElement;
                if(record.TryGetProperty("controlledReady",out _)){ready=LinuxControlledLoaderProtocol.ParseReady(raw);continue;}
                if(!record.TryGetProperty("pid",out _))continue;
                var e=LinuxKernelDecoder.Decode(raw,enrolled.EndpointId,instance,++sequence,DateTimeOffset.UtcNow);var kernel=e.Attribution!.LinuxKernel!;var target=kernel.TargetIdentity!;
                Check(ready?.Targets?.Contains(target.Ordinal,target.Device,ulong.Parse(target.Inode))==true,"Native operation belongs to exact ready target set");
                Check(kernel.NativeObservationSha256==Convert.ToHexString(SHA256.HashData(raw.Span)),"Raw frame hashed without reserialization");rawHashes.Add(kernel.NativeObservationSha256);
                using var actor=ActorLease.Capture(e,enrolled.EndpointId);
                var matches=item.GetProperty("ActorEvidence").EnumerateArray().Where(x=>x.GetProperty("Event").GetProperty("cookie").GetUInt64()==record.GetProperty("cookie").GetUInt64()).ToArray();
                Check(matches.Length==(kernel.Lease>0?1:0),"Exact native capture or explicit missing copy");
                if(matches.Length==1)
                {
                    var proof=matches[0];var tuple=proof.GetProperty("NativeTuple");Check(tuple.GetArrayLength()==24,"Native status ABI");var statusBytes=new byte[160];
                    for(var n=0;n<16;n++)BinaryPrimitives.WriteUInt64LittleEndian(statusBytes.AsSpan(n*8),tuple[n].GetUInt64());
                    for(var n=16;n<24;n++)BinaryPrimitives.WriteInt32LittleEndian(statusBytes.AsSpan(128+(n-16)*4),tuple[n].GetInt32());
                    var status=LinuxActorLeaseStatus.Decode(statusBytes).ToEvidence();Check(status.Ready&&status.Matches(kernel),"Archived capture matches complete process instance");
                    var image=files[proof.GetProperty("Artifact").GetString()!];var sha=Convert.ToHexString(SHA256.HashData(image));Check(sha.Equals(proof.GetProperty("Sha256").GetString(),StringComparison.OrdinalIgnoreCase),"Exact captured actor bytes independently hashed");
                    var id=Guid.NewGuid().ToString("N");var path=Path.Combine(root,id+".bin");
                    using(var output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){output.Write(image);output.Flush(true);}
                    actor.Image=File.OpenRead(path);actor.SnapshotFile=NativeFileIdentity.Read(actor.Image);actor.SnapshotPath=path;
                    actor.File=new(){StableId=status.SourceStableId,Size=image.Length,Status=EvidenceStatus.Captured("archived-native-device-inode; source-timestamps-unavailable")};
                    actor.LinuxAcquisition=new(){SourceEventId=e.EventId,NativeObservationSha256=kernel.NativeObservationSha256,NativeStatus=status,SnapshotId=id,SnapshotSha256=sha,SnapshotFile=actor.SnapshotFile,PersistedUtc=DateTimeOffset.UtcNow,SizeMatchesEarlierObservation=status.Size==kernel.ActorSize,Status=EvidenceStatus.Captured("archived-native-contract-replay; not-live-sensor-capture")};
                    actor.Binding=EvidenceStatus.Captured("archived-full-native-tuple-replay");actor.BindingSourceEventId=e.EventId;actor.BindingCapturedUtc=actor.LinuxAcquisition.PersistedUtc;
                }
                var begun=collector.Begin(e,actor);var complete=collector.Complete(e,actor,begun,new());var original=e with{Forensics=begun};
                var linked=collector.LinkCompletion(complete,Guid.NewGuid().ToString("N"));var completion=e with{EventId=linked.EventId,Source="Forensic enrichment",Operation="Archived actor acquisition contract replay",Forensics=linked};
                Check(begun.IsValid()&&linked.IsValid()&&LinuxKernelEvidence.Matches(original)&&LinuxKernelEvidence.Matches(completion),"Target identity survives common forensic collector");
                Check(linked.Observation.File.StableId==target.StableId&&linked.Observation.HashPolicy=="not-hashed-by-forensic-collector","Target metadata retained without target hashing");
                Check(kernel.Lease>0?linked.Preservation is {Status.State:"captured",HashMatched:true}:linked.ActorExecutable.Sha256==null&&linked.Preservation.Status.State=="unavailable","Copy/hash status reflects actual native capture");
                events.Add(original);events.Add(completion);originals.Add(original);uploads.Register(original,completion);
                if(matches.Length==1)copied.Add(completion);
            }
        }
        Check(originals.Count==13&&copied.Count==12&&originals.Count(e=>e.Attribution!.LinuxKernel!.Lease<0)==1,"All13 operations and12 actor copies remain represented");
        using var seed=JsonDocument.Parse(File.ReadAllBytes(legacySeed));
        Check(seed.RootElement.GetProperty("SourceArchiveSha256").GetString()=="a0b444564eb2e7477f154ce52c0c0ec6c0c2dbb6512e3befbac314f370361eca","Immutable legacy schema5 seed");
        var legacy=LinuxKernelDecoder.Decode(Convert.FromBase64String(seed.RootElement.GetProperty("Native").GetString()!),enrolled.EndpointId,Guid.NewGuid().ToString("N"),1,DateTimeOffset.UtcNow);
        Check(legacy.Attribution!.LinuxKernel!.Version==1&&!JsonSerializer.Serialize(legacy.Attribution.LinuxKernel).Contains("TargetIdentity"),"Legacy canonical evidence does not gain a null field");
        events.Add(legacy);
        foreach(var (required,baseVersion,targetVersion,expected) in new[]{(0,0,0,true),(1,1,0,true),(1,1,1,true),(2,1,0,false),(2,1,1,true),(2,0,1,false),(2,2,1,false),(2,1,2,false),(3,1,1,false)})
            Check(LinuxKernelEvidence.Supports(required,baseVersion,targetVersion)==expected,"Explicit version compatibility");
        foreach(var (cap,ack) in new[]{(0,1),(2,1),(1,0),(1,2)})
        {
            using var handler=new CapabilityHandler(cap,ack);using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},enrolled.Credential);
            try{await client.SendEventsAsync(new([originals[0]]));throw new Exception("Unsupported target identity accepted");}
            catch(InvalidDataException){Check(handler.Events==(cap==1?1:0),"Missing/unknown target support blocks POST or receipt");}
        }
        using(var handler=new CapabilityHandler(0,0))
        using(var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},enrolled.Credential))
        {await client.SendEventsAsync(new([legacy]));Check(handler.Events==1,"Legacy client evidence works without additive target capability");}
        var spool=new EventSpool(Path.Combine(root,"spool"),enrolled.EndpointId);foreach(var e in events)spool.Enqueue(e);var firstBatch=spool.Peek();
        foreach(var targetVersion in new[]{0,2})
        {
            try{spool.Acknowledge(firstBatch,new(firstBatch.Events.Length,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1,LinuxKernelTargetIdentityVersion=targetVersion});throw new Exception("Unsupported receipt discarded queue");}
            catch(InvalidDataException){Check(spool.Count==27,"Unknown or missing target receipt preserves queue");}
        }
        Check(new EventSpool(Path.Combine(root,"spool"),enrolled.EndpointId).Count==27,"All evidence retained across spool reopen");
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var admin=Store.Secret();
        var start=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(serverDll));
        foreach(var key in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())start.Environment.Remove(key);
        start.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");start.Environment["RF_ADMIN_KEY"]=admin;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";
        using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
        try
        {
            var ready=false;for(var i=0;i<150;i++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}Check(ready,"Isolated HTTP server starts");
            using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},enrolled.Credential);
            using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/capabilities"){Content=JsonContent.Create(new{})})
            {request.Headers.Authorization=new("Bearer",enrolled.Credential);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();using var doc=JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());Check(doc.RootElement.GetProperty("linuxKernelVersion").GetInt32()==1&&doc.RootElement.GetProperty("linuxKernelTargetIdentityVersion").GetInt32()==1,"Old base capability preserved with additive target support");}
            var batches=0;while(spool.Count>0){var batch=spool.Peek();var receipt=await client.SendEventsAsync(batch);Check(receipt.Accepted==batch.Events.Length&&receipt.LinuxKernelVersion==1&&receipt.LinuxKernelTargetIdentityVersion==1,"Server explicitly acknowledges target evidence");spool.Acknowledge(batch,receipt);batches++;}
            Check(store.Events(0,500).Count==27,"All events persisted");
            foreach(var e in events)
            {
                Check(JsonSerializer.Serialize(store.Events(0,500).Single(x=>x.Event.EventId==e.EventId).Event)==JsonSerializer.Serialize(e),"Exact event database round trip");
                var alert=new Alert(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process??"Unavailable",e.User??"Unavailable",e.Source){EventId=e.EventId,ProcessId=e.ProcessId,Attribution=e.Attribution,Forensics=e.Forensics,EndpointId=enrolled.EndpointId};
                var text=Encoding.UTF8.GetString(SyslogClient.Format(alert,new(){Format="RFC5424"}));using var siem=JsonDocument.Parse(text[text.IndexOf('{')..]);
                Check(JsonSerializer.Serialize(siem.RootElement.GetProperty("Attribution").GetProperty("LinuxKernel").Deserialize<LinuxKernelEvidence>())==JsonSerializer.Serialize(e.Attribution!.LinuxKernel),"SIEM retains exact native fields and target identity");
            }
            using(var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500"))
            {
                request.Headers.Authorization=new("Bearer",admin);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var history=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;
                Check(history.Items.Count==27&&history.Items.All(x=>JsonSerializer.Serialize(x.Event)==JsonSerializer.Serialize(events.Single(e=>e.EventId==x.Event.EventId))),"API history exposes exact user/process/PID and target fields");File.WriteAllBytes(Path.Combine(root,"history.json"),JsonSerializer.SerializeToUtf8Bytes(history));
                Check(history.Items.All(x=>x.Activity.Outcome=="unknown"&&x.DisplayOperation==(x.Event.Source=="Linux kernel"?"Open Requested":"Forensic Evidence")),"Both schemas display honest pre-open and forensic actions");
            }
            foreach(var (action,count) in new[]{("Open Requested",14),("Forensic Evidence",13),("File Opened",0)})
            {
                using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500&action="+Uri.EscapeDataString(action));request.Headers.Authorization=new("Bearer",admin);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var history=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;
                Check(history.Items.Count==count,"Database action filter includes both native schemas: "+action);
            }
            var sample=originals[0];var k=sample.Attribution!.LinuxKernel!;
            foreach(var bad in new[]{sample with{Attribution=sample.Attribution with{LinuxKernel=k with{TargetIdentity=null}}},sample with{Attribution=sample.Attribution with{TargetStableId="different"}},sample with{Attribution=sample.Attribution with{LinuxKernel=k with{TargetIdentity=k.TargetIdentity! with{Ordinal=32}}}},sample with{Attribution=sample.Attribution with{LinuxKernel=k with{Version=1}}},sample with{Forensics=sample.Forensics! with{Observation=sample.Forensics.Observation with{File=sample.Forensics.Observation.File with{StableId=null}}}}})
            {
                using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events"){Content=JsonContent.Create(new EventBatch([bad]))};request.Headers.Authorization=new("Bearer",enrolled.Credential);using var response=await http.SendAsync(request);Check(response.StatusCode==HttpStatusCode.BadRequest&&store.Events(0,500).Count==27,"Server rejects contradictory target identity before persistence");
            }
            Check(await uploads.Pump(client)==8&&await uploads.Pump(client)==4&&await new EvidenceUploadQueue(root).Pump(client)==0,"Twelve actor copies uploaded in bounded8+4 passes and retry is idempotent");
            foreach(var completion in copied)
            {
                var preserved=completion.Forensics!.Preservation;var received=store.EvidenceReceipt(enrolled.EndpointId,preserved.EvidenceId!)!;
                Check(received.State=="received"&&received.Sha256==preserved.Sha256&&received.Size==preserved.Size,"Central receipt matches actor evidence");
                foreach(var kind in new[]{"artifact","manifest"})
                {
                    using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{enrolled.EndpointId}/{preserved.EvidenceId}/{kind}");request.Headers.Authorization=new("Bearer",admin);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var bytes=await response.Content.ReadAsByteArrayAsync();
                    Check(Convert.ToHexString(SHA256.HashData(bytes))==(kind=="artifact"?preserved.Sha256:preserved.ManifestSha256),"Downloaded central "+kind+" hash verified");
                }
                var possession=store.Events(0,500).Single(x=>x.Event.EventId==received.ReceiptId).Event;Check(LinuxKernelEvidence.Matches(possession)&&possession.Attribution!.LinuxKernel==completion.Attribution!.LinuxKernel,"Central possession preserves schema6 target and process evidence");
            }
            Check(store.Events(0,500).Count==39,"27 replay events plus12 central possession records");
            var result=new{Passed=true,Checks=checks,NativeOperations=13,OriginalAndCompletionEvents=26,LegacyEvents=1,Batches=batches,ActorUploads=12,StoredEvents=39,UnavailableCopies=1,NativeFrameSha256=rawHashes,Scope="Exact archived native R3 observations/status/actor bytes through common forensic collector and isolated authenticated HTTP/database/history/SIEM/upload/download. Contract replay, not live installed runtime or production rollout."};
            File.WriteAllBytes(Path.Combine(root,"RESULTS.json"),JsonSerializer.SerializeToUtf8Bytes(result));Console.WriteLine(JsonSerializer.Serialize(result));
        }
        finally{if(!process.HasExited)process.Kill(entireProcessTree:true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr.txt"),await stderr);}
    }
    private sealed class CapabilityHandler(int targetCapability,int targetReceipt):HttpMessageHandler
    {
        internal int Events;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            object value;if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities"))value=new{AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1,LinuxKernelTargetIdentityVersion=targetCapability};
            else{Events++;value=new BatchReceipt(1,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1,LinuxKernelTargetIdentityVersion=targetReceipt};}
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(value)});
        }
    }
}
