using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

static class NativeWorkTransportChecks
{
    internal static async Task Run(string serverDll,string deliveryRoot,string root,bool methodDetails=false,bool ownedRuntime=false,bool ownedRuntimeV2=false,bool nativeTrust=false,string? uiScript=null,string? atomicArchiveSha256=null,bool ioOperations=false)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated transport root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        AgentEvent[] ReadEvents(string file)
        {
            if(!ownedRuntime)return JsonSerializer.Deserialize<EventBatch>(File.ReadAllBytes(file))!.Events;
            using var doc=JsonDocument.Parse(File.ReadAllBytes(file));return [..doc.RootElement.GetProperty("Originals").Deserialize<AgentEvent[]>()!,..doc.RootElement.GetProperty("Completions").Deserialize<AgentEvent[]>()!];
        }
        var files=Directory.GetFiles(deliveryRoot,"events.json",SearchOption.AllDirectories).Order().ToArray();
        var events=files.SelectMany(ReadEvents).ToArray();
        int expectedEvents=14;
        if(ownedRuntime)
        {
            using var accepted=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(deliveryRoot,"RUNTIME-ACCEPTANCE.json")));var proof=accepted.RootElement;
            var archiveHash=atomicArchiveSha256??(nativeTrust?"a230b0a26c0067a18872ad71ea41dcba4e9d6ab310133cec232c132be5dc4cd2":ownedRuntimeV2?"041fd9209913832125a42750a8c03f562df04b3af8ef12bd9c1fa19e4fd4cafa":"8f898efe3a0a62a152c9322cf2d2396e22b49eff2fa88bd8d3fbcfae62fb94a9");
            Check(proof.GetProperty("Passed").GetBoolean()&&proof.GetProperty("ArchiveSha256").GetString()==archiveHash&&files.Length==1,"independently accepted exact native-runtime archive required");
            foreach(var item in proof.GetProperty("Files").EnumerateArray())
            {
                var path=Path.GetFullPath(Path.Combine(deliveryRoot,item.GetProperty("Path").GetString()!));
                if(!path.StartsWith(Path.GetFullPath(deliveryRoot)+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)||!Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).Equals(item.GetProperty("Sha256").GetString(),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Accepted native input file changed");
            }
            expectedEvents=proof.GetProperty("Events").GetInt32();Check(atomicArchiveSha256!=null?expectedEvents is >=4 and <=500&&expectedEvents%2==0:expectedEvents==10,"exact actual native original/completion inventory required");
            if(atomicArchiveSha256!=null)Check(events.All(e=>ioOperations?e.Attribution?.LinuxKernel is {Version:3,NativeSchemaVersion:7,PermissionObservation:not null} or {Version:4,NativeSchemaVersion:8,IoObservation:not null}:e.Attribution?.LinuxKernel is {Version:3,NativeSchemaVersion:7,PermissionObservation:not null}),"all atomic runtime records retain their versioned permission or I/O evidence");
            if(ownedRuntimeV2)Check(events.All(e=>e.Attribution?.LinuxKernel is {Version:2,NativeSchemaVersion:6,TargetIdentity:not null}),"actual composed-v2 records all retain target identity");
        }
        else if(methodDetails)
        {
            using var fixture=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(deliveryRoot,"RESULTS.json")));
            var cases=fixture.RootElement.TryGetProperty("Cases",out var count)?count.GetInt32():8;
            if(!fixture.RootElement.GetProperty("Passed").GetBoolean()||cases is <8 or >32||files.Length!=cases)throw new InvalidDataException("Completed exact serial-worker case inventory required");
            expectedEvents=2*cases;
        }
        Check(events.Length==expectedEvents&&events.Select(e=>e.EventId).Distinct().Count()==expectedEvents,"fixture contains exact distinct original/completion inventory");
        var sensor=events[0].Forensics!.SensorId;Check(events.All(e=>e.Forensics!.SensorId==sensor&&(methodDetails?e.Forensics.ActorExecutable.LinuxNativeWork!=null:e.Forensics.ActorExecutable.LinuxNativeWork?.State=="PIN_INTERRUPTED_UNKNOWN")),"all replay records retain same sensor and explicit native outcome");
        var requiredVersion=LinuxNativeWorkEvidence.RequiredVersion(events);
        if(methodDetails)Check(requiredVersion==2&&events.Count(e=>e.Forensics!.ActorExecutable.LinuxNativeWork!.Version==2)==(ownedRuntime?expectedEvents:expectedEvents-4),"method evidence version inventory is exact");
        var store=new Store(Path.Combine(root,"server"));var enrolled=store.Enroll(new(store.CreateCode().Code,"SQ-NATIVE-WORK isolated replay","native-work-qa"))!;
        // This brand new fixture DB has no events or endpoint relationships.
        // Bind its test credential to the archived fixture sensor identity;
        // do not rewrite the immutable source events or forensic manifests.
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"server/management.db")}.ToString()))
        {c.Open();using var q=c.CreateCommand();q.CommandText="UPDATE endpoints SET id=$sensor WHERE id=$id";q.Parameters.AddWithValue("$sensor",sensor);q.Parameters.AddWithValue("$id",enrolled.EndpointId);Check(q.ExecuteNonQuery()==1,"isolated empty endpoint bound to fixture sensor");}
        TrustPolicy? nativePolicy=null;
        if(nativeTrust)
        {
            using var cache=JsonDocument.Parse(File.ReadAllBytes(Path.Combine(deliveryRoot,"evidence/trust-cache/managed-trust.json")));
            var assignment=cache.RootElement.GetProperty("Assignment").Deserialize<AssignedTrustPolicy>()!;assignment.Validate();nativePolicy=assignment.Policy;
            Check(assignment.EndpointId==sensor&&nativePolicy.Version==3&&events.Where(e=>e.Source=="Linux kernel").All(e=>e.Trust is {Version:3} t&&t.Result.Digest==assignment.Digest&&t.LinuxKernelBinding!.Matches(e)),"exact qualified native policy and all committed original bindings retained");
            store.InitializeTrustStorage();
            // Restore only the independently accepted policy into this empty fixture
            // history. Republishing would change its timestamp, revision and digest.
            using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"server/management.db")}.ToString());c.Open();
            using var tx=c.BeginTransaction();using var q=c.CreateCommand();q.Transaction=tx;
            q.CommandText="INSERT INTO trust_revisions(revision,created,actor,payload) VALUES($revision,$created,$actor,$payload); INSERT INTO trust_current(id,revision) VALUES(1,$revision)";
            q.Parameters.AddWithValue("$revision",nativePolicy.Revision);q.Parameters.AddWithValue("$created",nativePolicy.PublishedUtc.ToUnixTimeMilliseconds());q.Parameters.AddWithValue("$actor",nativePolicy.Actor);q.Parameters.AddWithValue("$payload",JsonSerializer.Serialize(nativePolicy));q.ExecuteNonQuery();tx.Commit();
            Check(store.ReadTrustPolicy().Digest()==assignment.Digest,"server restores exact qualified policy history without rewriting native events");
        }
        foreach(var (capable,ack) in new[]{(false,true),(true,false)})
        {
            var handler=new NativeWorkCapabilityHandler(capable,ack,requiredVersion);
            using var blocked=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},enrolled.Credential);
            try{await blocked.SendEventsAsync(new([events.First(e=>e.Forensics!.ActorExecutable.LinuxNativeWork!.Version==requiredVersion)]));throw new Exception("Missing timeline support accepted");}
            catch(InvalidDataException){Check(handler.Events==(capable?1:0),"missing capability or acknowledgement retains timeline without false acceptance");}
        }
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();var admin=Store.Secret();
        var start=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(serverDll));
        foreach(var key in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())start.Environment.Remove(key);
        start.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");start.Environment["RF_ADMIN_KEY"]=admin;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";
        start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";
        using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
        try
        {
            var ready=false;
            for(var i=0;i<150;i++){if(process.HasExited)throw new Exception(await stderr);try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}
            Check(ready,"isolated real HTTP server starts");using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},enrolled.Credential);
            if(nativeTrust)
            {
                foreach(var version in new[]{0,3})
                {
                    using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/trust-policy"){Content=JsonContent.Create(new TrustCapabilitiesReport(1,version,version==3?1:0,"linux"))};request.Headers.Authorization=new("Bearer",enrolled.Credential);
                    using var response=await http.SendAsync(request);
                    Check(response.StatusCode==(version==3?HttpStatusCode.OK:HttpStatusCode.Conflict),"real policy endpoint enforces parser version "+version);
                    if(version==3){var assignment=(await response.Content.ReadFromJsonAsync<AssignedTrustPolicy>())!;Check(assignment.Digest==nativePolicy!.Digest()&&JsonSerializer.Serialize(assignment.Policy)==JsonSerializer.Serialize(nativePolicy),"real policy assignment retains exact native policy bytes and digest");}
                }
                foreach(var version in new[]{0,3})
                {
                    using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/trust-policy/receipt"){Content=JsonContent.Create(new TrustPolicyReceipt(1,nativePolicy!.Revision,nativePolicy.Digest(),null,"enforce"){PolicyVersion=version})};request.Headers.Authorization=new("Bearer",enrolled.Credential);
                    using var response=await http.SendAsync(request);Check(response.StatusCode==(version==3?HttpStatusCode.NoContent:HttpStatusCode.Conflict),"real policy receipt requires explicit parser version "+version);
                }
            }
            var spool=new EventSpool(Path.Combine(root,"spool"),sensor);foreach(var e in events)spool.Enqueue(e);
            var batch=spool.Peek();
            if(methodDetails)
            {
                try{spool.Acknowledge(batch,new(batch.Events.Length,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=1});throw new Exception("v1 receipt removed v2 evidence");}
                catch(InvalidDataException){Check(spool.Count==expectedEvents,"old v1 acknowledgement cannot remove structured v2 method evidence");}
            }
            // The production spool limits payload bytes as well as event count.
            // Deliver each actual prefix and check its receipt before advancing.
            var accepted=0;var batches=0;var acceptedIds=new HashSet<string>();
            while(spool.Count>0)
            {
                batch=spool.Peek();var before=spool.Count;
                Check(batch.Events.Length>0&&batch.Events.All(e=>acceptedIds.Add(e.EventId)),"bounded FIFO batch contains only new expected events");
                var receipt=await client.SendEventsAsync(batch);
                Check(receipt.Accepted==batch.Events.Length&&receipt.Duplicates==0&&receipt.LinuxNativeWorkVersion==2&&(!ioOperations||receipt.LinuxIoObservationVersion==1),"authenticated server explicitly accepts exact native timeline batch");
                if(nativeTrust)Check(receipt.WhitelistVersion==1&&receipt.LinuxKernelTrustVersion==1,"real durable receipt explicitly acknowledges native policy evidence");
                spool.Acknowledge(batch,receipt);accepted+=receipt.Accepted;batches++;
                Check(spool.Count==before-batch.Events.Length,"exact acknowledgement advances only its FIFO prefix");
            }
            Check(accepted==expectedEvents&&acceptedIds.SetEquals(events.Select(e=>e.EventId)),"all bounded batches deliver full native timeline inventory without loss or duplication");
            foreach(var e in events)
            {
                Check(JsonSerializer.Serialize(store.Events(0,500).Single(x=>x.Event.EventId==e.EventId).Event)==JsonSerializer.Serialize(e),"database retains exact event: "+e.EventId);
                var alert=new Alert(e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process??"Unavailable",e.User??"Unavailable",e.Source){EventId=e.EventId,ProcessId=e.ProcessId,Attribution=e.Attribution,Trust=e.Trust,Forensics=e.Forensics,EndpointId=sensor};
                var formatted=Encoding.UTF8.GetString(SyslogClient.Format(alert,new(){Format="RFC5424"}));using var json=JsonDocument.Parse(formatted[formatted.IndexOf('{')..]);
                Check(JsonSerializer.Serialize(json.RootElement.GetProperty("Forensics").Deserialize<ForensicEvidence>())==JsonSerializer.Serialize(e.Forensics),"SIEM retains unknown native outcome and exact forensic evidence: "+e.EventId);
                if(nativeTrust&&e.Trust is {} claim)
                {
                    Check(JsonSerializer.Serialize(json.RootElement.GetProperty("Trust").Deserialize<EventTrust>())==JsonSerializer.Serialize(claim),"SIEM retains exact bound native policy evidence");
                    using var quiet=new SyslogOutbox(Path.Combine(root,"syslog",e.EventId),enabled:false);var options=new SyslogOptions{Enabled=true,Host="127.0.0.1"};quiet.Enqueue(alert,options);
                    Check(quiet.Count==(claim.Result.Decision.LogOnly?0:1),"local notification queue respects only valid committed native log-only decisions");
                    quiet.Enqueue(alert with{ProcessId=alert.ProcessId+1},options);
                    Check(quiet.Count==(claim.Result.Decision.LogOnly?1:2),"mismatched actor cannot inherit native log-only suppression");
                }
            }
            using(var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500"))
            {
                request.Headers.Authorization=new("Bearer",admin);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var history=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;
                Check(history.Items.Count==expectedEvents&&history.Items.All(x=>JsonSerializer.Serialize(x.Event)==JsonSerializer.Serialize(events.Single(e=>e.EventId==x.Event.EventId))),"history API exposes all original user/process/PID fields and native timeline without loss");
                if(nativeTrust)Check(history.Items.Count(x=>x.TrustClassification=="LogOnly")==4&&history.Items.Count(x=>x.TrustClassification=="NonWhitelisted")==3&&history.Items.Count(x=>x.TrustClassification=="Informational")==3,"real history independently classifies two allowed originals and their completions plus three alerting originals");
                File.WriteAllBytes(Path.Combine(root,"history.json"),JsonSerializer.SerializeToUtf8Bytes(history));
            }
            if(ownedRuntimeV2)
            {
                using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/event-history?limit=500&action=Open%20Requested");request.Headers.Authorization=new("Bearer",admin);using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var history=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;
                Check(history.Items.Count==5&&history.Items.All(x=>x.Event.Source=="Linux kernel"&&x.Activity.Outcome=="unknown"),"all five actual v2 opens appear in database action filter without invented final success");
            }
            var sample=events.First(e=>e.Forensics!.ActorExecutable.LinuxNativeWork!.Version==requiredVersion);var f=sample.Forensics!;var native=f.ActorExecutable.LinuxNativeWork!;
            var corruptions=new List<LinuxNativeWorkEvidence>{native with{Cookie="0"},native with{AuthorizationId=null,StartingGeneration=99},native with{SourceEventId=Guid.NewGuid().ToString("N")}};
            if(methodDetails){corruptions.Add(native with{Method=null});corruptions.Add(native with{Method=native.Method! with{DropMethodAttempted=false,DropMethodReturned=true}});corruptions.Add(native with{Method=native.Method! with{PinId=Guid.NewGuid().ToString("N")}});}
            foreach(var altered in corruptions)
            {
                using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events"){Content=JsonContent.Create(new EventBatch([sample with{Forensics=f with{ActorExecutable=f.ActorExecutable with{LinuxNativeWork=altered}}}]))};
                request.Headers.Authorization=new("Bearer",enrolled.Credential);using var response=await http.SendAsync(request);
                Check(response.StatusCode==HttpStatusCode.BadRequest&&store.Events(0,500).Count==expectedEvents,"server rejects contradictory native timeline before persistence");
            }
            var selected=ownedRuntime?events.Where(e=>e.Forensics!.Preservation.Status.State=="captured").ToArray():[methodDetails?events.First(e=>e.Forensics!.Preservation.Status.State=="captured"&&e.Forensics.ActorExecutable.LinuxNativeWork!.Method?.LastStep=="DROP_METHOD"):events.Single(e=>e.Forensics!.Preservation.Status.State=="captured")];
            Check(atomicArchiveSha256!=null?selected.Length==events.Count(e=>e.Source=="Forensic enrichment"&&(e.Attribution!.LinuxKernel!.PermissionObservation?.Stage==1||ioOperations&&e.Attribution.LinuxKernel.IoObservation?.Stage==1)&&e.Forensics!.Preservation.Status.State=="captured"):selected.Length==(nativeTrust?3:ownedRuntime?5:1),"exact actor-preservation inventory selected for central verification");
            var copyRoot=Path.GetDirectoryName(files.Single(file=>ReadEvents(file).Any(e=>e.EventId==selected[0].EventId)))!;
            // Copy only the owned fixture's evidence tree into this transport
            // workspace so running the upload cannot mutate the crash receipt.
            foreach(var file in Directory.GetFiles(Path.Combine(copyRoot,"evidence"),"*",SearchOption.AllDirectories))
            {var destination=Path.Combine(root,"evidence",Path.GetRelativePath(Path.Combine(copyRoot,"evidence"),file));Directory.CreateDirectory(Path.GetDirectoryName(destination)!);File.Copy(file,destination,false);}
            var uploads=new EvidenceUploadQueue(root);var uploaded=0;
            for(var pass=0;pass<(selected.Length+7)/8;pass++)uploaded+=await uploads.Pump(client);
            Check(uploaded==selected.Length,"all selected actor executables and manifests uploaded through bounded real-client passes");
            Check(await new EvidenceUploadQueue(root).Pump(client)==0,"confirmed upload remains idempotent after queue restart");
            foreach(var completion in selected)
            {
            var preservation=completion.Forensics!.Preservation;
            var received=store.EvidenceReceipt(sensor,preservation.EvidenceId!)!;
            Check(received.State=="received"&&received.Sha256==preservation.Sha256&&received.Size==preservation.Size,"central possession verifies actor bytes independently of unknown native return");
            foreach(var kind in new[]{"artifact","manifest"})
            {
                using var request=new HttpRequestMessage(HttpMethod.Get,$"/api/v1/admin/actor-evidence/{sensor}/{preservation.EvidenceId}/{kind}");request.Headers.Authorization=new("Bearer",admin);
                using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var bytes=await response.Content.ReadAsByteArrayAsync();
                Check(Convert.ToHexString(SHA256.HashData(bytes))==(kind=="artifact"?preservation.Sha256:preservation.ManifestSha256),"central downloaded "+kind+" matches original hash");
                if(kind=="manifest")
                {using var manifest=JsonDocument.Parse(bytes);Check(manifest.RootElement.GetProperty("LinuxNativeWork").Deserialize<LinuxNativeWorkEvidence>()==completion.Forensics.ActorExecutable.LinuxNativeWork,"downloaded manifest preserves unknown native timeline exactly");}
            }
            var possession=store.Events(0,500).Single(x=>x.Event.EventId==received.ReceiptId).Event;
            Check(possession.Source=="Evidence transfer"&&LinuxKernelEvidence.Matches(possession)&&possession.Forensics!.ActorExecutable.LinuxNativeWork==completion.Forensics.ActorExecutable.LinuxNativeWork,"server possession event preserves source native timeline without claiming native success");
            }
            if(uiScript!=null)
            {
                if(!nativeTrust&&atomicArchiveSha256==null)throw new ArgumentException("Accepted native fixture required for its packaged UI check");
                var uiStart=new ProcessStartInfo(@"C:\Program Files\nodejs\node.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
                uiStart.ArgumentList.Add(Path.GetFullPath(uiScript));uiStart.ArgumentList.Add(http.BaseAddress!.GetLeftPart(UriPartial.Authority));uiStart.ArgumentList.Add(Path.Combine(root,"ui"));
                uiStart.Environment["RF_NATIVE_UI_ADMIN"]=admin;uiStart.Environment["RF_NATIVE_UI_CREDENTIAL"]=enrolled.Credential;
                using var ui=Process.Start(uiStart)!;var uiOut=ui.StandardOutput.ReadToEndAsync();var uiError=ui.StandardError.ReadToEndAsync();await ui.WaitForExitAsync();
                File.WriteAllText(Path.Combine(root,"ui.stdout.txt"),await uiOut);File.WriteAllText(Path.Combine(root,"ui.stderr.txt"),await uiError);Check(ui.ExitCode==0,"actual authenticated packaged browser acceptance passes");
            }
            File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,OriginalEvents=expectedEvents,Batches=batches,ActualUploads=selected.Length,StoredEvents=store.Events(0,500).Count,MethodVersion=requiredVersion,Scope=ownedRuntime?"Exact accepted actual Linux runtime evidence through isolated authenticated HTTP, database/history, SIEM and central artifact/manifest upload/download; no production deployment":"Actual isolated authenticated HTTP, database/history, SIEM formatting and central copy upload/download of controlled fixture; no production or native kernel activation"}));
            Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Root=root}));
        }
        finally{if(!process.HasExited)process.Kill(entireProcessTree:true);await process.WaitForExitAsync();File.WriteAllText(Path.Combine(root,"server.stdout.txt"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr.txt"),await stderr);}
    }
    private sealed class NativeWorkCapabilityHandler(bool capable,bool acknowledge,int version):HttpMessageHandler
    {
        internal int Events;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            object value;
            if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities"))value=new{AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,LinuxKernelTrustVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=capable?version:version-1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1};
            else{Events++;value=new BatchReceipt(1,0){AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,LinuxKernelTrustVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=acknowledge?version:version-1,LinuxPermissionObservationVersion=1,LinuxIoObservationVersion=1};}
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(value)});
        }
    }
}
