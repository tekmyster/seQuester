using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

static class TransportChecks
{
    internal static async Task Run(string? serverAssembly)
    {
        var root=Path.Combine(@"D:\Codex\RansomFree\boundary-20261006","acquisition-transport-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        int checks=0;void Check(bool b,string message){if(!b)throw new Exception(message);checks++;}
        var raw=new byte[3800];void U32(int o,uint n)=>BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(o),n);void U64(int o,ulong n)=>BinaryPrimitives.WriteUInt64LittleEndian(raw.AsSpan(o),n);
        U32(0,4);U32(4,3800);U64(8,10);U64(16,20);U64(24,(ulong)DateTimeOffset.UtcNow.ToFileTime());U64(32,(ulong)DateTimeOffset.UtcNow.ToFileTime());U32(72,31);U32(76,3);U32(3760,2);U64(3784,100);U64(3792,10000000);
        Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume1\owned-contract-fixture.txt").CopyTo(raw,240);
        var observed=WindowsKernelDecoder.Decode(raw,"isolated-acquisition-fixture",x=>x,false);
        const string provider="1234567890ABCDEF1234567890ABCDEF";var frame=new byte[128];
        BinaryPrimitives.WriteUInt32LittleEndian(frame,1);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4),128);Convert.FromHexString(provider).CopyTo(frame,8);
        foreach(var pair in new[]{(24,10UL),(32,10UL),(40,20UL),(80,100UL)})BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(pair.Item1),pair.Item2);
        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(88),0xC0000225);
        var acquisition=WindowsAcquisitionOutcomeProtocol.Evidence(WindowsAcquisitionOutcomeProtocol.Decode(frame,provider,10,10,20),Convert.ToHexString(SHA256.HashData(raw)));
        var sample=observed with{Attribution=observed.Attribution! with{WindowsKernel=observed.Attribution!.WindowsKernel! with{AcquisitionObservation=acquisition}}};
        Check(sample.Attribution!.IsValid()&&WindowsKernelEvidence.Matches(sample),"explicit unavailable actor retains a valid operation");
        var spool=new EventSpool(Path.Combine(root,"spool"),Guid.NewGuid().ToString("N"));spool.Enqueue(sample);var batch=spool.Peek();
        var receipt=new BatchReceipt(1,0){AttributionVersion=1,WindowsKernelVersion=4,WindowsAcquisitionObservationVersion=1};
        try{spool.Acknowledge(batch,receipt with{WindowsAcquisitionObservationVersion=0});throw new Exception("Old receipt accepted");}
        catch(InvalidDataException){Check(spool.Count==1&&JsonSerializer.Serialize(spool.Peek())==JsonSerializer.Serialize(batch),"old receipt preserves exact pending evidence");}
        foreach(var mode in new[]{"capability","receipt","success"})
        {
            using var handler=new Handler(mode,receipt);using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},new string('a',64));
            try
            {
                var accepted=await client.SendEventsAsync(batch);if(mode!="success")throw new Exception("Unsupported server accepted acquisition observation");
                Check(handler.EventPosts==1&&accepted.WindowsAcquisitionObservationVersion==1,"capable transport acknowledges observation schema explicitly");
            }
            catch(InvalidDataException)when(mode!="success")
            {Check(handler.EventPosts==(mode=="receipt"?1:0)&&spool.Count==1,"missing "+mode+" support withholds queue acknowledgement");}
        }
        var store=new Store(Path.Combine(root,"server"));var endpoint=store.Enroll(new(store.CreateCode().Code,"Owned acquisition contract fixture","qa"))!;
        var acceptedStore=store.Ingest(endpoint.EndpointId,batch,IPAddress.Loopback);
        Check(acceptedStore?.Accepted==1,"server persists event with explicit acquisition unavailability");
        var saved=store.Events(0,10).Single().Event;
        Check(JsonSerializer.Serialize(saved)==JsonSerializer.Serialize(sample),"database round trip retains full immutable event fields");
        var duplicate=store.Ingest(endpoint.EndpointId,batch,IPAddress.Loopback);Check(duplicate?.Duplicates==1&&store.Events(0,10).Count==1,"replay is idempotent without rewriting evidence");
        var tampered=sample with{EventId=Guid.NewGuid().ToString("N"),Attribution=sample.Attribution with{WindowsKernel=sample.Attribution.WindowsKernel! with{AcquisitionObservation=acquisition with{State=5}}}};
        Check(!tampered.Attribution.IsValid(),"manufactured acquisition success fails schema/hash validation");
        var recovery=acquisition with{Version=2,QueryAttempted=null,Status=EvidenceStatus.Unavailable("provider-retired-before-companion-commit"),ProcessGeneration=null,NegativeAssociation=null,OriginCandidate=null,OriginGeneration=null,ObservedQpc=null,NativeStatus=null,State=null,Stage=null,Certainty=null,Flags=null,RawSha256=null,RecoveryProvider="ABCDEF1234567890ABCDEF1234567890",RecoveryEpoch=11,RecoveryObservedUtc=DateTimeOffset.UtcNow};
        var recovered=sample with{EventId=Guid.NewGuid().ToString("N"),Attribution=sample.Attribution with{WindowsKernel=sample.Attribution.WindowsKernel! with{AcquisitionObservation=recovery}}};
        Check(recovered.Attribution.IsValid()&&WindowsKernelEvidence.Matches(recovered),"versioned recovery retains original operation while native outcome remains unavailable");
        var recoverySpool=new EventSpool(Path.Combine(root,"recovery-spool"),Guid.NewGuid().ToString("N"));recoverySpool.Enqueue(recovered);var recoveryBatch=recoverySpool.Peek();
        try{recoverySpool.Acknowledge(recoveryBatch,receipt);throw new Exception("Unacknowledged recovery accepted");}
        catch(InvalidDataException){Check(recoverySpool.Count==1,"observation-only receipt cannot discard recovered failure evidence");}
        foreach(var mode in new[]{"recovery-capability","recovery-receipt","success"})
        {
            using var handler=new Handler(mode,receipt);using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},new string('a',64));
            try{var accepted=await client.SendEventsAsync(recoveryBatch);if(mode!="success")throw new Exception("Unsupported recovery accepted");Check(accepted.WindowsAcquisitionRecoveryVersion==1&&handler.EventPosts==1,"supported transport explicitly acknowledges recovery schema");}
            catch(InvalidDataException)when(mode!="success"){Check(handler.EventPosts==(mode=="recovery-receipt"?1:0)&&recoverySpool.Count==1,"missing recovery "+mode+" preserves evidence");}
        }
        if(serverAssembly!=null)
        {
            var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
            var psi=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
            psi.ArgumentList.Add(Path.GetFullPath(serverAssembly));
            foreach(var name in psi.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())psi.Environment.Remove(name);
            psi.Environment["RF_DATA_DIR"]=Path.Combine(root,"server");psi.Environment["RF_ADMIN_KEY"]=Store.Secret();psi.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";
            psi.Environment["ASPNETCORE_ENVIRONMENT"]="Development";psi.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";psi.Environment["Database__Provider"]="Sqlite";psi.Environment["Logging__LogLevel__Default"]="Warning";
            using var process=Process.Start(psi)??throw new IOException("Isolated server failed to start");var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
            using var http=new HttpClient{BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
            try
            {
                bool ready=false;for(int i=0;i<150;i++){if(process.HasExited)throw new IOException("Isolated server exited; retained logs");try{ready=(await http.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}
                Check(ready,"actual isolated server starts with its own retained database");
                using(var unauthorized=await http.PostAsJsonAsync("/api/v1/agent/capabilities",new{}))Check(unauthorized.StatusCode==HttpStatusCode.Unauthorized,"capability remains authenticated");
                using var client=new ManagementClient(new HttpClient{BaseAddress=http.BaseAddress},endpoint.Credential);
                var actual=await client.SendEventsAsync(batch);
                Check(actual.Duplicates==1&&actual.WindowsAcquisitionObservationVersion==1,"actual authenticated HTTP capability and replay receipt acknowledge observation V1");
                try{await client.SendEventsAsync(new([tampered]));throw new Exception("Server accepted fabricated acquisition state");}
                catch(HttpRequestException e)when(e.StatusCode==HttpStatusCode.BadRequest){Check(store.Events(0,10).Count==1,"actual HTTP rejects fabricated state and retains original evidence");}
                Check(JsonSerializer.Serialize(store.Events(0,10).Single().Event)==JsonSerializer.Serialize(sample),"actual HTTP replay leaves stored evidence byte-equivalent");
                var recoveredReceipt=await client.SendEventsAsync(recoveryBatch);
                Check(recoveredReceipt.Accepted==1&&recoveredReceipt.WindowsAcquisitionRecoveryVersion==1,"actual HTTP accepts explicitly unavailable retired-provider metadata with recovery ACK");
                Check(JsonSerializer.Serialize(store.Events(0,10).Single(x=>x.Event.EventId==recovered.EventId).Event)==JsonSerializer.Serialize(recovered),"database retains null prior query and original source key with immutable recovery proof");
                var invalidRecovery=recovered with{EventId=Guid.NewGuid().ToString("N"),Attribution=recovered.Attribution with{WindowsKernel=recovered.Attribution.WindowsKernel! with{AcquisitionObservation=recovery with{RecoveryProvider=provider,RecoveryEpoch=10}}}};
                try{await client.SendEventsAsync(new([invalidRecovery]));throw new Exception("Same-provider recovery fabricated");}
                catch(HttpRequestException ex)when(ex.StatusCode==HttpStatusCode.BadRequest){Check(store.Events(0,10).Count==2,"actual HTTP rejects fabricated retirement and preserves accepted evidence");}
            }
            finally
            {
                if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync();}
                await File.WriteAllTextAsync(Path.Combine(root,"server.stdout.private.log"),await stdout);await File.WriteAllTextAsync(Path.Combine(root,"server.stderr.private.log"),await stderr);
            }
        }
        spool.Acknowledge(batch,receipt);Check(spool.Count==0,"explicit supported receipt removes only acknowledged queue prefix");
        recoverySpool.Acknowledge(recoveryBatch,receipt with{WindowsAcquisitionRecoveryVersion=1});Check(recoverySpool.Count==0,"recovery ACK releases only its retained queue prefix");
        Console.WriteLine($"PASS {checks} acquisition transport/queue/database checks; isolated fixture {root}");
    }
    private sealed class Handler(string mode,BatchReceipt receipt):HttpMessageHandler
    {
        internal int EventPosts;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
        {
            if(request.Headers.Authorization?.Scheme!="Bearer"||request.Headers.Authorization.Parameter!=new string('a',64))throw new Exception("Authenticated request expected");
            object result;
            if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities",StringComparison.Ordinal))
                result=new{AttributionVersion=1,WindowsKernelVersion=4,WindowsAcquisitionObservationVersion=mode=="capability"?0:1,WindowsAcquisitionRecoveryVersion=mode=="recovery-capability"?0:1};
            else{EventPosts++;result=receipt with{WindowsAcquisitionObservationVersion=mode=="receipt"?0:1,WindowsAcquisitionRecoveryVersion=mode=="recovery-receipt"?0:1};}
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(result)});
        }
    }
}
