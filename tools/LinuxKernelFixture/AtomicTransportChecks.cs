using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
using RansomFree.Server;

static class AtomicTransportChecks
{
    internal static async Task Run(string serverDll,string rawRoot)
    {
        var root=Path.Combine(@"D:\Codex\RansomFree\windows-token-20260930","atomic-transport-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        var data=Path.Combine(root,"server");var store=new Store(data);var code=store.CreateCode();var enrollment=store.Enroll(new(code.Code,"atomic-contract-fixture","integration-candidate"))!;
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
        var admin=Store.Secret();var start=new ProcessStartInfo(@"C:\Program Files\dotnet\dotnet.exe"){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(Path.GetFullPath(serverDll));
        foreach(var key in start.Environment.Keys.Where(k=>k.StartsWith("RF_")||k.StartsWith("ASPNETCORE_")).ToArray())start.Environment.Remove(key);
        start.Environment["RF_ADMIN_KEY"]=admin;start.Environment["RF_DATA_DIR"]=data;start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_URLS"]="http://127.0.0.1:"+port;start.Environment["Logging__LogLevel__Default"]="Warning";
        using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();var checks=0;
        void Check(bool value,string label){if(!value)throw new InvalidDataException(label);checks++;Console.WriteLine("PASS "+label);}
        try
        {
            using var http=new HttpClient{BaseAddress=new Uri("http://127.0.0.1:"+port),Timeout=TimeSpan.FromSeconds(10)};
            var ready=false;for(int i=0;i<100;i++){if(child.HasExited)throw new IOException("Isolated server exited");try{using var health=await http.GetAsync("/health/live");ready=health.IsSuccessStatusCode;}catch(HttpRequestException){}if(ready)break;await Task.Delay(100);}
            Check(ready,"isolated server started");
            using var client=new ManagementClient(http,enrollment.Credential);
            var collector=Guid.NewGuid().ToString("N");var entry=LinuxKernelDecoder.Decode(File.ReadAllBytes(Path.Combine(rawRoot,"raw-entry.json")),enrollment.EndpointId,collector,1,DateTimeOffset.UtcNow);
            var result=LinuxKernelDecoder.Decode(File.ReadAllBytes(Path.Combine(rawRoot,"raw-result.json")),enrollment.EndpointId,collector,2,DateTimeOffset.UtcNow);
            var spool=new EventSpool(Path.Combine(root,"spool"),enrollment.EndpointId);spool.Enqueue(entry);spool.Enqueue(result);var batch=spool.Peek();
            try{spool.Acknowledge(batch,new(2,0){AttributionVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1});throw new Exception("Missing permission receipt accepted");}
            catch(InvalidDataException){Check(spool.Count==2,"missing additive receipt retains both observations");}
            var receipt=await client.SendEventsAsync(new([entry,result]));Check(receipt.Accepted==2&&receipt.LinuxPermissionObservationVersion==1,"server acknowledges both permission stages with explicit capability");
            spool.Acknowledge(batch,receipt);Check(spool.Count==0,"acknowledged observations leave durable spool");
            var replay=await client.SendEventsAsync(new([entry,result]));Check(replay.Duplicates==2&&replay.Accepted==0,"event replay remains idempotent");
            using var request=new HttpRequestMessage(HttpMethod.Get,"/api/v1/admin/events?limit=100");request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",admin);
            using var response=await http.SendAsync(request);response.EnsureSuccessStatusCode();var saved=(await response.Content.ReadFromJsonAsync<StoredEvent[]>())!;
            Check(saved.Length==2&&saved.All(x=>LinuxKernelEvidence.Matches(x.Event)),"server history preserves valid permission contracts");
            foreach(var expected in new[]{entry,result})Check(JsonSerializer.Serialize(saved.Single(x=>x.Event.EventId==expected.EventId).Event)==JsonSerializer.Serialize(expected),"exact user/PID/lifetime/target and native status retained "+expected.Attribution!.LinuxKernel!.PermissionObservation!.Stage);
            foreach(var stage in new[]{1,2})
            {
                var label=stage==1?"Permission Check Requested":"Permission Check Returned";
                var page=await store.History(new EventHistoryQuery{Action=label});
                Check(page.Items.Count==1&&page.Items[0].Event.Attribution!.LinuxKernel!.PermissionObservation!.Stage==stage&&new HistoryEvent(page.Items[0].Sequence,page.Items[0].EndpointId,page.Items[0].ReceivedUtc,page.Items[0].Event,EventActivity.From(page.Items[0].Event)).DisplayOperation==label,"history filter and presentation distinguish permission stage "+stage);
            }
            File.WriteAllBytes(Path.Combine(root,"history.json"),JsonSerializer.SerializeToUtf8Bytes(saved));
            File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Synthetic permission protocol through real isolated server API, SQLite and spool; not live kernel capture"}));Console.WriteLine($"Atomic transport checks: {checks} passed; {root}");
        }
        finally
        {
            if(!child.HasExited){child.Kill();await child.WaitForExitAsync();}
            File.WriteAllText(Path.Combine(root,"server.stdout"),await stdout);File.WriteAllText(Path.Combine(root,"server.stderr"),await stderr);
        }
    }
}
