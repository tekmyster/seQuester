using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;
using RansomFree.Server;
using RansomFree.Client;

if(args.Length is <2 or >4)throw new ArgumentException("Arguments: dotnet executable, published server DLL, optional published Windows agent DLL, optional --preview");
var root=Path.GetFullPath(Path.Combine("test-results","server",Guid.NewGuid().ToString("N")));Directory.CreateDirectory(root);
var report=new List<string>();Process? server=null;
void Check(bool value,string text){if(!value)throw new Exception("FAIL: "+text);report.Add("PASS: "+text);Console.WriteLine(report[^1]);}
var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
var key=Store.Secret();
using var http=new HttpClient {BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(10)};
async Task Start(bool allowHttp=true,bool production=false)
{
    var start=new ProcessStartInfo(Path.GetFullPath(args[0])) {UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
    start.ArgumentList.Add(Path.GetFullPath(args[1]));
    start.Environment["RF_DATA_DIR"]=root;start.Environment["RF_ADMIN_KEY"]=key;
    start.Environment["ASPNETCORE_ENVIRONMENT"]=production?"Production":"Development";
    start.Environment["RF_ALLOW_LOOPBACK_HTTP"]=allowHttp?"true":"false";
    start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";
    start.Environment["Logging__LogLevel__Default"]="Warning";
    server=Process.Start(start)!;
    server.OutputDataReceived+=(_,_)=>{};server.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)Console.Error.WriteLine("SERVER: "+e.Data);};server.BeginOutputReadLine();server.BeginErrorReadLine();
    for(var i=0;i<100;i++)
    {
        if(server.HasExited){if(production)return;throw new Exception("Test server exited during startup.");}
        try{using var response=await http.GetAsync("/health/live");if(response.StatusCode==(allowHttp?HttpStatusCode.OK:HttpStatusCode.BadRequest))return;}catch(HttpRequestException){}
        await Task.Delay(100);
    }
    throw new Exception("Test server did not start.");
}
void Stop(){if(server is null)return;if(!server.HasExited){server.Kill();server.WaitForExit(10000);}server.Dispose();server=null;}
async Task<HttpResponseMessage> Send(HttpMethod method,string path,object? body=null,string? credential=null)
{
    using var request=new HttpRequestMessage(method,path);
    if(body!=null)request.Content=JsonContent.Create(body);
    if(credential!=null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",credential);
    return await http.SendAsync(request);
}
async Task<T> Value<T>(HttpResponseMessage response){using(response){response.EnsureSuccessStatusCode();return (await response.Content.ReadFromJsonAsync<T>())!;}}
async Task Status(HttpResponseMessage response,HttpStatusCode expected,string description){using(response){Check(response.StatusCode==expected,description);await response.Content.LoadIntoBufferAsync();}}
try
{
    EventQueueChecks.Run(root,Check);
    using(var schema=typeof(Store).Assembly.GetManifestResourceStream("RansomFree.Server.Database.EndpointProtection001.sql"))using(var reader=new StreamReader(schema??throw new Exception("Endpoint protection SQL migration missing."))){var sql=reader.ReadToEnd();Check(sql.Contains("REFERENCES dbo.endpoints(id)")&&sql.Contains("CHECK(deployed_items>=0")&&sql.Contains("monitoring_state IN"),"SQL Server protection migration is embedded, additive, bounded, and endpoint-linked");}
    await DiagnosticChecks.Run(args[0],args.Length>=3?args[2]:null,root,Check);
    foreach(var invalid in new[]{"http://localhost:5000","https://user:secret@example.test","https://example.test/path","https://example.test/?secret=x","https://example.test/#x"})
    {
        var rejected=false;try{using var client=new ManagementClient(invalid);}catch(ArgumentException){rejected=true;}
        Check(rejected,"client rejects unsafe server origin");
    }
    var spoolEndpoint=Guid.NewGuid().ToString("N");var spool=new EventSpool(root,spoolEndpoint);
    var queued=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","QA file",null,null,null,"test");spool.Enqueue(queued);
    spool=new EventSpool(root,spoolEndpoint);Check(spool.Count==1 && spool.Peek().Events[0]==queued,"client spool survives restart");
    var receiptRejected=false;try{spool.Acknowledge(spool.Peek(),new(0,0));}catch(InvalidDataException){receiptRejected=true;}
    Check(receiptRejected && spool.Count==1,"invalid receipt cannot discard queued event");
    spool.Acknowledge(spool.Peek(),new(1,0));Check(new EventSpool(root,spoolEndpoint).Count==0,"acknowledgement durably removes delivered event");
    var invalidEventRejected=false;try{spool.Enqueue(queued with {EventId="bad"});}catch(ArgumentException){invalidEventRejected=true;}
    Check(invalidEventRejected && spool.Count==0,"client rejects invalid event without modifying queue");
    var corruptId=Guid.NewGuid().ToString("N");var corruptPath=Path.Combine(root,"events-"+corruptId+".json");File.WriteAllText(corruptPath,"broken");
    var corruptRejected=false;try{_=new EventSpool(root,corruptId);}catch(System.Text.Json.JsonException){corruptRejected=true;}
    Check(corruptRejected && File.ReadAllText(corruptPath)=="broken","corrupt client spool is preserved and startup fails visibly");
    var expiryRoot=Path.Combine(root,"expiry-qa");var expiryStore=new Store(expiryRoot);var expired=expiryStore.CreateCode();
    using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(expiryRoot,"management.db")}.ToString()))
    {
        c.Open();using var cmd=c.CreateCommand();cmd.CommandText="UPDATE enrollment SET expires=0";cmd.ExecuteNonQuery();
    }
    Check(expiryStore.Enroll(new(expired.Code,"expired-test","0.5")) is null,"expired enrollment code is refused");
    await Start();
    await IdentityChecks.Run(http.BaseAddress!,key,Check);
    await ReportChecks.Run(http.BaseAddress!,root,Check);
    await Status(await Send(HttpMethod.Get,"/api/v1/admin/endpoints"),HttpStatusCode.Unauthorized,"anonymous inventory denied");
    await Status(await Send(HttpMethod.Post,"/api/v1/admin/enrollment-codes",credential:Store.Secret()),HttpStatusCode.Unauthorized,"wrong administrator key denied");
    var code=await Value<EnrollmentCodeResponse>(await Send(HttpMethod.Post,"/api/v1/admin/enrollment-codes",credential:key));
    Check(code.Code.Length==64 && code.ExpiresUtc>DateTimeOffset.UtcNow,"short-lived random enrollment code issued");
    var enrollment=new EnrollmentRequest(code.Code,"test-endpoint","0.5.0-test");
    var endpoint=await Value<EnrollmentResponse>(await Send(HttpMethod.Post,"/api/v1/enroll",enrollment));
    Check(endpoint.Credential.Length==64 && endpoint.EndpointId.Length==32,"unique endpoint identity and credential issued");
    await Status(await Send(HttpMethod.Post,"/api/v1/enroll",enrollment),HttpStatusCode.Unauthorized,"enrollment code cannot be reused");
    await Status(await Send(HttpMethod.Get,"/api/v1/admin/endpoints",credential:endpoint.Credential),HttpStatusCode.Unauthorized,"endpoint credential cannot administer server");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5.0","Healthy"),endpoint.Credential),HttpStatusCode.NoContent,"authenticated heartbeat accepted");
    var inventory=await Value<List<EndpointSummary>>(await Send(HttpMethod.Get,"/api/v1/admin/endpoints",credential:key));
    Check(inventory.Count==1 && inventory[0].Health=="Healthy" && inventory[0].AgentVersion=="0.5.0" && inventory[0].Protection==null,"older heartbeat remains compatible and protection is explicitly not reported");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5.0","Healthy"){Protection=new(7,"active")},endpoint.Credential),HttpStatusCode.NoContent,"structured client protection report accepted without an inventory prerequisite");
    inventory=await Value<List<EndpointSummary>>(await Send(HttpMethod.Get,"/api/v1/admin/endpoints",credential:key));
    Check(inventory[0].Protection==new EndpointProtectionReport(7,"active"),"client-reported monitoring and canary/honeypot count appear in inventory");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5.0","Healthy"){Protection=new(-1,"active")},endpoint.Credential),HttpStatusCode.BadRequest,"negative deployed item count rejected without changing prior state");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5.0","Healthy"){Protection=new(0,"healthy")},endpoint.Credential),HttpStatusCode.BadRequest,"invented monitoring state rejected without changing prior state");
    var item=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)","C:\\QA\\sample.txt","TEST\\user","reader.exe",123,"Windows audit 4663");
    var batch=new EventBatch([item]);
    var receipt=await Value<BatchReceipt>(await Send(HttpMethod.Post,"/api/v1/agent/events",batch,endpoint.Credential));
    Check(receipt.Accepted==1 && receipt.Duplicates==0,"event stored and acknowledged");
    receipt=await Value<BatchReceipt>(await Send(HttpMethod.Post,"/api/v1/agent/events",batch,endpoint.Credential));
    Check(receipt.Accepted==0 && receipt.Duplicates==1,"retry deduplicated");
    foreach(var incomplete in new[]{item with{EventId=Guid.NewGuid().ToString("N"),User=null},item with{EventId=Guid.NewGuid().ToString("N"),Process="Unavailable"},item with{EventId=Guid.NewGuid().ToString("N"),ProcessId=null}})
        await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([incomplete]),endpoint.Credential),HttpStatusCode.OK,"local honeypot event missing an actor field is retained");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([item with {EventId=Guid.NewGuid().ToString("N")},item with {Operation="different"}]),endpoint.Credential),HttpStatusCode.Conflict,"conflicting event ID rolls back entire batch");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([item with {EventId="invalid"}]),endpoint.Credential),HttpStatusCode.BadRequest,"invalid event ID rejected");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch([]),endpoint.Credential),HttpStatusCode.BadRequest,"empty event batch rejected");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",new EventBatch(Enumerable.Repeat(item,101).ToArray()),endpoint.Credential),HttpStatusCode.BadRequest,"oversized batch rejected");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5","bad\nhealth"),endpoint.Credential),HttpStatusCode.BadRequest,"control characters rejected in health");
    await Status(await Send(HttpMethod.Get,"/api/v1/admin/events?limit=10000",credential:key),HttpStatusCode.BadRequest,"unbounded query rejected");
    var events=await Value<List<StoredEvent>>(await Send(HttpMethod.Get,"/api/v1/admin/events",credential:key));
    Check(events.Count==4 && events.All(e=>e.EndpointId==endpoint.EndpointId) && events.Any(e=>e.Event==item) && events.Count(e=>!LocalActorEvidence.IsComplete(e.Event))==3,"server preserves complete and incomplete local actor evidence");
    var historyPage=await Value<EventHistoryPage>(await Send(HttpMethod.Get,"/api/v1/admin/event-history?limit=100",credential:key));
    var historyItem=historyPage.Items.Single(x=>x.Event.EventId==item.EventId);
    Check(historyItem.MachineName=="test-endpoint" && historyItem.DisplayOperation=="Copied/Read","event history resolves host evidence and uses the precise read-or-copy presentation label");
    using(var human=new HttpClient(new HttpClientHandler {CookieContainer=new CookieContainer(),AllowAutoRedirect=false}) {BaseAddress=http.BaseAddress})
    {
        using var csrf=await human.GetFromJsonAsync<JsonDocument>("/api/v1/auth/csrf");using var login=new HttpRequestMessage(HttpMethod.Post,"/api/v1/auth/login") {Content=JsonContent.Create(new {userName="local-admin",password="QA-only-long-passphrase-904!"})};login.Headers.Add("X-CSRF",csrf!.RootElement.GetProperty("token").GetString());
        using(var signedIn=await human.SendAsync(login))signedIn.EnsureSuccessStatusCode();
        using var detailResponse=await human.GetAsync($"/api/v1/console/evidence/{historyItem.Sequence}");var detail=await Value<HistoryEvent>(detailResponse);
        Check(detail.MachineName=="test-endpoint" && detail.DisplayOperation=="Copied/Read","evidence detail reports the associated host and precise read-or-copy label");
    }
    var callbackScript=await http.GetStringAsync("/callbacks.js");
    Check(callbackScript.Contains("Canary token activated (application/resource access)")&&!callbackScript.Contains("Copy detected",StringComparison.OrdinalIgnoreCase),"callback presentation stays separate from filesystem-copy claims");
    var code2=await Value<EnrollmentCodeResponse>(await Send(HttpMethod.Post,"/api/v1/admin/enrollment-codes",credential:key));
    var parallel=await Task.WhenAll(Send(HttpMethod.Post,"/api/v1/enroll",new EnrollmentRequest(code2.Code,"race-a","0.5")),Send(HttpMethod.Post,"/api/v1/enroll",new EnrollmentRequest(code2.Code,"race-b","0.5")));
    Check(parallel.Count(r=>r.StatusCode==HttpStatusCode.OK)==1 && parallel.Count(r=>r.StatusCode==HttpStatusCode.Unauthorized)==1,"concurrent enrollment consumes code only once");foreach(var r in parallel)r.Dispose();
    Stop();await Start();
    inventory=await Value<List<EndpointSummary>>(await Send(HttpMethod.Get,"/api/v1/admin/endpoints",credential:key));
    events=await Value<List<StoredEvent>>(await Send(HttpMethod.Get,"/api/v1/admin/events",credential:key));
    Check(inventory.Count==2 && events.Count==4 && events.Any(e=>e.Event==item) && events.Count(e=>!LocalActorEvidence.IsComplete(e.Event))==3 && inventory.Single(x=>x.EndpointId==endpoint.EndpointId).Protection==new EndpointProtectionReport(7,"active"),"inventory, client protection reports, and complete/incomplete events survive packaged server restart");
    receipt=await Value<BatchReceipt>(await Send(HttpMethod.Post,"/api/v1/agent/events",batch,endpoint.Credential));
    Check(receipt.Duplicates==1,"deduplication survives restart");
    await Status(await Send(HttpMethod.Post,$"/api/v1/admin/endpoints/{endpoint.EndpointId}/revoke",credential:key),HttpStatusCode.NoContent,"administrator revokes endpoint");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/heartbeat",new HeartbeatRequest("0.5","Healthy"),endpoint.Credential),HttpStatusCode.Unauthorized,"revoked endpoint heartbeat denied");
    await Status(await Send(HttpMethod.Post,"/api/v1/agent/events",batch,endpoint.Credential),HttpStatusCode.Unauthorized,"revoked endpoint event ingestion denied");
    Stop();
    using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(root,"management.db")}.ToString()))
    {
        c.Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT credential_hash FROM endpoints WHERE id=$id";cmd.Parameters.AddWithValue("$id",endpoint.EndpointId);
        Check(cmd.ExecuteScalar() is string hash && hash!=endpoint.Credential,"database stores hashed endpoint credentials");
        cmd.Parameters.Clear();cmd.CommandText="SELECT COUNT(*) FROM audit";Check(Convert.ToInt64(cmd.ExecuteScalar())>=5,"administrative changes have durable audit records");
    }
    await Start(false);await Status(await Send(HttpMethod.Get,"/health/live"),HttpStatusCode.BadRequest,"HTTP refused without explicit loopback development exception");Stop();
    await Start(false,true);Check(server!.HasExited && server.ExitCode!=0,"unfinished enterprise server refuses Production startup");Stop();
    if(args.Length>=3)
    {
        var agentRoot=Path.Combine(root,"agent-qa");Directory.CreateDirectory(agentRoot);
        var canary=Path.Combine(agentRoot,"synthetic.txt");File.WriteAllText(canary,"Synthetic QA canary");
        var hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(canary)));
        File.WriteAllText(Path.Combine(agentRoot,"settings.json"),System.Text.Json.JsonSerializer.Serialize(new {Canaries=new[]{new {Path=canary,Hash=hash}}}));
        var start=new ProcessStartInfo(Path.GetFullPath(args[0])) {UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var argument in new[]{Path.GetFullPath(args[2]),"--console","--data",agentRoot,"--run-seconds","5"})start.ArgumentList.Add(argument);
        var ready=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var agent=new Process {StartInfo=start};
        agent.OutputDataReceived+=(_,e)=>{if(e.Data?.Contains("Agent runtime started")==true)ready.TrySetResult();};agent.ErrorDataReceived+=(_,_)=>{};
        agent.Start();agent.BeginOutputReadLine();agent.BeginErrorReadLine();
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));File.AppendAllText(canary,"\nQA write");
            await agent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12));
            Check(agent.ExitCode==0,"packaged agent starts and shuts down gracefully in console QA mode");
            var activity=File.ReadAllText(Path.Combine(agentRoot,"activity.jsonl"));
            Check(activity.Contains("File changed") && activity.Contains("synthetic.txt"),"packaged agent monitors isolated file changes without tray UI");
            Check(!File.Exists(Path.Combine(agentRoot,"connection.json")),"unenrolled agent does not create credentials or contact a manager");
        }
        finally {if(!agent.HasExited){agent.Kill();agent.WaitForExit(10000);}}
        var damagedConnection=Path.Combine(agentRoot,"connection.json");File.WriteAllText(damagedConnection,"invalid connection");
        using var failedAgent=Process.Start(start)!;
        var failedOutput=failedAgent.StandardOutput.ReadToEndAsync();var failedError=failedAgent.StandardError.ReadToEndAsync();
        await failedAgent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(12));await Task.WhenAll(failedOutput,failedError);
        Check(failedAgent.ExitCode!=0 && File.ReadAllText(damagedConnection)=="invalid connection","invalid agent enrollment fails startup without overwriting configuration");
    }
    Console.WriteLine("Evidence: "+root);
    if(args.Length==4 && args[3]=="--preview")
    {
        await Start();Console.WriteLine("QA preview: "+http.BaseAddress);Console.WriteLine("Stop signal: "+Path.Combine(root,"preview.stop"));
        var deadline=DateTime.UtcNow.AddMinutes(15);
        while(DateTime.UtcNow<deadline && !File.Exists(Path.Combine(root,"preview.stop")))await Task.Delay(500);
        Stop();
    }
}
catch(Exception ex){report.Add(ex.ToString());Console.Error.WriteLine(ex);Environment.ExitCode=1;}
finally{Stop();File.WriteAllLines(Path.Combine(root,"results.txt"),report);}
