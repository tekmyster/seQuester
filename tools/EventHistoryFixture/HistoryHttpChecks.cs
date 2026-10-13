using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using RansomFree.Server;
using RansomFree.Contracts;

internal static class HistoryHttpChecks
{
    public static async Task Run(string dotnet,string serverDll,string root,Action<bool,string> check,Action checkpoint,bool preview,bool adminPreview=false)
    {
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();var port=((IPEndPoint)listener.LocalEndpoint).Port;listener.Stop();
        var secret=Store.Secret();var start=new ProcessStartInfo(dotnet){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(serverDll);
        var keep=new Dictionary<string,string?>();foreach(var name in new[]{"SystemRoot","WINDIR","PATH","USERPROFILE","LOCALAPPDATA","APPDATA"})keep[name]=Environment.GetEnvironmentVariable(name);
        start.Environment.Clear();foreach(var pair in keep)if(pair.Value!=null)start.Environment[pair.Key]=pair.Value;
        start.Environment["TEMP"]="D:\\Codex\\RansomFree\\temp";start.Environment["TMP"]=start.Environment["TEMP"];
        start.Environment["RF_DATA_DIR"]=root;start.Environment["RF_ADMIN_KEY"]=secret;start.Environment["RF_ALLOW_LOOPBACK_HTTP"]="true";start.Environment["ASPNETCORE_ENVIRONMENT"]="Development";
        start.Environment["ASPNETCORE_URLS"]=$"http://127.0.0.1:{port}";start.Environment["Database__Provider"]="Sqlite";start.Environment["Logging__LogLevel__Default"]="Warning";
        using var process=Process.Start(start)!;var log=new List<string>();process.OutputDataReceived+=(_,e)=>{if(e.Data!=null)lock(log)log.Add(e.Data);};process.ErrorDataReceived+=(_,e)=>{if(e.Data!=null)lock(log)log.Add(e.Data);};process.BeginOutputReadLine();process.BeginErrorReadLine();
        using var browser=new HttpClient(new HttpClientHandler{CookieContainer=new(),AllowAutoRedirect=false}){BaseAddress=new Uri($"http://127.0.0.1:{port}"),Timeout=TimeSpan.FromSeconds(30)};
        try
        {
            var ready=false;for(var i=0;i<150;i++){if(process.HasExited)throw new Exception("Fixture server exited: "+string.Join("\n",log));try{ready=(await browser.GetAsync("/health/live")).IsSuccessStatusCode;if(ready)break;}catch(HttpRequestException){}await Task.Delay(100);}check(ready,"isolated published HTTP server starts");
            using(var health=await browser.GetFromJsonAsync<JsonDocument>("/health/live"))
                check(health!.RootElement.GetProperty("serverVersion").GetString()==typeof(Store).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion.Split('+')[0],"served public build identity matches server assembly");
            var loginHtml=await browser.GetStringAsync("/");
            check(loginHtml.Contains("data-server-version",StringComparison.Ordinal)&&!loginHtml.Contains("Development build · 0.6.20-dev",StringComparison.Ordinal)&&!loginHtml.Contains("Console version: 0.6.20-dev",StringComparison.Ordinal),"server build labels do not claim the obsolete hardcoded version");
            async Task<string> Csrf(){using var reply=await browser.GetAsync("/api/v1/auth/csrf");reply.EnsureSuccessStatusCode();using var body=await reply.Content.ReadFromJsonAsync<JsonDocument>();return body!.RootElement.GetProperty("token").GetString()!;}
            async Task<HttpResponseMessage> Request(HttpMethod method,string route,object? body=null,bool admin=false,bool csrf=false){using var request=new HttpRequestMessage(method,route);if(body!=null)request.Content=JsonContent.Create(body);if(admin)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",secret);if(csrf)request.Headers.Add("X-CSRF",await Csrf());return await browser.SendAsync(request);}
            async Task Status(HttpResponseMessage response,HttpStatusCode expected,string text){using(response){var detail=await response.Content.ReadAsStringAsync();check(response.StatusCode==expected,text+" HTTP "+(int)response.StatusCode+(response.StatusCode==expected?"":" "+detail));}}
            await Status(await Request(HttpMethod.Get,"/api/v1/console/event-history"),HttpStatusCode.Unauthorized,"anonymous history denied");
            await Status(await Request(HttpMethod.Get,"/api/v1/admin/event-history"),HttpStatusCode.Unauthorized,"anonymous admin history denied");
            using(var response=await Request(HttpMethod.Get,"/api/v1/admin/event-history?sort=pid&direction=asc&limit=100",admin:true))
            {
                response.EnsureSuccessStatusCode();var page=await response.Content.ReadFromJsonAsync<EventHistoryPage>();check(page!.Items.Count==100&&page.NextCursor!=null,"authenticated bootstrap history page");
                await Status(await Request(HttpMethod.Get,"/api/v1/admin/event-history?sort=pid&direction=asc&limit=100&cursor="+Uri.EscapeDataString(page.NextCursor!),admin:true),HttpStatusCode.OK,"HTTP protected cursor resumes");
            }
            await Status(await Request(HttpMethod.Get,"/api/v1/admin/event-history?limit=0",admin:true),HttpStatusCode.BadRequest,"HTTP page limit rejected");
            await Status(await Request(HttpMethod.Get,"/api/v1/admin/event-history?sort=pid&sort=user",admin:true),HttpStatusCode.BadRequest,"HTTP duplicate sort rejected");
            await Status(await Request(HttpMethod.Get,"/api/v1/admin/events?after=0&limit=2",admin:true),HttpStatusCode.OK,"legacy relay/event pagination unchanged");
            const string password="History-Only-QA-904!";
            await Status(await Request(HttpMethod.Post,"/api/v1/admin/users",new{userName="history-reader",password,role="Reader"},admin:true),HttpStatusCode.OK,"isolated reader provisioned");
            await Status(await Request(HttpMethod.Post,"/api/v1/auth/login",new{userName="history-reader",password},csrf:true),HttpStatusCode.NoContent,"reader signs in");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/event-history"),HttpStatusCode.OK,"reader default history accepted");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/event-capabilities"),HttpStatusCode.OK,"reader can inspect compiled provider capabilities");
            using(var catalog=await Request(HttpMethod.Get,"/api/v1/console/decoy-deployment-types"))
            {catalog.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await catalog.Content.ReadAsStringAsync());check(json.RootElement.GetProperty("types").GetArrayLength()==19&&!json.RootElement.GetProperty("enabledByDefault").GetBoolean(),"catalog is explicit and default-disabled");}
            await Status(await Request(HttpMethod.Post,"/api/v1/console/simulation/trust",new{},csrf:true),HttpStatusCode.Forbidden,"reader cannot submit administrator simulation");
            await Status(await Request(HttpMethod.Get,"/api/v1/admin/event-history"),HttpStatusCode.Unauthorized,"reader cannot use bootstrap admin route");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/responses",new{},csrf:true),HttpStatusCode.Forbidden,"reader cannot request process response");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/trust-policy"),HttpStatusCode.OK,"reader can inspect trust policy");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/trust-policy",new PublishTrustBody(0,"enforce",[],[],password),csrf:true),HttpStatusCode.Forbidden,"reader cannot publish trust policy");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/decoy-services"),HttpStatusCode.OK,"reader can inspect service inventory");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/decoy-services",new{},csrf:true),HttpStatusCode.Forbidden,"reader cannot create service decoys");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/email"),HttpStatusCode.Forbidden,"reader cannot inspect email configuration");
            await Status(await Request(HttpMethod.Get,"/api/v1/console/evidence/1"),HttpStatusCode.OK,"reader can retrieve authorized endpoint evidence");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/incidents",new CreateIncidentBody("Denied","High",1),csrf:true),HttpStatusCode.Forbidden,"reader cannot create incidents");
            await Status(await Request(HttpMethod.Post,"/api/v1/admin/users",new{userName="history-admin",password,role="Administrator"},admin:true),HttpStatusCode.OK,"isolated simulation administrator provisioned");
            await Status(await Request(HttpMethod.Post,"/api/v1/auth/login",new{userName="history-admin",password},csrf:true),HttpStatusCode.NoContent,"simulation administrator signs in");
            var now=DateTimeOffset.UtcNow;var hash=new string('a',64);
            var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","fixture","process",["read"],"informational",now.AddMinutes(-1),now.AddHours(1)){Enabled=true,Executable="/synthetic/process",Sha256=hash};
            var scenario=new TrustSimulationRequest([rule],new("fixture",null,"fixture-host","linux","/synthetic/file",["read"],now,new(Executable:"/synthetic/process",Sha256:hash,Verified:true)));
            await Status(await Request(HttpMethod.Post,"/api/v1/console/simulation/trust",scenario),HttpStatusCode.BadRequest,"administrator simulation requires CSRF");
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/simulation/trust",scenario,csrf:true))
            {response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());check(!json.RootElement.GetProperty("applied").GetBoolean()&&!json.RootElement.GetProperty("decision").GetProperty("suppressPopup").GetBoolean()&&json.RootElement.GetProperty("decision").GetProperty("severity").GetString()=="informational","administrator can simulate severity-only policy without applying it");}
            var decoy=new DecoyDeploymentRequest(Guid.NewGuid().ToString("N"),"V04","linux","/synthetic/not-created","Fixture only"){Enabled=true};
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/simulation/decoy-deployment",decoy,csrf:true))
            {response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());check(!json.RootElement.GetProperty("applied").GetBoolean()&&!json.RootElement.GetProperty("preview").GetProperty("canDeploy").GetBoolean(),"administrator preview cannot create an unavailable volume");}
            var publication=new PublishTrustBody(0,"enforce",[rule with{ScopeId="server",Subject="account",Executable=null,Sha256=null,Authority="fixture-domain",AccountKind="sid",AccountId="S-1-5-21-123-1001"}],[],password);
            await Status(await Request(HttpMethod.Post,"/api/v1/console/trust-policy",publication),HttpStatusCode.Unauthorized,"publication requires CSRF");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/trust-policy",publication with{AdministratorPassword="incorrect-fixture-password"},csrf:true),HttpStatusCode.Unauthorized,"publication requires administrator reauthentication");
            TrustPolicy published;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/trust-policy",publication,csrf:true)){response.EnsureSuccessStatusCode();published=(await response.Content.ReadFromJsonAsync<TrustPolicy>())!;check(published.Revision>0&&published.Mode=="enforce","authenticated policy publication persisted");}
            await Status(await Request(HttpMethod.Post,"/api/v1/console/trust-policy",publication,csrf:true),HttpStatusCode.Conflict,"stale publication cannot overwrite current policy");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/trust-policy",publication with{ExpectedRevision=published.Revision,Rules=[rule with{ScopeId="wrong-server"}]},csrf:true),HttpStatusCode.BadRequest,"invalid target is rejected without publication");
            using(var response=await Request(HttpMethod.Get,"/api/v1/console/trust-policy/history")){response.EnsureSuccessStatusCode();var history=await response.Content.ReadFromJsonAsync<TrustPolicy[]>();check(history!.Length==1&&history[0].Digest()==published.Digest(),"history contains only committed version");}
            using(var response=await Request(HttpMethod.Get,"/api/v1/console/trust-policy/endpoints")){response.EnsureSuccessStatusCode();var receipts=await response.Content.ReadFromJsonAsync<TrustEndpointStatus[]>();check(receipts!.Length>=2&&receipts.All(x=>x.Status=="Pending"),"unreported endpoints never appear enforced or received");}
            var serviceRequest=new DecoyServiceChange("Synthetic archive","Isolated fixture only",false,0,password){RequestId=Guid.NewGuid().ToString("N"),Location="Isolated lab",Note="Synthetic record\nNo real user data"};
            await Status(await Request(HttpMethod.Post,"/api/v1/console/decoy-services",serviceRequest),HttpStatusCode.Unauthorized,"service creation requires CSRF");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/decoy-services",serviceRequest with{AdministratorPassword="incorrect-fixture-password"},csrf:true),HttpStatusCode.Unauthorized,"service creation requires reauthentication");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/decoy-services",serviceRequest with{Enabled=true},csrf:true),HttpStatusCode.BadRequest,"service creation cannot enable implicitly");
            CreatedDecoyService created;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/decoy-services",serviceRequest,csrf:true)){response.EnsureSuccessStatusCode();created=(await response.Content.ReadFromJsonAsync<CreatedDecoyService>())!;check(!created.Service.Enabled&&created.ActivationPath.StartsWith("/decoy-api/",StringComparison.Ordinal),"HTTP service created disabled with activation path");}
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/decoy-services",serviceRequest,csrf:true)){response.EnsureSuccessStatusCode();var retry=(await response.Content.ReadFromJsonAsync<CreatedDecoyService>())!;check(retry.AlreadyExists&&retry.ActivationPath==""&&retry.Service.Id==created.Service.Id,"HTTP retry keeps one resource and does not redisclose secret");}
            // Never use a real token or send credentials to the activation route.
            using var activationClient=new HttpClient{BaseAddress=browser.BaseAddress};
            await Status(await activationClient.GetAsync(created.ActivationPath),HttpStatusCode.NotFound,"disabled service activation unavailable");
            DecoyService active;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/decoy-services/"+created.Service.Id,serviceRequest with{ExpectedRevision=1,Enabled=true},csrf:true)){response.EnsureSuccessStatusCode();active=(await response.Content.ReadFromJsonAsync<DecoyService>())!;check(active.Enabled&&active.Revision==2,"HTTP explicit service activation persisted");}
            using(var response=await activationClient.GetAsync(created.ActivationPath)){response.EnsureSuccessStatusCode();using var json=await response.Content.ReadFromJsonAsync<JsonDocument>();check(response.Headers.CacheControl?.NoStore==true&&json!.RootElement.GetProperty("records").GetArrayLength()==0,"anonymous activation returns only synthetic data and no-store");}
            await Status(await activationClient.PostAsJsonAsync(created.ActivationPath,new{}),HttpStatusCode.MethodNotAllowed,"service does not process submitted bodies");
            using(var response=await Request(HttpMethod.Get,$"/api/v1/console/decoy-services/{active.Id}/hits")){response.EnsureSuccessStatusCode();var hits=(await response.Content.ReadFromJsonAsync<DecoyServiceHit[]>())!;check(hits.Length==1&&hits[0].Method=="GET"&&IPAddress.IsLoopback(IPAddress.Parse(hits[0].SourceAddress)),"HTTP activation evidence committed with observed source, no invented actor");}
            await Status(await Request(HttpMethod.Post,"/api/v1/console/decoy-services/"+active.Id,serviceRequest with{ExpectedRevision=1},csrf:true),HttpStatusCode.Conflict,"stale service control cannot overwrite current state");
            var collector=new TcpListener(IPAddress.Loopback,0);collector.Start();var collectorPort=((IPEndPoint)collector.LocalEndpoint).Port;
            object Forwarding(bool enabled,long revision)=>new{expectedRevision=revision,destination=new{enabled,host="127.0.0.1",port=collectorPort,transport="TCP",format="RFC5424",octetCounting=false,facility=16,severity=4},endpointEvents=false,callbackHits=false,serviceHits=enabled,administratorPassword=password};
            try
            {
                await Status(await Request(HttpMethod.Post,"/api/v1/console/server-syslog",Forwarding(true,0),csrf:true),HttpStatusCode.OK,"administrator enables only service syslog to isolated collector");
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(25));var connection=collector.AcceptTcpClientAsync(deadline.Token);
                await Status(await activationClient.GetAsync(created.ActivationPath),HttpStatusCode.OK,"new service hit enters server-only relay after activation checkpoint");
                using var socket=await connection;using var reader=new StreamReader(socket.GetStream());var syslog=await reader.ReadLineAsync(deadline.Token)??throw new Exception("Missing syslog line");
                File.WriteAllText(Path.Combine(root,"service-syslog.txt"),syslog);
                using var wire=JsonDocument.Parse(syslog[syslog.IndexOf('{')..]);var fields=wire.RootElement;
                check(fields.GetProperty("Source").GetString()=="Server service decoy"&&fields.GetProperty("ServiceContext").GetProperty("ServiceId").GetString()==active.Id&&fields.GetProperty("ProcessId").ValueKind==JsonValueKind.Null&&fields.GetProperty("EndpointId").ValueKind==JsonValueKind.Null,"loopback syslog contains stable service context and no invented endpoint/process");
                check(new Store(root).ServiceEvents(0).Any(x=>x.Event.EventId==fields.GetProperty("EventId").GetString()),"syslog event identity matches durable unified history evidence");
            }
            finally{collector.Stop();await Status(await Request(HttpMethod.Post,"/api/v1/console/server-syslog",Forwarding(false,1),csrf:true),HttpStatusCode.OK,"fixture forwarding disabled after local check");}
            using(var response=await Request(HttpMethod.Get,"/api/v1/console/event-history?source=Server%20service%20decoy&limit=1"))
            {
                response.EnsureSuccessStatusCode();var page=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;check(page.Items.Count==1&&page.Items[0].RecordKind=="server-service"&&!page.Items[0].ResponseCandidate&&page.NextCursor!=null,"HTTP unified service history uses protected two-stream cursor and blocks response");
                await Status(await Request(HttpMethod.Get,"/api/v1/console/event-history?source=Server%20service%20decoy&limit=1&cursor="+Uri.EscapeDataString(page.NextCursor!)),HttpStatusCode.OK,"negative service identity resumes through protected history cursor");
            }
            using(var response=await Request(HttpMethod.Post,$"/api/v1/console/decoy-services/{active.Id}/retire",new DecoyServiceRetirement(active.Revision,password),csrf:true)){response.EnsureSuccessStatusCode();check((await response.Content.ReadFromJsonAsync<DecoyService>())!.Retired,"HTTP retirement persists tombstone");}
            await Status(await activationClient.GetAsync(created.ActivationPath),HttpStatusCode.NotFound,"retired service path no longer works");
            check(new Store(root).DecoyServiceHits(active.Id).Count==2,"retirement preserves HTTP hits across reopened store");
            var serviceEvidence=new Store(root).ServiceEvents(0).Last();var serviceSequence=-serviceEvidence.Sequence;
            using(var response=await Request(HttpMethod.Get,$"/api/v1/console/evidence/{serviceSequence}"))
            {response.EnsureSuccessStatusCode();var record=(await response.Content.ReadFromJsonAsync<HistoryEvent>())!;check(record.Event.EventId==serviceEvidence.Event.EventId&&record.Event.ServiceContext is {Location:"Isolated lab",Note:"Synthetic record\nNo real user data"}&&!record.ResponseCandidate,"HTTP evidence lookup retains service context after retirement");}
            await Status(await Request(HttpMethod.Get,"/api/v1/console/evidence/0"),HttpStatusCode.NotFound,"zero evidence identity is not a real event");
            var incidentBody=new CreateIncidentBody("Service event investigation","High",serviceSequence);
            await Status(await Request(HttpMethod.Post,"/api/v1/console/incidents",incidentBody),HttpStatusCode.BadRequest,"incident creation requires CSRF");
            Incident incident;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/incidents",incidentBody,csrf:true)){response.EnsureSuccessStatusCode();incident=(await response.Content.ReadFromJsonAsync<Incident>())!;check(incident.Version==1,"HTTP incident starts from server service evidence");}
            await Status(await Request(HttpMethod.Post,$"/api/v1/console/incidents/{incident.Id}/events",new LinkIncidentBody(1,1),csrf:true),HttpStatusCode.NoContent,"HTTP incident links endpoint and service evidence");
            await Status(await Request(HttpMethod.Post,$"/api/v1/console/incidents/{incident.Id}/events",new LinkIncidentBody(2,serviceSequence),csrf:true),HttpStatusCode.Conflict,"duplicate HTTP service link is refused");
            using(var response=await Request(HttpMethod.Get,$"/api/v1/console/incidents/{incident.Id}")){response.EnsureSuccessStatusCode();var detail=(await response.Content.ReadFromJsonAsync<IncidentDetail>())!;check(detail.Incident.Version==2&&detail.EventSequenceTexts.Contains(serviceSequence.ToString(System.Globalization.CultureInfo.InvariantCulture))&&detail.EventSequences.Count==2,"HTTP incident roundtrip preserves exact IDs and duplicate rollback");}
            using(var response=await Request(HttpMethod.Post,$"/api/v1/console/incidents/{incident.Id}/export",new ExportRequest("txt"),csrf:true)){response.EnsureSuccessStatusCode();var text=await response.Content.ReadAsStringAsync();check(text.Contains("Service event "+serviceEvidence.Sequence)&&!text.Contains("Event -"),"incident text export distinguishes service evidence");File.WriteAllText(Path.Combine(root,"service-incident.txt"),text);}
            using(var response=await Request(HttpMethod.Post,$"/api/v1/console/incidents/{incident.Id}/export",new ExportRequest("pdf"),csrf:true)){response.EnsureSuccessStatusCode();var bytes=await response.Content.ReadAsByteArrayAsync();check(response.Content.Headers.ContentType?.MediaType=="application/pdf"&&System.Text.Encoding.ASCII.GetString(bytes,0,5)=="%PDF-","HTTP incident PDF export created for separate visual review");File.WriteAllBytes(Path.Combine(root,"service-incident.pdf"),bytes);}
            SavedReport executive;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/reports",new ReportRequest(1),csrf:true)){response.EnsureSuccessStatusCode();executive=(await response.Content.ReadFromJsonAsync<SavedReport>())!;check(executive.Snapshot.ServiceEvents==2,"saved HTTP report includes service events");}
            using(var response=await Request(HttpMethod.Post,$"/api/v1/console/reports/{executive.Id}/export",new ExportRequest("pdf"),csrf:true)){response.EnsureSuccessStatusCode();var bytes=await response.Content.ReadAsByteArrayAsync();check(response.Content.Headers.ContentType?.MediaType=="application/pdf"&&System.Text.Encoding.ASCII.GetString(bytes,0,5)=="%PDF-","HTTP executive PDF export created for separate visual review");File.WriteAllBytes(Path.Combine(root,"service-summary.pdf"),bytes);}
            using(var response=await Request(HttpMethod.Get,"/api/v1/console/overview?days=1")){response.EnsureSuccessStatusCode();var snapshot=(await response.Content.ReadFromJsonAsync<ExecutiveSnapshot>())!;check(snapshot.ServiceEvents==2&&snapshot.TotalEvents==snapshot.Events+2&&snapshot.OpenIncidents==1,"HTTP overview includes service events and incident counts");}
            var emailSettings=new{expectedRevision=0,enabled=false,host="",port=587,from="",recipients=Array.Empty<string>(),username="",password=(string?)null,clearPassword=false,subjectPrefix="[seQuester]",minimumIntervalSeconds=1,administratorPassword=password,serviceHits=true};
            await Status(await Request(HttpMethod.Post,"/api/v1/console/email",emailSettings),HttpStatusCode.Unauthorized,"email configuration requires CSRF");
            await Status(await Request(HttpMethod.Post,"/api/v1/console/email",emailSettings,csrf:true),HttpStatusCode.OK,"administrator can configure service email while keeping sending disabled");
            using(var response=await Request(HttpMethod.Get,"/api/v1/console/email")){response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());var settings=json.RootElement.GetProperty("settings");check(settings.GetProperty("serviceHits").GetBoolean()&&!settings.GetProperty("enabled").GetBoolean()&&!settings.TryGetProperty("password",out _),"saved email source choice is returned without secrets or enabling delivery");}
            if(!adminPreview)await Status(await Request(HttpMethod.Post,"/api/v1/auth/login",new{userName="history-reader",password},csrf:true),HttpStatusCode.NoContent,"restore reader-only browser preview");
            foreach(var asset in new[]{"/","/event-history.js","/trust-policy.js","/console.js","/console.css","/manifest.webmanifest","/brand/sequester.ico","/brand/sequester-128.png","/brand/sequester-180.png","/brand/sequester-192.png","/brand/sequester-512.png"})await Status(await browser.GetAsync(asset),HttpStatusCode.OK,"published asset "+asset);
            // End-to-end local transport proof: real authenticated ingest and real server relay.
            // This trustCollector is loopback-only and is not a Wazuh acceptance claim.
            await Status(await Request(HttpMethod.Post,"/api/v1/auth/login",new{userName="history-admin",password},csrf:true),HttpStatusCode.NoContent,"isolated trust relay administrator signs in");
            var relayStore=new Store(root);var relayEndpoint=relayStore.Enroll(new(relayStore.CreateCode().Code,"trust-relay-fixture","fixture"))!;
            var relayRule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account",["read","delete"],"informational",DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1)){Enabled=true,Authority=relayEndpoint.EndpointId,AccountKind="uid",AccountId="1000"};
            TrustPolicy relayPolicy;
            using(var response=await Request(HttpMethod.Post,"/api/v1/console/trust-policy",new PublishTrustBody(published.Revision,"enforce",[relayRule],[],password),csrf:true)){response.EnsureSuccessStatusCode();relayPolicy=(await response.Content.ReadFromJsonAsync<TrustPolicy>())!;}
            var trustCollector=new TcpListener(IPAddress.Loopback,0);trustCollector.Start();
            try
            {
                var trustCollectorPort=((IPEndPoint)trustCollector.LocalEndpoint).Port;
                await Status(await Request(HttpMethod.Post,"/api/v1/console/server-syslog",new{expectedRevision=2,destination=new{enabled=true,host="127.0.0.1",port=trustCollectorPort,transport="TCP",facility=16,severity=4,format="RFC5424"},endpointEvents=true,callbackHits=false,administratorPassword=password},csrf:true),HttpStatusCode.OK,"isolated loopback endpoint relay enabled");
                var relayNow=DateTimeOffset.UtcNow;var relayActor=new TrustActor(Authority:relayEndpoint.EndpointId,AccountKind:"uid",AccountId:"1000",Verified:true);
                AgentEvent Wire(string syscall,string operation,string action)
                {
                    var value=new AgentEvent(Guid.NewGuid().ToString("N"),relayNow,operation,"/synthetic/trust-relay","fixture-user","/fixture/reader",123,"Linux Audit"){Attribution=new(){Provider="Linux Audit",Level="Partial attribution",Basis="Synthetic fixture",Syscall=syscall,UserId=1000,CompleteRecordSet=true,EventTimeCredentials=true,Outcome="Success"}};
                    return value with{Trust=new EventTrust(1,"linux",null,relayActor,new(relayPolicy.Revision,relayPolicy.Digest(),"enforce",TrustEvaluation.Evaluate(relayPolicy.Rules,new("server",null,relayEndpoint.EndpointId,"linux",value.Path,[action],relayNow,relayActor),relayNow))){EvaluatedUtc=relayNow}};
                }
                var relayEvents=new[]{Wire("read","Read intent","read"),Wire("unlink","Deletion intent","delete")};
                using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events")){request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",relayEndpoint.Credential);request.Content=JsonContent.Create(new EventBatch(relayEvents));using var response=await browser.SendAsync(request);response.EnsureSuccessStatusCode();var receipt=await response.Content.ReadFromJsonAsync<BatchReceipt>();check(receipt is {Accepted:2,TrustVersion:1},"authenticated agent ingest acknowledges both informational and deletion evidence");}
                using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(25));
                for(var index=0;index<2;index++)
                {
                    using var connection=await trustCollector.AcceptTcpClientAsync(deadline.Token);using var stream=connection.GetStream();using var reader=new StreamReader(stream);var line=await reader.ReadLineAsync(deadline.Token)??throw new Exception("Missing local relay payload");
                    File.WriteAllText(Path.Combine(root,"trust-relay-"+index+".txt"),line);
                    check(line.StartsWith(index==0?"<134>1 ":"<132>1 "),"real server relay applies informational only to read; deletion keeps warning "+index);
                    using var json=JsonDocument.Parse(line[line.IndexOf('{')..]);var e=relayEvents[index];var payload=json.RootElement;
                    check(payload.GetProperty("EventId").GetString()==e.EventId&&payload.GetProperty("User").GetString()==e.User&&payload.GetProperty("Process").GetString()==e.Process&&payload.GetProperty("ProcessId").GetInt32()==e.ProcessId&&payload.GetProperty("Trust").GetRawText()==JsonSerializer.Serialize(e.Trust)&&payload.GetProperty("Attribution").GetRawText()==JsonSerializer.Serialize(e.Attribution),"TCP trustCollector receives complete actor and trust evidence "+index);
                    var committed=new Store(root).Events(0,2000).Single(x=>x.Event.EventId==e.EventId);check(JsonSerializer.Serialize(committed.Event)==JsonSerializer.Serialize(e),"server retains exact event after successful relay "+index);
                }
                var whitelist=relayRule with{Disposition="log-only",Actions=["read"],Name="QA read only"};
                using(var response=await Request(HttpMethod.Post,"/api/v1/console/trust-policy",new PublishTrustBody(relayPolicy.Revision,"enforce",[whitelist],[],password),csrf:true)){response.EnsureSuccessStatusCode();relayPolicy=(await response.Content.ReadFromJsonAsync<TrustPolicy>())!;check(relayPolicy.Version==2,"HTTP log-only publication uses versioned whitelist policy");}
                relayNow=DateTimeOffset.UtcNow;
                var muted=Wire("read","Read intent","read");muted=muted with{Trust=muted.Trust! with{Version=2}};
                var sentinel=Wire("write","Write intent","write");sentinel=sentinel with{Trust=sentinel.Trust! with{Version=2}};
                ForensicEvidence Forensic(AgentEvent value)=>new(){EventId=value.EventId,SensorId=relayEndpoint.EndpointId,CollectorEpoch=Guid.NewGuid().ToString("N"),CollectorSequence=1,MonotonicTicks=100,MonotonicFrequency=1000,ObservedUtc=value.ObservedUtc,CapturedUtc=value.ObservedUtc,Process=new(){Pid=value.ProcessId,ExecutablePath=value.Process},Observation=new(){Path=value.Path,Actions=["read"]},ActorExecutable=new(){ObservedPath=value.Process,Sha256=new string('A',64),HashStatus=EvidenceStatus.Captured("synthetic-schema-fixture")},Collection=new("partial","synthetic-schema-fixture")};
                muted=muted with{Forensics=Forensic(muted)};sentinel=sentinel with{Forensics=Forensic(sentinel)};
                sentinel=sentinel with{Forensics=sentinel.Forensics! with{Process=sentinel.Forensics!.Process with{ParentPid=19,ParentExecutablePath="/usr/bin/parent-fixture",ParentStatus=new("partial","parent-start-unavailable"),ProcessSessionId=7,SessionStatus=EvidenceStatus.Captured("synthetic-session-fixture")},ActorExecutable=sentinel.Forensics.ActorExecutable with{File=new(){StableId="linux:8:1:1234",AccessedUtc=sentinel.ObservedUtc.AddMinutes(-2),ChangedUtc=sentinel.ObservedUtc.AddMinutes(-1),Status=EvidenceStatus.Captured("synthetic-file-fixture")}}}};
                using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events")){request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",relayEndpoint.Credential);request.Content=JsonContent.Create(new EventBatch([muted,sentinel]));using var response=await browser.SendAsync(request);response.EnsureSuccessStatusCode();var receipt=await response.Content.ReadFromJsonAsync<BatchReceipt>();check(receipt is {Accepted:2,WhitelistVersion:1},"HTTP ingest acknowledges both logged-only read and alerting write");}
                using(var connection=await trustCollector.AcceptTcpClientAsync(deadline.Token))
                {using var reader=new StreamReader(connection.GetStream());var line=await reader.ReadLineAsync(deadline.Token)??throw new Exception("Missing unsuppressed sentinel");using var json=JsonDocument.Parse(line[line.IndexOf('{')..]);check(json.RootElement.GetProperty("EventId").GetString()==sentinel.EventId,"real server relay skips log-only read and forwards next disallowed write");check(json.RootElement.GetProperty("Forensics").GetRawText()==JsonSerializer.Serialize(sentinel.Forensics),"TCP server relay preserves structured actor evidence without flattening");}
                var durable=new Store(root).Events(0,2000).Single(e=>e.Event.EventId==muted.EventId);
                check(JsonSerializer.Serialize(durable.Event)==JsonSerializer.Serialize(muted)&&relayStore.ClassifyTrust(durable)==TrustEventClassification.LogOnly,"muted notification remains stored with exact actor and matching rule");
                using(var response=await Request(HttpMethod.Get,"/api/v1/console/event-history?endpoint="+relayEndpoint.EndpointId+"&limit=100"))
                {response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());var row=json.RootElement.GetProperty("items").EnumerateArray().Single(x=>x.GetProperty("event").GetProperty("eventId").GetString()==muted.EventId);check(row.GetProperty("trustClassification").GetString()=="LogOnly"&&row.GetProperty("event").GetProperty("processId").GetInt32()==123,"authenticated Event History API exposes server-validated log-only status and PID");}
                var completeId=Guid.NewGuid().ToString("N");var follow=muted with{EventId=completeId,Source="Forensic enrichment",Operation="Actor forensic evidence collected",Trust=null,Forensics=muted.Forensics! with{EventId=completeId,RelatedEventId=muted.EventId,CollectorSequence=2}};
                var nextId=Guid.NewGuid().ToString("N");var next=sentinel with{EventId=nextId,Forensics=sentinel.Forensics! with{EventId=nextId,CollectorSequence=3}};
                using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events")){request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",relayEndpoint.Credential);request.Content=JsonContent.Create(new EventBatch([follow,next]));using var response=await browser.SendAsync(request);response.EnsureSuccessStatusCode();var receipt=await response.Content.ReadFromJsonAsync<BatchReceipt>();check(receipt is {Accepted:2,ForensicsVersion:1},"HTTP server explicitly acknowledges forensic schema");}
                using(var connection=await trustCollector.AcceptTcpClientAsync(deadline.Token))
                {using var reader=new StreamReader(connection.GetStream());var line=await reader.ReadLineAsync(deadline.Token)??throw new Exception("Missing forensic sentinel");using var json=JsonDocument.Parse(line[line.IndexOf('{')..]);check(json.RootElement.GetProperty("EventId").GetString()==next.EventId,"log-only forensic completion also suppresses alert forwarding through original server-validated decision");}
                using(var response=await Request(HttpMethod.Get,"/api/v1/console/event-history?endpoint="+relayEndpoint.EndpointId+"&action=Forensic%20Evidence&limit=100"))
                {response.EnsureSuccessStatusCode();var page=(await response.Content.ReadFromJsonAsync<EventHistoryPage>())!;check(page.Items.Count==1&&page.Items[0].Event.Forensics?.RelatedEventId==muted.EventId&&!page.Items[0].ResponseCandidate,"API forensic action filter and immutable source-event linkage survive storage");}
                using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events")){request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",relayEndpoint.Credential);request.Content=JsonContent.Create(new EventBatch([next with{Forensics=next.Forensics! with{SensorId=Guid.NewGuid().ToString("N")}}]));using var response=await browser.SendAsync(request);check(response.StatusCode==HttpStatusCode.BadRequest,"HTTP forensic evidence cannot claim a different sensor identity");}
                await Status(await Request(HttpMethod.Post,"/api/v1/console/server-syslog",new{expectedRevision=3,destination=new{enabled=true,host="127.0.0.1",port=trustCollectorPort,transport="TCP",facility=16,severity=4,format="RFC5424"},endpointEvents=true,includeLogOnlyEvents=true,callbackHits=false,administratorPassword=password},csrf:true),HttpStatusCode.OK,"administrator enables informational export of whitelisted events");
                using(var response=await Request(HttpMethod.Get,"/api/v1/console/server-syslog"))
                {response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());check(json.RootElement.GetProperty("settings").GetProperty("includeLogOnlyEvents").GetBoolean(),"informational export setting survives protected persistence and API read");}
                var exportedId=Guid.NewGuid().ToString("N");var exported=muted with{EventId=exportedId,Forensics=muted.Forensics! with{EventId=exportedId,CollectorSequence=4}};
                var exportedFollowId=Guid.NewGuid().ToString("N");var exportedFollow=follow with{EventId=exportedFollowId,Forensics=follow.Forensics! with{EventId=exportedFollowId,RelatedEventId=exportedId,CollectorSequence=5}};
                using(var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/agent/events")){request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",relayEndpoint.Credential);request.Content=JsonContent.Create(new EventBatch([exported,exportedFollow]));using var response=await browser.SendAsync(request);response.EnsureSuccessStatusCode();}
                foreach(var expected in new[]{exported,exportedFollow})
                {
                    using var connection=await trustCollector.AcceptTcpClientAsync(deadline.Token);using var reader=new StreamReader(connection.GetStream());var line=await reader.ReadLineAsync(deadline.Token)??throw new Exception("Missing whitelisted informational export");using var json=JsonDocument.Parse(line[line.IndexOf('{')..]);
                    check(line.StartsWith("<134>1 ")&&json.RootElement.GetProperty("EventId").GetString()==expected.EventId&&json.RootElement.GetProperty("NotificationSuppressed").GetBoolean(),"whitelisted original/completion exported at informational severity with authoritative suppression flag");
                    check(json.RootElement.GetProperty("Forensics").GetRawText()==JsonSerializer.Serialize(expected.Forensics),"informational export preserves complete actor evidence and source linkage");
                }
                check(new Store(root).ClassifyTrust(new Store(root).Events(0,2000).Single(e=>e.Event.EventId==exportedId))==TrustEventClassification.LogOnly,"SIEM export does not change whitelist enforcement or alert disposition");
                await Status(await Request(HttpMethod.Post,"/api/v1/console/server-syslog",new{expectedRevision=4,destination=new{enabled=false,host="127.0.0.1",port=trustCollectorPort,transport="TCP",facility=16,severity=4,format="RFC5424"},endpointEvents=true,includeLogOnlyEvents=true,callbackHits=false,administratorPassword=password},csrf:true),HttpStatusCode.OK,"isolated relay disabled after evidence capture");
            }
            finally{trustCollector.Stop();}
            if(!adminPreview)await Status(await Request(HttpMethod.Post,"/api/v1/auth/login",new{userName="history-reader",password},csrf:true),HttpStatusCode.NoContent,"restore reader role after trust relay check");
            checkpoint();
            if(preview)
            {
                // A GET-only, loopback-only proxy carries the fixture reader's session.
                // Browser automation never handles a user authentication dialog or secrets.
                var probe=new TcpListener(IPAddress.Loopback,0);probe.Start();var previewPort=((IPEndPoint)probe.LocalEndpoint).Port;probe.Stop();
                using var proxy=new HttpListener();var origin=$"http://127.0.0.1:{previewPort}/";proxy.Prefixes.Add(origin);proxy.Start();
                File.WriteAllText(Path.Combine(root,"preview.json"),JsonSerializer.Serialize(new{Url=origin,ReadOnly=true,Synthetic=true,ServerPid=process.Id,ExpiresUtc=DateTimeOffset.UtcNow.AddMinutes(30)}));
                Console.WriteLine("ISOLATED READ-ONLY BROWSER PREVIEW: "+origin);
                var until=Task.Delay(TimeSpan.FromMinutes(30));
                while(!until.IsCompleted)
                {
                    var pending=proxy.GetContextAsync();if(await Task.WhenAny(pending,until)!=pending)break;var incoming=await pending;
                    try
                    {
                        var relative=incoming.Request.Url!.PathAndQuery;var destination=new Uri(browser.BaseAddress!,relative);
                        if(incoming.Request.HttpMethod!="GET"||destination.Host!="127.0.0.1"||destination.Port!=port||destination.Scheme!="http"){incoming.Response.StatusCode=405;continue;}
                        using var response=await browser.GetAsync(destination);incoming.Response.StatusCode=(int)response.StatusCode;
                        incoming.Response.ContentType=response.Content.Headers.ContentType?.ToString()??"application/octet-stream";
                        byte[] bytes;if(relative=="/"){var html=await response.Content.ReadAsStringAsync();bytes=System.Text.Encoding.UTF8.GetBytes(html.Replace("<body>","<body><div role=\"status\">Isolated fixture · Synthetic events · Read-only</div>"));}else bytes=await response.Content.ReadAsByteArrayAsync();
                        incoming.Response.ContentLength64=bytes.Length;await incoming.Response.OutputStream.WriteAsync(bytes);
                    }
                    finally{incoming.Response.Close();}
                }
            }
        }
        finally{if(!process.HasExited){process.Kill();await process.WaitForExitAsync();}lock(log)File.WriteAllLines(Path.Combine(root,"http-server.log"),log);}
    }
}
