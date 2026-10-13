using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using PdfSharp.Pdf.Content;
using PdfSharp.Pdf.Content.Objects;
using PdfSharp.Pdf.IO;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class ReportChecks
{
    private static string PdfText(byte[] bytes)
    {
        static void Append(CObject value,StringBuilder result)
        {
            switch(value)
            {
                case CString text:result.Append(text.Value).Append(' ');break;
                case COperator operation:foreach(var item in operation.Operands)Append(item,result);break;
                case CSequence sequence:foreach(var item in sequence)Append(item,result);break;
            }
        }
        using var input=new MemoryStream(bytes);using var document=PdfReader.Open(input,PdfDocumentOpenMode.Import);var result=new StringBuilder();
        foreach(var page in document.Pages)Append(ContentReader.ReadContent(page),result);
        return result.ToString();
    }
    public static async Task Run(Uri origin,string root,Action<bool,string> check)
    {
        var directory=Path.Combine(root,"report-fixtures");Directory.CreateDirectory(directory);var store=new Store(directory);
        var empty=store.Snapshot(7);check(empty.Registered==0 && empty.Events==0 && empty.RecentContact==0 && empty.ProtectionReportingClients==0 && empty.NonWhitelistedAlerts==0,"empty reporting state is valid without an inventory prerequisite");
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"management.db")}.ToString()))
        {
            c.Open();using var tx=c.BeginTransaction();
            using var insert=c.CreateCommand();insert.Transaction=tx;insert.CommandText="INSERT INTO endpoints(id,credential_hash,machine,version,health,last_seen,revoked) VALUES($id,$id,'QA endpoint','test','QA',$seen,$revoked)";
            var id=insert.Parameters.Add("$id",SqliteType.Text);var seen=insert.Parameters.Add("$seen",SqliteType.Integer);var revoked=insert.Parameters.Add("$revoked",SqliteType.Integer);
            for(var i=0;i<1005;i++){id.Value=Guid.NewGuid().ToString("N");seen.Value=DateTimeOffset.UtcNow.AddHours(i%2==0?0:-1).ToUnixTimeMilliseconds();revoked.Value=i<5?1:0;insert.ExecuteNonQuery();}
            using var protection=c.CreateCommand();protection.Transaction=tx;protection.CommandText="CREATE TABLE endpoint_protection(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),deployed_items INTEGER NOT NULL,monitoring_state TEXT NOT NULL,reported INTEGER NOT NULL); INSERT INTO endpoint_protection SELECT id,3,'active',$now FROM endpoints WHERE revoked=0 LIMIT 1; INSERT INTO endpoint_protection SELECT id,0,'degraded',$now FROM endpoints WHERE revoked=0 AND id NOT IN (SELECT endpoint FROM endpoint_protection) LIMIT 1";protection.Parameters.AddWithValue("$now",DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());protection.ExecuteNonQuery();tx.Commit();
        }
        var s=store.Snapshot(7);check(s.Registered==1005 && s.Revoked==5 && s.RecentContact+s.StaleContact==1000,"enrolled inventory remains available without becoming a protection denominator");
        check(s.ProtectionReportingClients==2 && s.ProtectionActiveClients==1 && s.ProtectionNeedsAttentionClients==1 && s.DeployedCanaryAndHoneypotFiles==3,"protection aggregate uses only actual client reports and accepts an explicit zero-item degraded report");
        string endpointId;using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"management.db")}.ToString())){c.Open();using var endpoint=c.CreateCommand();endpoint.CommandText="SELECT id FROM endpoints WHERE revoked=0 ORDER BY id LIMIT 1";endpointId=(string)endpoint.ExecuteScalar()!;}
        store.InitializeTrustStorage();var account="S-1-5-21-1000";var infoActor=new TrustActor(Authority:"QA",AccountId:account,Verified:true,AccountKind:"sid");var normalActor=infoActor with{AccountId="S-1-5-21-2000"};
        var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account",["read"],"informational",DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1)){Enabled=true,Authority="QA",AccountId=account,AccountKind="sid",OperatingSystem="windows"};
        var policy=store.PublishTrustPolicy(new(0,"enforce",[rule],[],"unused"),"qa-owner");var evaluated=policy.PublishedUtc.AddSeconds(1);var observed=evaluated.AddMilliseconds(-500);var received=evaluated.AddMilliseconds(500);
        AgentEvent Evidence(TrustActor actor)=>new(Guid.NewGuid().ToString("N"),observed,"Content read (copy possible)","C:\\QA\\bait.txt","QA\\user","reader.exe",41,"Windows audit 4663");
        EventTrust Claim(AgentEvent evidence,TrustActor actor,string mode="enforce")
        {
            var decision=mode=="enforce"?TrustEvaluation.Evaluate(policy.Rules,new TrustContext("server",null,endpointId,"windows",evidence.Path,EventActivity.From(evidence).Actions,evidence.ObservedUtc,actor),evaluated,policy.ApprovedRules()):new TrustDecision(1,"normal",false,mode=="pending","normal",[],mode=="pending"?"Trust policy is pending.":"Legacy decision.");
            return new(1,"windows",null,actor,new(mode=="pending"?null:policy.Revision,mode=="pending"?null:policy.Digest(),mode,decision)){EvaluatedUtc=evaluated};
        }
        var infoEvent=Evidence(infoActor);infoEvent=infoEvent with{Trust=Claim(infoEvent,infoActor)};var normalEvent=Evidence(normalActor);normalEvent=normalEvent with{Trust=Claim(normalEvent,normalActor)};
        var unknownEvents=new[]
        {
            Evidence(infoActor),
            Evidence(infoActor) with{Trust=Claim(Evidence(infoActor),infoActor,"pending")},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=infoEvent.Trust! with{Result=infoEvent.Trust!.Result with{Decision=infoEvent.Trust.Result.Decision with{Reason="Fabricated decision."}}}},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=infoEvent.Trust! with{Result=infoEvent.Trust!.Result with{Digest=new string('b',64)}}},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=infoEvent.Trust! with{EvaluatedUtc=policy.PublishedUtc.AddTicks(-1)}},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=Claim(infoEvent,infoActor,"legacy")},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=infoEvent.Trust! with{Version=3}},
            infoEvent with{EventId=Guid.NewGuid().ToString("N"),Trust=infoEvent.Trust! with{Group=Guid.NewGuid().ToString("N")}}
        };
        check(store.ClassifyTrust(new(1,endpointId,received,normalEvent))==TrustEventClassification.NonWhitelisted,"authoritative replay classifies an exact normal decision as non-whitelisted");
        check(store.ClassifyTrust(new(2,endpointId,received,infoEvent))==TrustEventClassification.Informational,"authoritative replay classifies an exact informational decision as lower-level activity");
        foreach(var item in unknownEvents)check(store.ClassifyTrust(new(3,endpointId,received,item))==TrustEventClassification.PolicyUnknown,"missing, pending, fabricated, mismatched, stale, legacy, invalid, and wrong-group claims stay policy unknown");
        var saved=store.CreateReport(7,"qa-owner");
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"management.db")}.ToString()))
        {
            c.Open();using var cmd=c.CreateCommand();
            cmd.CommandText="INSERT INTO events(endpoint,event_id,received,payload) SELECT id,$event,$time,$payload FROM endpoints LIMIT 1";
            var eventId=cmd.Parameters.Add("$event",SqliteType.Text);var receivedParameter=cmd.Parameters.Add("$time",SqliteType.Integer);
            var payload=cmd.Parameters.Add("$payload",SqliteType.Text);
            var current=new[]{normalEvent,infoEvent}.Concat(unknownEvents).ToArray();foreach(var entry in current){eventId.Value=entry.EventId;receivedParameter.Value=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();payload.Value=JsonSerializer.Serialize(entry);cmd.ExecuteNonQuery();}
            foreach(var daysAgo in new[]{8,30,-1}){var entry=Evidence(infoActor);eventId.Value=entry.EventId;receivedParameter.Value=DateTimeOffset.UtcNow.AddDays(-daysAgo).ToUnixTimeMilliseconds();payload.Value=JsonSerializer.Serialize(entry);cmd.ExecuteNonQuery();}
        }
        var activity=store.Snapshot(7);
        check(activity.Events==10 && activity.PreviousEvents==1 && activity.ReportingEndpoints==1,"activity windows exclude old/future receipts and count distinct reporting endpoints");
        check(activity.NonWhitelistedAlerts==1 && activity.InformationalActivity==1 && activity.PolicyUnknownAlerts==8,"reports reuse authoritative policy replay and retain every unproven claim as policy unknown");
        check(store.ReadReport(saved.Id,"qa-owner",false)?.Snapshot.Events==0,"saved report remains unchanged after new events arrive");
        check(store.ReadReport(saved.Id,"other-reader",false)==null,"report ownership enforced in persistence layer");
        check(store.ReadReport(saved.Id,"administrator",true)?.Snapshot==saved.Snapshot,"administrator can read immutable report snapshot");
        check(new Store(directory).ReadReport(saved.Id,"qa-owner",false)==saved,"report survives store restart");
        check(new Store(directory).ListReports("qa-owner").Single()==saved && store.ListReports("other-reader").Count==0,"saved report history persists and is owner scoped");
        var text=ReportRenderer.Text(saved);var pdf=ReportRenderer.Pdf(saved);
        check(text.Contains("2 clients reported protection state"),"text export includes actual client protection reports");
        check(text.Contains("no expected client count",StringComparison.OrdinalIgnoreCase) && text.Contains("inventory prerequisite",StringComparison.OrdinalIgnoreCase),"text export explicitly rejects an inventory prerequisite");
        check(!text.Contains("credential_hash"),"text export excludes stored credentials");
        check(pdf.AsSpan().StartsWith("%PDF-"u8) && pdf.Length>5000,"PDF export contains a real formatted document");
        File.WriteAllText(Path.Combine(root,"executive-summary.txt"),text);File.WriteAllBytes(Path.Combine(root,"executive-summary.pdf"),pdf);
        var historical=JsonNode.Parse(JsonSerializer.Serialize(saved))!;var historicalSnapshot=historical["Snapshot"]!.AsObject();
        foreach(var field in new[]{"ProtectionReportingClients","ProtectionActiveClients","ProtectionNeedsAttentionClients","DeployedCanaryAndHoneypotFiles","NonWhitelistedAlerts","PolicyUnknownAlerts","InformationalActivity"})historicalSnapshot.Remove(field);
        var historicalReport=historical.Deserialize<SavedReport>()!;var historicalPdf=ReportRenderer.Pdf(historicalReport);var historicalText=PdfText(historicalPdf);
        check(historicalText.Split("Not captured",StringSplitOptions.None).Length-1>=7,"historical PDF renders omitted protection and alert values as Not captured rather than invented zeroes");
        File.WriteAllBytes(Path.Combine(root,"executive-historical.pdf"),historicalPdf);
        var large=ReportRenderer.Pdf(saved with {Snapshot=saved.Snapshot with {Registered=long.MaxValue,RecentContact=long.MaxValue,StaleContact=long.MaxValue,Revoked=long.MaxValue,Events=long.MaxValue,PreviousEvents=long.MaxValue,ReportingEndpoints=long.MaxValue,Days=90}});
        File.WriteAllBytes(Path.Combine(root,"executive-large-counts.pdf"),large);check(large.Length>5000,"PDF renderer handles maximum count values without layout exceptions");
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"management.db")}.ToString()))
        {
            c.Open();using var cmd=c.CreateCommand();cmd.CommandText="WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4999) INSERT INTO reports(id,owner,created,payload) SELECT 'quota-'||x,'qa-owner',0,$payload FROM n";cmd.Parameters.AddWithValue("$payload",JsonSerializer.Serialize(saved));cmd.ExecuteNonQuery();
        }
        var capacityRejected=false;try{store.CreateReport(7,"qa-owner");}catch(ReportCapacityException){capacityRejected=true;}
        check(capacityRejected && store.ReadReport(saved.Id,"qa-owner",false)==saved,"report capacity rejection preserves existing snapshots");
        check(store.ListReports("qa-owner").Count==100,"saved report history has a bounded response");
        using var anonymous=new HttpClient {BaseAddress=origin};
        using(var denied=await anonymous.GetAsync("/api/v1/console/overview"))check(denied.StatusCode==HttpStatusCode.Unauthorized,"anonymous executive overview denied");
        async Task<HttpClient> Login(string name)
        {
            var client=new HttpClient {BaseAddress=origin};using var token=await client.GetFromJsonAsync<JsonDocument>("/api/v1/auth/csrf");
            using var request=new HttpRequestMessage(HttpMethod.Post,"/api/v1/auth/login") {Content=JsonContent.Create(new {userName=name,password="QA-only-long-passphrase-904!"})};request.Headers.Add("X-CSRF",token!.RootElement.GetProperty("token").GetString());
            using var response=await client.SendAsync(request);response.EnsureSuccessStatusCode();return client;
        }
        async Task<HttpResponseMessage> Post(HttpClient client,string path,object body,bool csrf=true)
        {
            using var request=new HttpRequestMessage(HttpMethod.Post,path){Content=JsonContent.Create(body)};
            if(csrf){using var token=await client.GetFromJsonAsync<JsonDocument>("/api/v1/auth/csrf");request.Headers.Add("X-CSRF",token!.RootElement.GetProperty("token").GetString());}
            return await client.SendAsync(request);
        }
        using var admin=await Login("local-admin");using var reader=await Login("reader-test");
        using(var invalid=await admin.GetAsync("/api/v1/console/overview?days=91"))check(invalid.StatusCode==HttpStatusCode.BadRequest,"unbounded executive period rejected");
        using(var missing=await Post(admin,"/api/v1/console/reports",new {days=7},false))check(missing.StatusCode==HttpStatusCode.BadRequest,"report creation requires CSRF proof");
        using var created=await Post(admin,"/api/v1/console/reports",new {days=7});created.EnsureSuccessStatusCode();var report=(await created.Content.ReadFromJsonAsync<SavedReport>())!;
        var history=await admin.GetFromJsonAsync<List<SavedReport>>("/api/v1/console/reports");var otherHistory=await reader.GetFromJsonAsync<List<SavedReport>>("/api/v1/console/reports");
        check(history!.Any(x=>x.Id==report.Id) && otherHistory!.Count==0,"report history API returns only the signed-in user's snapshots");
        using(var denied=await Post(reader,$"/api/v1/console/reports/{report.Id}/export",new {format="txt"}))check(denied.StatusCode==HttpStatusCode.NotFound,"reader cannot export another user's report");
        using(var invalid=await Post(admin,$"/api/v1/console/reports/{report.Id}/export",new {format="html"}))check(invalid.StatusCode==HttpStatusCode.BadRequest,"unsupported report export format rejected");
        using(var missing=await Post(admin,$"/api/v1/console/reports/{report.Id}/export",new {format="pdf"},false))check(missing.StatusCode==HttpStatusCode.BadRequest,"report export requires CSRF proof");
        using(var txt=await Post(admin,$"/api/v1/console/reports/{report.Id}/export",new {format="txt"}))check(txt.IsSuccessStatusCode && txt.Content.Headers.ContentDisposition?.DispositionType=="attachment" && (await txt.Content.ReadAsStringAsync()).Contains(report.Id),"text report download is authorized and identifies saved snapshot");
        using(var document=await Post(admin,$"/api/v1/console/reports/{report.Id}/export",new {format="pdf"}))check(document.IsSuccessStatusCode && document.Content.Headers.ContentType?.MediaType=="application/pdf" && (await document.Content.ReadAsByteArrayAsync()).AsSpan().StartsWith("%PDF-"u8),"PDF report download succeeds over packaged API");
    }
}
