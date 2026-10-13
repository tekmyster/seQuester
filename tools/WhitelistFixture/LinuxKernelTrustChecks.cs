using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Contracts;
using RansomFree.Server;

internal static class LinuxKernelTrustChecks
{
    internal static async Task Run(string evidence,string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated root required");Directory.CreateDirectory(root);
        byte[] Exact(string name,string hash)
        {
            var bytes=File.ReadAllBytes(Path.Combine(evidence,name));
            if(Convert.ToHexString(SHA256.HashData(bytes))!=hash)throw new InvalidDataException("Accepted native R36 evidence required");return bytes;
        }
        var originals=JsonNode.Parse(Exact("events.json","09D3DFC1501CC00CE9EF550EEB9E301BE5A8C7829B30E557E9B081790315C3B4"))!["Originals"]!.Deserialize<AgentEvent[]>()!;
        var samples=JsonNode.Parse(Exact("source-health.json","9C19E06A9FCBE7EFA8689F47BB5F894F0E7584D5E95AB31449F5D82C6D646A85"))!["Observations"]!.AsArray();
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is ArgumentException or InvalidDataException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        var directory=Path.Combine(root,"server");var store=new Store(directory);store.InitializeTrustStorage();
        var enrolled=store.Enroll(new(store.CreateCode().Code,"Native trust archived replay","qualification"))!;
        var sensor=originals[0].Forensics!.SensorId;
        // Only this new empty test endpoint is mapped to the archived sensor.
        // Native evidence and process-instance identities are not rewritten.
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"management.db")}.ToString()))
        {c.Open();using var q=c.CreateCommand();q.CommandText="UPDATE endpoints SET id=$sensor WHERE id=$id";q.Parameters.AddWithValue("$sensor",sensor);q.Parameters.AddWithValue("$id",enrolled.EndpointId);Check(q.ExecuteNonQuery()==1,"isolated empty endpoint mapped to native sensor ID");}
        var first=originals[0];var facts=LinuxKernelActorMatchEvidence.Inspect(first).Evidence!;
        var now=DateTimeOffset.UtcNow;
        var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["open"],"log-only",first.ObservedUtc.AddMinutes(-1),now.AddDays(1))
        {Enabled=true,OperatingSystem="linux",ProcessMatch=TrustEvaluation.LinuxKernelProcessMatch,Executable=facts.Executable,Sha256=facts.Sha256};
        var body=new PublishTrustBody(0,"enforce",[rule],[],"unused");
        Reject(()=>store.PublishTrustPolicy(body,"qa"),"missing policy capability blocks publication");
        Check(store.RecordTrustCapabilities(sensor,new(1,3,0,"linux")),"Linux parser support recorded without claiming native support");
        Reject(()=>store.PublishTrustPolicy(body,"qa"),"inactive native source blocks applicable Linux whitelist");
        Reject(()=>store.RecordTrustCapabilities(sensor,new(1,2,1,"linux")),"native support cannot contradict policy parser version");
        Reject(()=>store.RecordTrustCapabilities(sensor,new(1,3,1,"windows")),"Windows cannot advertise Linux source");
        Check(store.RecordTrustCapabilities(sensor,new(1,3,1,"linux")),"qualified Linux source capability recorded");
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"management.db")}.ToString()))
        {
            c.Open();using var q=c.CreateCommand();q.CommandText="UPDATE trust_capabilities SET reported=$time WHERE endpoint=$id";
            q.Parameters.AddWithValue("$time",DateTimeOffset.UtcNow.AddSeconds(-Store.LinuxTrustSourceMaximumAgeSeconds-10).ToUnixTimeMilliseconds());q.Parameters.AddWithValue("$id",sensor);
            Check(q.ExecuteNonQuery()==1,"isolated source readiness sample made stale without expiring parser support");
        }
        Reject(()=>store.PublishTrustPolicy(body,"qa"),"old active source sample cannot publish a new native rule");
        Check(store.RecordTrustCapabilities(sensor,new(1,3,1,"linux")),"fresh actual-source report restores readiness");
        var windows=store.Enroll(new(store.CreateCode().Code,"Older Windows","fixture"))!;
        Reject(()=>store.PublishTrustPolicy(body,"qa"),"global revision cannot be published while another sensor parser is unknown");
        Check(store.RecordTrustCapabilities(windows.EndpointId,new(1,3,0,"windows")),"Windows can parse v3 without claiming Linux native source");
        var policy=store.PublishTrustPolicy(body,"qa");
        Check(policy.Version==3&&new Store(directory).ReadTrustPolicy().Digest()==policy.Digest(),"qualified version3 revision persists exactly");
        Check(store.TrustCapabilityStatuses().Count==2&&store.TrustCapabilityStatuses().All(c=>c.PolicyVersion==3),"capability history is queryable and survives database reads");
        Check(store.RecordTrustCapabilities(windows.EndpointId,new()),"older empty request explicitly replaces stale capability claim");
        Reject(()=>store.PublishTrustPolicy(body with{ExpectedRevision=policy.Revision},"qa"),"downgraded parser report blocks subsequent v3 publication");
        Check(store.ReadTrustPolicy().Digest()==policy.Digest(),"rejected publication leaves current policy unchanged");
        var e=first;var source=samples.Single(n=>n!["EventId"]!.GetValue<string>()==e.EventId)!["Result"]!["Evidence"]!.Deserialize<LinuxKernelSourceMatchEvidence>()!;
        var binding=LinuxKernelTrustBinding.Create(e,source);
        var context=new TrustContext("server",null,sensor,"linux",e.Path,["open"],e.ObservedUtc,binding.TrustActor()){ProcessBasis=LinuxKernelTrustBinding.Basis};
        var evaluated=DateTimeOffset.UtcNow;var decision=TrustEvaluation.Evaluate(policy.Rules,context,evaluated);
        var claim=new EventTrust(3,"linux",null,binding.TrustActor(),new(policy.Revision,policy.Digest(),"enforce",decision))
            {EvaluatedUtc=evaluated,ProcessBasis=LinuxKernelTrustBinding.Basis,LinuxKernelBinding=binding};
        e=e with{Trust=claim,Forensics=e.Forensics! with{Detection=new("log-only","informational",["SQ-MONITORED-FILE-001"],["MONITORED_FILE_ACTIVITY"])}};
        Check(claim.IsValid()&&binding.Matches(e)&&decision.LogOnly,"synthetic policy decision binds unchanged archived native evidence");
        var stored=new StoredEvent(1,sensor,DateTimeOffset.UtcNow,e);
        Check(store.ClassifyTrust(stored)==TrustEventClassification.LogOnly,"server independently checks binding and historical rule decision");
        Check(store.ClassifyTrust(stored with{Event=e with{ProcessId=e.ProcessId+1}})==TrustEventClassification.PolicyUnknown,"server rejects reused/mismatched PID claim");
        Check(store.ClassifyTrust(stored with{Event=e with{Trust=claim with{LinuxKernelBinding=binding with{Actor=binding.Actor with{Sha256=new string('a',64)}}}}})==TrustEventClassification.PolicyUnknown,"server rejects different executable hash");
        Check(store.ClassifyTrust(stored with{Event=e with{Forensics=e.Forensics! with{CollectorSequence=e.Forensics!.CollectorSequence+1}}})==TrustEventClassification.PolicyUnknown,"server rejects changed nondecision timeline fields");
        Check(store.ClassifyTrust(stored with{Event=e with{Trust=claim with{Result=claim.Result with{Digest=new string('b',64)}}}})==TrustEventClassification.PolicyUnknown,"server rejects policy digest substitution");
        Check(store.Ingest(sensor,new([e]))?.Accepted==1&&new Store(directory).ClassifyTrust(store.Events(0,10).Single())==TrustEventClassification.LogOnly,"log-only native original stored and classified after reopen");
        store.PublishTrustPolicy(new(policy.Revision,"enforce",[],[],"unused"),"qa");
        Check(store.ClassifyTrust(stored)==TrustEventClassification.LogOnly,"new policy revision does not reevaluate committed historical decision");
        var spool=new EventSpool(Path.Combine(root,"spool"),sensor);spool.Enqueue(e);var batch=spool.Peek();
        var receipt=new BatchReceipt(1,0){AttributionVersion=1,TrustVersion=1,WhitelistVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxKernelTargetIdentityVersion=1,LinuxActorAcquisitionVersion=1,LinuxNativeWorkVersion=2};
        Reject(()=>spool.Acknowledge(batch,receipt),"old acknowledgement cannot discard version3 evidence");
        Check(spool.Count==1,"failed capability acknowledgement retains exact queued original");
        foreach(var mode in new[]{"preflight-old","receipt-old","success"})
        {
            using var handler=new CapabilityTransport(mode,receipt);using var http=new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")};using var client=new ManagementClient(http,new string('a',64));
            bool failed=false;try{await client.SendEventsAsync(batch);}catch(InvalidDataException){failed=true;}
            Check(failed==(mode!="success")&&handler.EventPosts==(mode=="preflight-old"?0:1),"actual client capability boundary: "+mode);
        }
        spool.Acknowledge(batch,receipt with{LinuxKernelTrustVersion=1});Check(spool.Count==0,"explicit new durable acknowledgement releases exact queue prefix");
        File.WriteAllText(Path.Combine(root,"checks.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Event=e,Policy=policy}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Scope="SQLite publication/classification/queue and injected actual client HTTP transport using archived native data plus synthetic policy decision; not a new native or network server run"}));
    }
    private sealed class CapabilityTransport(string mode,BatchReceipt receipt):HttpMessageHandler
    {
        internal int EventPosts;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
        {
            if(request.RequestUri!.AbsolutePath.EndsWith("/events",StringComparison.Ordinal))EventPosts++;
            var version=request.RequestUri.AbsolutePath.EndsWith("/capabilities",StringComparison.Ordinal)?mode=="preflight-old"?0:1:mode=="receipt-old"?0:1;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(receipt with{LinuxKernelTrustVersion=version})});
        }
    }
}
