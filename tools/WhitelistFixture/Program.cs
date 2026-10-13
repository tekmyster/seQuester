using System.Text.Json;
using RansomFree.Contracts;
using RansomFree.Client;
using RansomFree.Server;

if(args.Length==3&&args[0]=="--native-policy-http"){await NativePolicyHttpChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
if(args.Length==2&&args[0]=="--ui-seed"){UiSeed.Run(args[1]);return;}
if(args.Length==3&&args[0]=="--linux-kernel-trust"){await LinuxKernelTrustChecks.Run(Path.GetFullPath(args[1]),Path.GetFullPath(args[2]));return;}
var root=Path.Combine(OperatingSystem.IsWindows()?@"D:\Codex\RansomFree\whitelist-20260924":"/var/tmp/sequester-whitelist-qa","fixture-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var checks=new List<string>();
void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);Console.WriteLine("PASS: "+label);}
void Reject(Action action,string label){var rejected=false;try{action();}catch(Exception e)when(e is ArgumentException or InvalidDataException or InvalidOperationException){rejected=true;}Check(rejected,label);}
var store=new Store(root);store.InitializeTrustStorage();
var endpoint=store.Enroll(new(store.CreateCode().Code,"Whitelist-QA","fixture"))!;
var now=DateTimeOffset.UtcNow;
var rules=new List<TrustRule>();
TrustRule Rule(string os,string subject,string[] actions)=>new(Guid.NewGuid().ToString("N"),"organization","server",subject,actions,"log-only",now.AddMinutes(-1),now.AddDays(1))
{
    Name=os+" "+subject,Enabled=true,OperatingSystem=os,
    Authority=subject=="process"?null:os=="linux"?endpoint.EndpointId:"QA",
    AccountKind=subject=="process"?null:os=="linux"?"uid":"sid",
    AccountId=subject=="process"?null:os=="linux"?"1000":"S-1-5-21-1-2-3-1000",
    Executable=subject=="account"?null:os=="linux"?"/usr/bin/reader":@"C:\Tools\Reader.exe",
    ProcessMatch=subject=="account"?null:"event-path"
};
TrustActor Actor(string os)=>new(os=="linux"?endpoint.EndpointId:"QA",os=="linux"?"1000":"S-1-5-21-1-2-3-1000",os=="linux"?"/usr/bin/reader":@"C:\Tools\Reader.exe",Verified:true,AccountKind:os=="linux"?"uid":"sid");
TrustContext Context(string os,string[] actions)=>new("server",null,endpoint.EndpointId,os,os=="linux"?"/qa/bait":@"C:\QA\bait",actions,now,Actor(os));
foreach(var os in new[]{"windows","linux"})foreach(var subject in new[]{"account","process","account-and-process"})
{
    foreach(var action in TrustEvaluation.Actions.Where(x=>x!="callback"))
    {
        var rule=Rule(os,subject,[action]);var context=Context(os,[action]);var d=TrustEvaluation.Evaluate([rule],context,now);
        Check(d is {LogOnly:true,RetainEvidence:true,Severity:"informational"}&&d.MatchedRules.SequenceEqual([rule.Id]),$"{os} {subject} permits only selected {action}, retaining matched rule");
        Check(!TrustEvaluation.Evaluate([rule],context with{Actions=[action=="read"?"write":"read"]},now).LogOnly,$"{os} {subject} {action} leaves other actions alerting");
    }
    var r=Rule(os,subject,["read","open"]);var c=Context(os,["read","open"]);
    Check(TrustEvaluation.Evaluate([r],c,now).LogOnly,$"{os} {subject} multiple selected rights match");
    Check(!TrustEvaluation.Evaluate([r],c with{Actions=["read","write"]},now).LogOnly,$"{os} {subject} mixed allowed/disallowed event alerts");
    Check(!TrustEvaluation.Evaluate([r],c with{Actor=c.Actor with{Verified=false}},now).LogOnly,$"{os} {subject} unverified identity alerts");
    if(subject!="process")Check(!TrustEvaluation.Evaluate([r],c with{Actor=c.Actor with{AccountId=null}},now).LogOnly,$"{os} {subject} missing account alerts");
    if(subject!="account")Check(!TrustEvaluation.Evaluate([r],c with{Actor=c.Actor with{Executable=null}},now).LogOnly,$"{os} {subject} missing process alerts");
}
var linux=Rule("linux","account-and-process",["read"]);var ctx=Context("linux",["read"]);
Check(!TrustEvaluation.Evaluate([linux],ctx with{Actor=ctx.Actor with{Authority=Guid.NewGuid().ToString("N")}},now).LogOnly,"same UID on another sensor does not match");
Check(!TrustEvaluation.Evaluate([linux],ctx with{Actor=ctx.Actor with{Executable="/usr/bin/Reader"}},now).LogOnly,"Linux path comparison preserves case");
var windows=Rule("windows","account-and-process",["read"]);var wc=Context("windows",["read"]);
Check(TrustEvaluation.Evaluate([windows],wc with{Actor=wc.Actor with{Executable=@"c:\tools\READER.exe"}},now).LogOnly,"Windows path comparison ignores case");
Check(!TrustEvaluation.Evaluate([linux],ctx with{ProtectedEvent=true},now).LogOnly,"health/integrity events always alert");
Check(!TrustEvaluation.Evaluate([linux with{Enabled=false}],ctx,now).LogOnly,"disabled rule does not suppress");
Check(!TrustEvaluation.Evaluate([linux with{ExpiresUtc=now.AddSeconds(-1)}],ctx,now).LogOnly,"expired rule does not suppress");
Check(!TrustEvaluation.Evaluate([linux],ctx with{ObservedUtc=now.AddDays(-2)},now).LogOnly,"new rule does not retroactively suppress older events");
Check(!TrustEvaluation.Evaluate([linux,linux with{Id=Guid.NewGuid().ToString("N"),Disposition="normal"}],ctx,now).LogOnly,"explicit alert rule wins conflict");
Check(!TrustEvaluation.Evaluate([linux,linux with{Id=Guid.NewGuid().ToString("N"),Disposition="informational"}],ctx,now).LogOnly,"informational alert rule does not silently become log only");
Reject(()=>TrustEvaluation.Validate([linux with{Executable="reader"}]),"relative process names rejected");
Reject(()=>TrustEvaluation.Validate([linux with{Executable="/usr/bin/*"}]),"wildcard process paths rejected");
Reject(()=>TrustEvaluation.Validate([linux with{Actions=[]}]),"empty action set rejected");
Reject(()=>TrustEvaluation.Validate([linux with{ProcessMatch=null}]),"hash mode never falls back to path matching");
Reject(()=>TrustEvaluation.Validate([linux with{Sha256=new string('a',64)}]),"path-only rule rejects contradictory hash predicate");
var hashRule=windows with{ProcessMatch=null,Sha256=new string('a',64)};
Check(!TrustEvaluation.Evaluate([hashRule],wc,now).LogOnly,"missing process hash does not match hash rule");
Check(TrustEvaluation.Evaluate([hashRule],wc with{Actor=wc.Actor with{Sha256=new string('a',64)}},now).LogOnly,"matching path and hash allow selected actions");
Check(!TrustEvaluation.Evaluate([hashRule],wc with{Actor=wc.Actor with{Sha256=new string('b',64)}},now).LogOnly,"renamed or replaced binary at the allowed path cannot match a different executable hash");
Check(!TrustEvaluation.Evaluate([hashRule],wc with{Actor=wc.Actor with{Sha256=new string('a',64)},Actions=["write"]},now).LogOnly,"verified executable hash does not grant unselected write rights");
Check(!TrustEvaluation.Evaluate([hashRule,hashRule with{Id=Guid.NewGuid().ToString("N"),Disposition="normal"}],wc with{Actor=wc.Actor with{Sha256=new string('a',64)}},now).LogOnly,"always-alert rule overrides a simultaneously matching verified executable whitelist");
Reject(()=>new TrustPolicy(1,"enforce",[linux],[],"qa",now).Validate(),"new policy semantics cannot be disguised as version 1");
Check(store.Events(0,10).Count==0,"manual server policy creation requires no event to exist");
var policy=store.PublishTrustPolicy(new(0,"enforce",[linux,windows],[],"unused"),"qa");
Check(policy.Version==2&&new Store(root).ReadTrustPolicy().Digest()==policy.Digest(),"version 2 policy persists exactly across reopen");
var events=new List<AgentEvent>();
foreach(var os in new[]{"windows","linux"})
{
    var e=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Content read (copy possible)",os=="linux"?"/qa/bait":@"C:\QA\bait","QA user",Actor(os).Executable,4242,os=="linux"?"Linux Audit":"Windows audit 4663")
    {Attribution=new(){Provider=os=="linux"?"Linux Audit":"Windows Security Audit",Level="Full attribution",Basis="Synthetic native-record replay",Syscall=os=="linux"?"read":null,UserId=os=="linux"?1000u:null,FileSystemUserId=os=="linux"?1000u:null,CompleteRecordSet=true,EventTimeCredentials=true,Outcome="Success"}};
    Directory.CreateDirectory(Path.Combine(root,os));
    var cache=new TrustPolicyCache(Path.Combine(root,os),endpoint.EndpointId,"https://qa.invalid");
    var assignment=store.TrustAssignment(endpoint.EndpointId);cache.Save(assignment,DateTimeOffset.UtcNow);
    var trust=TrustEventEvaluation.Evaluate(cache,endpoint.EndpointId,null,os,e,os=="linux"?TrustEventEvaluation.LinuxActor(endpoint.EndpointId,e):Actor(os),DateTimeOffset.UtcNow);
    e=e with{Trust=trust};events.Add(e);var stored=new StoredEvent(1,endpoint.EndpointId,DateTimeOffset.UtcNow,e);
    Check(trust.IsValid()&&trust.Version==2&&trust.Result.Decision.LogOnly,os+" sensor evaluates a valid log-only event");
    Check(store.ClassifyTrust(stored)==TrustEventClassification.LogOnly,os+" server independently validates log-only decision");
    Check(store.ClassifyTrust(stored with{Event=e with{Process=os=="linux"?"/usr/bin/other":@"C:\Tools\Other.exe"}})==TrustEventClassification.PolicyUnknown,os+" mismatched audited executable never suppresses server alerts");
    Check(store.ClassifyTrust(stored with{Event=e with{Trust=trust with{Result=trust.Result with{Digest=new string('b',64)}}}})==TrustEventClassification.PolicyUnknown,os+" unknown digest never suppresses server alerts");
    Check(!(trust with{Version=1}).IsValid(),os+" log-only claim rejected under historical evidence version");
    var spool=new EventSpool(Path.Combine(root,os+"-spool"),endpoint.EndpointId);spool.Enqueue(e);var batch=spool.Peek();
    Reject(()=>spool.Acknowledge(batch,new(1,0){TrustVersion=1}),os+" old server cannot acknowledge and lose whitelist evidence");
    Check(spool.Status.Pending==1,os+" original event remains durably queued");
    spool.Acknowledge(batch,new(1,0){TrustVersion=1,WhitelistVersion=1});Check(spool.Status.Pending==0,os+" new server acknowledgement drains exact evidence");
    Check(!cache.Evaluate(trust.Context(endpoint.EndpointId,e),DateTimeOffset.UtcNow.AddHours(25)).Decision.LogOnly,os+" expired cached assignment resumes alerting");
}
var accepted=store.Ingest(endpoint.EndpointId,new(events.ToArray()));
Check(accepted?.Accepted==2&&new Store(root).Events(0,10).Count==2,"log-only Windows and Linux events are stored and survive database reopen");
foreach(var e in events)Check(JsonSerializer.Serialize(store.Events(0,10).Single(s=>s.Event.EventId==e.EventId).Event)==JsonSerializer.Serialize(e),"stored log-only evidence preserves user/process/PID/action/policy exactly: "+e.Source);
var la=events.Single(e=>e.Source=="Linux Audit");
Check(TrustEventEvaluation.LinuxActor(endpoint.EndpointId,la with{Attribution=la.Attribution! with{FileSystemUserId=1001}}).AccountId=="1001","Linux whitelist identity uses filesystem UID for actual file access");
Check(!TrustEventEvaluation.LinuxActor(endpoint.EndpointId,la with{Attribution=la.Attribution! with{CompleteRecordSet=false}}).Verified,"incomplete Linux audit evidence remains untrusted");
var ambiguous=events[0] with{Operation="Permissions changed"};
Check(EventTrust.PolicyActions(ambiguous).SequenceEqual(["permissions","ownership"]),"ambiguous Windows access requires both permissions and ownership selections");
// Invoke the actual direct sensor outbox shared with the Windows sensor. Keep its worker disabled.
var assembly=typeof(Store).Assembly;var alertType=assembly.GetType("RansomFree.Alert")!;var optionsType=assembly.GetType("RansomFree.SyslogOptions")!;var outboxType=assembly.GetType("RansomFree.SyslogOutbox")!;
using(var outbox=(IDisposable)Activator.CreateInstance(outboxType,[Path.Combine(root,"direct-syslog"),false])!)
{
    object Alert(AgentEvent e)=>JsonSerializer.Deserialize(JsonSerializer.Serialize(new{Time=e.ObservedUtc.UtcDateTime,e.Operation,e.Path,e.Process,e.User,e.Source,e.EventId,e.ProcessId,e.Trust}),alertType)!;
    var options=JsonSerializer.Deserialize("{\"Enabled\":true,\"Host\":\"127.0.0.1\",\"Port\":1,\"Transport\":\"TCP\"}",optionsType)!;
    var enqueue=outboxType.GetMethod("Enqueue")!;var count=outboxType.GetProperty("Count")!;
    foreach(var e in events)enqueue.Invoke(outbox,[Alert(e),options]);
    Check((int)count.GetValue(outbox)! ==0,"actual shared sensor syslog outbox suppresses log-only events");
    enqueue.Invoke(outbox,[Alert(events[0] with{Trust=null}),options]);
    Check((int)count.GetValue(outbox)! ==1,"actual shared sensor syslog outbox retains normal alerts");
}
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Checks=checks,Policy=policy,Events=events},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS: {checks.Count} whitelist functional and boundary checks; evidence {root}");
