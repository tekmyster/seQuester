using RansomFree.Contracts;
using RansomFree.Server;
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","trust-governance-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool valid,string label){if(!valid)throw new Exception(label);checks.Add("PASS: "+label);Console.WriteLine(checks[^1]);}
var store=new Store(root);Check(!store.HasTrustStorage()&&store.ReadTrustPolicy().Mode=="legacy","unconfigured installation retains explicit legacy mode");
var endpoint=store.Enroll(new(store.CreateCode().Code,"synthetic","fixture"))!;var group=store.CreateGroup("synthetic","fixture-admin");store.AssignGroup(endpoint.EndpointId,new(group.Id,null),"fixture-admin");
store.InitializeTrustStorage();var now=DateTimeOffset.UtcNow;
var global=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["read"],"informational",now.AddMinutes(-1),now.AddDays(2)){Enabled=true,Executable="/synthetic/reader",Sha256=new string('a',64)};
var initial=store.PublishTrustPolicy(new(0,"enforce",[global],[],"not-used-by-store"),"fixture-admin");
Check(initial.Revision>0&&initial.Mode=="enforce","global policy persisted");
store=new Store(root);Check(store.ReadTrustPolicy().Digest()==initial.Digest(),"reopening preserves exact policy digest");
var assignment=store.TrustAssignment(endpoint.EndpointId);assignment.Validate();Check(assignment.GroupId==group.Id&&assignment.EndpointId==endpoint.EndpointId,"assignment includes authenticated endpoint and current group");
Check(store.RecordTrustReceipt(endpoint.EndpointId,new(1,initial.Revision,initial.Digest(),group.Id,"enforce")),"exact endpoint policy receipt accepted");
Check(!store.RecordTrustReceipt(endpoint.EndpointId,new(1,initial.Revision,"wrong",group.Id,"enforce")),"digest mismatch receipt rejected");
var conflict=false;try{store.PublishTrustPolicy(new(0,"enforce",[],[],"unused"),"fixture-admin");}catch(TrustPolicyConflictException){conflict=true;}Check(conflict,"stale publication cannot replace current policy");
var child=global with{Id=Guid.NewGuid().ToString("N"),Scope="group",ScopeId=group.Id,ParentRuleId=global.Id,Actions=["write"]};
var denied=false;try{store.PublishTrustPolicy(new(initial.Revision,"enforce",[global,child],[],"unused"),"fixture-admin");}catch(ArgumentException){denied=true;}Check(denied&&store.ReadTrustPolicy().Digest()==initial.Digest(),"unapproved broadening rolls back without changing policy");
var approved=store.PublishTrustPolicy(new(initial.Revision,"enforce",[global,child],[child.Id],"unused"),"fixture-admin");
Check(approved.Approvals.Single().RuleHash==TrustPolicy.RuleHash(child),"administrator approval is bound to exact rule content");
var altered=child with{Actions=["read","write"]};denied=false;try{store.PublishTrustPolicy(new(approved.Revision,"enforce",[global,altered],[],"unused"),"fixture-admin");}catch(ArgumentException){denied=true;}Check(denied,"changing approved rule does not inherit stale approval");
var rolledBack=store.PublishTrustPolicy(new(approved.Revision,"enforce",initial.Rules,[],"unused"),"fixture-admin");
Check(rolledBack.Revision>approved.Revision&&rolledBack.Rules.SequenceEqual(initial.Rules),"rollback is a new monotonic audited revision");
Check(store.TrustHistory().Count==3&&store.ManagementAudit().Count(x=>x.Action=="Trust policy published")==3,"all committed policies retained with transactional audit");
Check(!store.RecordTrustReceipt(endpoint.EndpointId,new(1,approved.Revision,approved.Digest(),group.Id,"enforce")),"prior receipt cannot acknowledge rollback revision");
var accountRule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","account",["read"],"informational",now.AddMinutes(-1),now.AddDays(1)){Enabled=true,Authority=endpoint.EndpointId,AccountKind="uid",AccountId="1000"};
var infoPolicy=store.PublishTrustPolicy(new(rolledBack.Revision,"enforce",[accountRule],[],"unused"),"fixture-admin");var evaluated=DateTimeOffset.UtcNow;
var actor=new TrustActor(Authority:endpoint.EndpointId,AccountId:"1000",Verified:true,AccountKind:"uid");
var access=new AgentEvent(Guid.NewGuid().ToString("N"),evaluated,"Read intent","/fixture/canary","synthetic","/fixture/reader",555,"Linux Audit"){Attribution=new(){Provider="Linux Audit",Syscall="read",UserId=1000,CompleteRecordSet=true,EventTimeCredentials=true,Outcome="Success"}};
var context=new TrustContext("server",group.Id,endpoint.EndpointId,"linux",access.Path,["read"],evaluated,actor);
var claim=new EventTrust(1,"linux",group.Id,actor,new(infoPolicy.Revision,infoPolicy.Digest(),"enforce",TrustEvaluation.Evaluate(infoPolicy.Rules,context,evaluated))){EvaluatedUtc=evaluated};
access=access with{Trust=claim};var stored=new StoredEvent(1,endpoint.EndpointId,evaluated,access);
Check(store.TrustSyslogSeverity(stored)==6,"server replays known policy before lowering syslog priority to informational");
Check(store.TrustSyslogSeverity(stored with{Event=access with{Trust=claim with{Result=claim.Result with{Digest=new string('a',64)}}}})==null,"unknown policy digest retains configured syslog severity");
Check(store.TrustSyslogSeverity(stored with{Event=access with{Attribution=access.Attribution! with{CompleteRecordSet=false}}})==null,"incomplete actor evidence retains configured syslog severity");
Check(store.TrustSyslogSeverity(stored with{Event=access with{Attribution=access.Attribution! with{Syscall="unlink"}}})==null,"deletion cannot inherit informational routing");
Check(store.TrustSyslogSeverity(stored with{Event=access with{Trust=claim with{EvaluatedUtc=evaluated.AddHours(1)}}})==null,"future decision cannot lower relay severity");
Check(store.TrustSyslogSeverity(stored with{Event=access with{Trust=claim with{Actor=actor with{Sha256=new string('a',64)}}}})==null,"unreviewed native executable enrichment cannot lower relay severity");
Check(store.TrustEndpointStatuses().Single(x=>x.EndpointId==endpoint.EndpointId).Status=="Pending","new revision invalidates old receipt presentation");
Check(store.RecordTrustReceipt(endpoint.EndpointId,new(1,infoPolicy.Revision,infoPolicy.Digest(),group.Id,"enforce"))&&store.TrustEndpointStatuses().Single(x=>x.EndpointId==endpoint.EndpointId).Status=="Received","exact persisted receipt displays received, not native enforcement");
foreach(var obsolete in new[]{"popup-only","response-only","popup-and-response"})
{
    var rejected=false;try{store.PublishTrustPolicy(new(infoPolicy.Revision,"enforce",[accountRule with{Disposition=obsolete}],[],"unused"),"fixture-admin");}catch(ArgumentException){rejected=true;}
    Check(rejected&&store.ReadTrustPolicy().Digest()==infoPolicy.Digest(),"obsolete suppression publication rejected transactionally: "+obsolete);
}
var receipt=store.Ingest(endpoint.EndpointId,new([access]));
var preserved=new Store(root).Events(0,10).Single().Event;
Check(receipt?.Accepted==1&&System.Text.Json.JsonSerializer.Serialize(preserved)==System.Text.Json.JsonSerializer.Serialize(access),"severity-reduced event retains exact client evidence through durable server ingest and reopen");
var hostRule=accountRule with{Id=Guid.NewGuid().ToString("N"),Scope="host",ScopeId=endpoint.EndpointId,ParentRuleId=accountRule.Id};
var groupRule=accountRule with{Id=Guid.NewGuid().ToString("N"),Scope="group",ScopeId=group.Id,ParentRuleId=accountRule.Id};
var hierarchy=store.PublishTrustPolicy(new(infoPolicy.Revision,"enforce",[accountRule,groupRule,hostRule with{ParentRuleId=groupRule.Id}],[],"unused"),"fixture-admin");
Check(TrustEvaluation.Evaluate(hierarchy.Rules,context,evaluated).Severity=="informational","global/group/host hierarchy persists and selects severity-only account exception");
foreach(var action in TrustEvaluation.Actions)
{
    var r=accountRule with{Actions=[action]};var d=TrustEvaluation.Evaluate([r],context with{Actions=[action]},evaluated);
    Check(!d.SuppressPopup&&!d.SuppressResponse&&d.RetainEvidence&&d.Severity==(action=="delete"?"normal":"informational"),"access-type selection retains evidence and response: "+action);
}
// Exercise the actual shared formatter compiled into the server, not a fixture copy.
var assembly=typeof(Store).Assembly;var alertType=assembly.GetType("RansomFree.Alert")!;var optionsType=assembly.GetType("RansomFree.SyslogOptions")!;var syslogType=assembly.GetType("RansomFree.SyslogClient")!;
var formatMethod=syslogType.GetMethod("Format",System.Reflection.BindingFlags.Static|System.Reflection.BindingFlags.Public)!;
foreach(var (configured,policySeverity,expected) in new (int,int?,int)[]{(7,6,7),(4,6,6),(4,null,4),(4,-1,4),(4,8,4),(4,0,4)})
{
    var alert=System.Text.Json.JsonSerializer.Deserialize(System.Text.Json.JsonSerializer.Serialize(new{Time=access.ObservedUtc.UtcDateTime,access.Operation,access.Path,access.Process,access.User,access.Source,access.EventId,access.ProcessId,access.Attribution,access.Trust,EndpointId=endpoint.EndpointId,EventSequence=1,PolicySyslogSeverity=policySeverity}),alertType)!;
    var opts=System.Text.Json.JsonSerializer.Deserialize(System.Text.Json.JsonSerializer.Serialize(new{Severity=configured,Facility=16,Format="RFC5424"}),optionsType)!;
    var formatted=System.Text.Encoding.UTF8.GetString((byte[])formatMethod.Invoke(null,[alert,opts])!);
    Check(formatted.StartsWith($"<{128+expected}>1 "),$"shared severity floor configured={configured}, policy={policySeverity?.ToString()??"null"}, expected={expected}");
    using var json=System.Text.Json.JsonDocument.Parse(formatted[formatted.IndexOf('{')..]);var payload=json.RootElement;
    Check(payload.GetProperty("EventId").GetString()==access.EventId&&payload.GetProperty("ProcessId").GetInt32()==access.ProcessId&&payload.GetProperty("Path").GetString()==access.Path&&payload.GetProperty("Trust").GetRawText()==System.Text.Json.JsonSerializer.Serialize(access.Trust)&&payload.GetProperty("Attribution").GetRawText()==System.Text.Json.JsonSerializer.Serialize(access.Attribution),"severity formatting retains identity, raw trust and attribution evidence");
}
File.WriteAllLines(Path.Combine(root,"results.txt"),checks);Console.WriteLine(root);Console.WriteLine("Isolated SQLite governance only. SQL Server, UI publication, client enforcement and delivery not inferred.");
