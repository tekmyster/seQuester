using RansomFree.LinuxAgent;

var now=DateTimeOffset.Parse("2026-09-13T23:00:00Z");
var boot=Guid.NewGuid().ToString("N");
var heartbeat=new AuditHeartbeat(now,true,boot,Guid.NewGuid().ToString("N"),200,"12345",1,new(1,now,null));
var verifier=new AuditHeartbeatVerifier();
var waiting=verifier.Evaluate(heartbeat,boot,now);
var ready=verifier.Evaluate(heartbeat with{UpdatedUtc=now.AddSeconds(5),Sequence=2,Health=new(1,now.AddSeconds(5),null)},boot,now.AddSeconds(5));
var count=0;
void Check(bool value){if(!value)throw new Exception("Endpoint summary assertion failed");}
void Test(string name,Action run){run();count++;Console.WriteLine("PASS: "+name);}
string Format(string status)=>EndpointHealthSummary.Format("Canary monitoring configured",true,status);
Test("verified healthy outcome is concise",()=>Check(Format(ready)=="Canary monitoring active | User/process attribution active"));
Test("last verified Audit time is explicit",()=>Check(EndpointHealthSummary.Format("Canary monitoring configured",true,ready,now)=="Canary monitoring active | User/process attribution active | Audit last verified 2026-09-13T23:00:00Z"));
Test("provider diagnostics retained by verifier",()=>Check(ready.Contains("collector and relay verified")&&ready.Contains("per-event completeness varies")));
Test("waiting is not advertised as attribution active",()=>Check(Format(waiting).EndsWith(waiting)&&!Format(waiting).Contains("attribution active")));
foreach(var status in new[]{"Audit disabled","Audit connection not verified","Audit unavailable: Dispatcher executable identity unavailable","Linux Audit degraded: collector stopped or heartbeat stale","Linux Audit degraded: collector heartbeat not advancing","Linux Audit degraded: root collector health report missing or incompatible","Linux Audit degraded: relay disconnected","Audit continuity warning: input drops 1","Future provider ready",""})
{
    Test("non-ready provider preserved: "+status,()=>Check(Format(status)=="Canary monitoring active | "+status&&!Format(status).Contains("attribution active")));
}
foreach(var health in new[]{"No canaries configured","Starting","Management queue failed: IOException","Syslog queue failed: IOException","Policy pending: InvalidDataException","Kernel event queue overflow; evidence may be missing","Canary deleted"})
{
    Test("endpoint warning/state preserved: "+health,()=>Check(EndpointHealthSummary.Format(health,true,ready)==health+" | User/process attribution active"));
}
Test("dead monitor is never shown active",()=>{var value=EndpointHealthSummary.Format("Canary monitoring configured",false,ready);Check(value.Contains("Canary monitoring stopped")&&!value.Contains("Canary monitoring active"));});
Test("dead monitor does not replace existing warning",()=>Check(EndpointHealthSummary.Format("Policy pending",false,"Audit disabled")=="Policy pending | Canary monitoring stopped | Audit disabled"));
Test("near-match provider string is not promoted",()=>Check(!Format(ready+"; degraded").Contains("attribution active")));
Test("actual verifier failure remains visible after readiness",()=>{var failure=verifier.Evaluate(heartbeat with{UpdatedUtc=now.AddSeconds(10),Sequence=3,Health=new(1,now.AddSeconds(10),"relay disconnected")},boot,now.AddSeconds(10));Check(Format(failure).EndsWith("Linux Audit degraded: relay disconnected"));});
Test("structured protection active requires deployed bait, verified inventory, live monitor, normal agent state, and verified Audit",()=>Check(LinuxProtectionStatus.Build(3,3,true,true,"Canary monitoring configured",ready)==new RansomFree.Contracts.EndpointProtectionReport(3,"active")));
Test("zero-item report is explicitly not configured",()=>Check(LinuxProtectionStatus.Build(0,0,true,true,"No canaries configured",ready)==new RansomFree.Contracts.EndpointProtectionReport(0,"not-configured")));
Test("stopped monitor is reported stopped",()=>Check(LinuxProtectionStatus.Build(3,3,true,false,"Canary monitoring configured",ready)==new RansomFree.Contracts.EndpointProtectionReport(3,"stopped")));
Test("missing or altered bait is reported degraded",()=>{Check(LinuxProtectionStatus.Build(2,3,false,true,"Canary monitoring configured",ready)==new RansomFree.Contracts.EndpointProtectionReport(2,"degraded"));Check(LinuxProtectionStatus.Build(0,3,false,true,"Canary monitoring configured",ready)==new RansomFree.Contracts.EndpointProtectionReport(0,"degraded"));});
Test("verified bait summary counts present files without counting missing bait",()=>{var value=LinuxProtectionStatus.Summarize([BaitVerification.Healthy,BaitVerification.Changed,BaitVerification.Missing],now);Check(value==new DeploymentProtectionEvidence(2,true,false,now));});
Test("unreadable bait makes the deployed count unreportable",()=>{var value=LinuxProtectionStatus.Summarize([BaitVerification.Healthy,BaitVerification.Unknown],now);Check(value==new DeploymentProtectionEvidence(1,false,false,now)&&LinuxProtectionStatus.Build(value.Complete?value.DeployedItems:null,2,value.IntegrityHealthy,true,"Canary monitoring configured",ready)==null);});
foreach(var (health,status) in new[]{("Policy pending: InvalidDataException",ready),("Canary monitoring configured","Audit disabled"),("Canary monitoring configured","Audit connection not verified"),("Canary monitoring configured","Linux Audit degraded: relay disconnected")})
    Test("incomplete runtime evidence is degraded: "+health+" / "+status,()=>Check(LinuxProtectionStatus.Build(3,3,true,true,health,status)==new RansomFree.Contracts.EndpointProtectionReport(3,"degraded")));
Test("missing evidence remains unreported",()=>{Check(LinuxProtectionStatus.Build(null,3,true,true,"Canary monitoring configured",ready)==null);Check(LinuxProtectionStatus.Build(3,null,true,true,"Canary monitoring configured",ready)==null);Check(LinuxProtectionStatus.Build(3,3,null,true,"Canary monitoring configured",ready)==null);Check(LinuxProtectionStatus.Build(3,3,true,null,"Canary monitoring configured",ready)==null);Check(LinuxProtectionStatus.Build(3,3,true,true,null,ready)==null);Check(LinuxProtectionStatus.Build(3,3,true,true,"Canary monitoring configured",null)==null);});
Test("near-match Audit text cannot produce active protection",()=>Check(LinuxProtectionStatus.Build(3,3,true,true,"Canary monitoring configured",ready+"; degraded")==new RansomFree.Contracts.EndpointProtectionReport(3,"degraded")));
Test("impossible inventory count is rejected",()=>{foreach(var invalid in new[]{-1,1001}){try{LinuxProtectionStatus.Build(invalid,3,true,true,"Canary monitoring configured",ready);throw new Exception("Invalid inventory count accepted");}catch(ArgumentOutOfRangeException){}}try{LinuxProtectionStatus.Build(4,3,true,true,"Canary monitoring configured",ready);throw new Exception("Deployed count above configured count accepted");}catch(ArgumentOutOfRangeException){}});
Test("heartbeat wire includes the existing optional protection contract",()=>{var request=new RansomFree.Contracts.HeartbeatRequest("fixture","Canary monitoring active"){Protection=LinuxProtectionStatus.Build(3,3,true,true,"Canary monitoring configured",ready)};var json=System.Text.Json.JsonSerializer.Serialize(request);Check(json.Contains("\"Protection\":{\"DeployedCanaryAndHoneypotFiles\":3,\"MonitoringState\":\"active\"}"));});
Console.WriteLine($"PASS: {count} endpoint summary cases. Pure production formatter/verifier checks; no native or UI acceptance inferred.");
