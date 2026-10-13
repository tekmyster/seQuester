using RansomFree.LinuxAgent;

var now=DateTimeOffset.Parse("2026-09-13T12:00:00Z");
var boot=Guid.NewGuid().ToString("N");
var original=new AuditHeartbeat(now,true,boot,Guid.NewGuid().ToString("N"),200,"12345",1,new(1,now,null));
var count=0;
void Check(bool value){if(!value)throw new Exception("Health fixture assertion failed");}
void Test(string name,Action action){action();Console.WriteLine("PASS: "+name);count++;}
string Evaluate(AuditHeartbeat value)=>new AuditHeartbeatVerifier().Evaluate(value,boot,now);
void Reject(AuditHeartbeat value)=>Check(Evaluate(value).StartsWith("Linux Audit degraded:"));
AuditHeartbeat At(int seconds,long sequence)=>original with{UpdatedUtc=now.AddSeconds(seconds),Sequence=sequence,Health=new(1,now.AddSeconds(seconds),null)};
Test("first trusted heartbeat awaits advancement",()=>Check(Evaluate(original).Contains("awaiting heartbeat advancement")));
Test("advancing trusted heartbeat enables attribution status",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);Check(v.Evaluate(At(5,2),boot,now.AddSeconds(5)).Contains("user/process attribution enabled"));});
Test("normal repeated poll retains established ready status",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);v.Evaluate(At(5,2),boot,now.AddSeconds(5));Check(v.Evaluate(At(5,2),boot,now.AddSeconds(10)).Contains("user/process attribution enabled"));});
Test("stopped collector",()=>Reject(original with{Running=false}));
Test("stale heartbeat",()=>Reject(At(-21,1)));
Test("future heartbeat",()=>Reject(At(6,1)));
Test("previous boot",()=>Reject(original with{BootId="other-boot"}));
Test("invalid instance",()=>Reject(original with{InstanceId="invalid"}));
Test("invalid process identity",()=>{Reject(original with{Pid=1});Reject(original with{Pid=-1});});
Test("invalid process start",()=>{Reject(original with{StartTicks="0"});Reject(original with{StartTicks="unknown"});});
Test("invalid heartbeat sequence",()=>Reject(original with{Sequence=0}));
Test("legacy collector not silently healthy",()=>Reject(original with{Health=null}));
Test("unknown report version",()=>Reject(original with{Health=new(2,now,null)}));
Test("report cannot refer to earlier snapshot",()=>Reject(original with{Health=new(1,now.AddSeconds(-1),null)}));
Test("root collector failure propagated",()=>Check(Evaluate(original with{Health=new(1,now,"Rule reconciliation missing")}).Contains("degraded: Rule reconciliation missing")));
Test("sequence regression rejected",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(At(0,4),boot,now);Check(v.Evaluate(At(5,3),boot,now.AddSeconds(5)).Contains("regressed"));});
Test("new sequence without time advance rejected",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);Check(v.Evaluate(original with{Sequence=2},boot,now.AddSeconds(5)).Contains("time did not advance"));});
Test("unchanged sequence with refreshed timestamps not healthy forever",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);Check(v.Evaluate(At(21,1),boot,now.AddSeconds(21)).Contains("not advancing"));});
Test("restart requires new advancement",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);v.Evaluate(At(5,2),boot,now.AddSeconds(5));Check(v.Evaluate(At(10,1) with{InstanceId=Guid.NewGuid().ToString("N")},boot,now.AddSeconds(10)).Contains("awaiting heartbeat advancement"));});
Test("new PID or start identity requires advancement",()=>{foreach(var next in new[]{At(5,1) with{Pid=201},At(5,1) with{StartTicks="23456"}}){var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);Check(v.Evaluate(next,boot,now.AddSeconds(5)).Contains("awaiting heartbeat advancement"));}});
Test("failure is not overridden by prior healthy heartbeat",()=>{var v=new AuditHeartbeatVerifier();v.Evaluate(original,boot,now);v.Evaluate(At(5,2),boot,now.AddSeconds(5));Check(v.Evaluate(At(10,3) with{Health=new(1,now.AddSeconds(10),"relay disconnected")},boot,now.AddSeconds(10)).Contains("degraded: relay disconnected"));});
Test("initial zero loss report is not a gap",()=>Check(AuditLossCounter.Delta(0,0)==0));
Test("unchanged cumulative loss report is not another gap",()=>Check(AuditLossCounter.Delta(4,4)==0));
Test("only newly reported loss is counted",()=>{Check(AuditLossCounter.Delta(7,4)==3);Check(AuditLossCounter.Delta(long.MaxValue,0)==long.MaxValue);});
Test("negative or regressing loss counter refused",()=>{foreach(var pair in new[]{(-1L,0L),(0L,-1L),(3L,4L)}){try{AuditLossCounter.Delta(pair.Item1,pair.Item2);}catch(InvalidDataException){continue;}throw new Exception("Invalid loss counter accepted");}});
Console.WriteLine($"PASS: {count} production heartbeat/loss-counter cases. Pure state-machine checks only; no native collector, permissions, fleet or UI acceptance claim.");
