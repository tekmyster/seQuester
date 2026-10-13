using System.Text.Json;
using RansomFree.Contracts;
var root=Path.Combine("D:\\Codex\\RansomFree\\tests","activity-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var results=new List<string>();void Check(bool value,string label){if(!value)throw new Exception(label);results.Add("PASS: "+label);Console.WriteLine(results[^1]);}
AgentEvent Event(string source,string operation)=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,operation,"/synthetic","user","/synthetic/process",123,source);
foreach(var pair in new[]{("openat","open"),("pread64","read"),("writev","write"),("renameat2","rename"),("unlinkat","delete"),("ftruncate","truncate"),("fchmodat","permissions"),("fchownat","ownership"),("creat","create-or-truncate"),("copy_file_range","transfer"),("statx","query"),("mmap","unknown")})
{
    var e=Event("Linux Audit","raw evidence") with{Attribution=new(){Provider="Linux Audit",Syscall="c000003e:"+pair.Item1,Outcome="Success"}};
    var before=JsonSerializer.Serialize(e);var result=EventActivity.From(e);
    Check(result.Actions.SequenceEqual([pair.Item2])&&JsonSerializer.Serialize(e)==before,"conservative syscall projection preserves raw event: "+pair.Item1);
    Check(result.Actions.All(x=>x is not ("copy" or "encryption")),"no inferred copy/encryption: "+pair.Item1);
}
var denied=EventActivity.From(Event("Linux Audit","raw") with{Attribution=new(){Provider="Linux Audit",Syscall="x:openat",Outcome="Failed"}});
Check(denied.Outcome=="failed"&&denied.Evidence=="intent","failed attempt not successful access");
Check(EventActivity.From(Event("macOS FSEvents","File opened")).Actions[0]=="unknown","FSEvents cannot establish open");
Check(EventActivity.From(Event("Linux fanotify","Canary metadata changed")).Actions[0]=="unknown","unconfigured fanotify event not claimed");
Check(EventActivity.From(Event("Unknown provider","Content read (copy possible)")).Actions[0]=="unknown","unreviewed provider fails to unknown");
Check(EventActivity.From(Event("Windows audit 4663","Content read (copy possible), Content written")).Actions.SequenceEqual(["read","write"]),"multiple Windows access rights retained");
Check(EventActivity.From(Event("Windows audit 4663","Permissions changed")).Actions[0]=="permissions-or-ownership","legacy ownership ambiguity retained");
Check(EventActivity.From(Event("Linux inotify","Canary modified (encryption possible)")).Actions[0]=="write","modification not labeled encryption");
Check(LocalActorEvidence.IsComplete(Event("Windows audit 4663","Content read (copy possible)")),"Windows local event accepts complete user, process and PID");
Check(LocalActorEvidence.IsComplete(Event("Linux Audit","Audit openat (Success)")),"Linux local event accepts complete user, process and PID");
foreach(var rule in KernelActivityRules.All)
{
    var original=Event(rule.Provider,rule.Operation) with{Attribution=new(){Provider=rule.Provider,Outcome="Failed"}};
    var serialized=JsonSerializer.Serialize(original);var projected=EventActivity.From(original);
    Check(projected.Actions.SequenceEqual([rule.Action])&&projected.Evidence==rule.Evidence&&projected.Outcome==(rule.Evidence=="intent"?"unknown":"failed")&&serialized==JsonSerializer.Serialize(original),"kernel intent/permission/completion semantics preserve raw evidence: "+rule.Operation);
    Check(EventActivity.From(original with{Attribution=original.Attribution with{Provider="Wrong provider"}}).Actions[0]=="unknown","kernel provider mismatch is not proof: "+rule.Operation);
}
foreach(var source in new[]{"Windows audit 4663","File watcher","Integrity check","Linux Audit","Linux fanotify","Linux inotify","Linux periodic metadata","Windows minifilter prototype","Linux eBPF prototype"})
{
    Check(!LocalActorEvidence.IsComplete(Event(source,"synthetic") with{User=null}),source+" rejects missing user");
    Check(!LocalActorEvidence.IsComplete(Event(source,"synthetic") with{Process="Unavailable"}),source+" rejects missing process");
    Check(!LocalActorEvidence.IsComplete(Event(source,"synthetic") with{ProcessId=null}),source+" rejects missing PID");
    Check(!LocalActorEvidence.IsComplete(Event(source,"synthetic") with{User="unknown"}),source+" rejects placeholder user");
    Check(!LocalActorEvidence.IsComplete(Event(source,"synthetic") with{Process="PID 123"}),source+" rejects PID-only process label");
}
Check(LocalActorEvidence.IsComplete(Event("Linux monitor health","collector status") with{User=null,Process=null,ProcessId=null}),"operational health event does not invent actor attribution");
var old=new AgentConsoleEvent(Guid.NewGuid().ToString("N"),DateTime.UtcNow,"Read","/synthetic","tool","user","fixture",false,false);
Check(JsonSerializer.Deserialize<AgentConsoleEvent>(JsonSerializer.Serialize(old))!.ProcessId==null,"legacy IPC has unknown PID, not fabricated zero");
Check(JsonSerializer.Deserialize<AgentConsoleEvent>(JsonSerializer.Serialize(old with{ProcessId=123}))!.ProcessId==123,"additive IPC PID round-trip");
Check(SensorCapabilities.Inventory.Single(x=>x.Provider=="macOS Endpoint Security").Signals.Length==0,"unavailable native adapter does not advertise working events");
TrustChecks.Run(Check);
var orderTime=DateTimeOffset.UtcNow;
var orderRows=new[]{new LocalHistoryKey("a",orderTime,"Read","/a",null,"process",null),new("b",orderTime,"Read","/b","user2","process",2),new("c",orderTime,"Read","/c","user10","process",10)};
foreach(var field in LocalHistoryOrder.Fields)foreach(var desc in new[]{false,true})
{
    var ordered=orderRows.OrderBy(x=>x,Comparer<LocalHistoryKey>.Create((a,b)=>LocalHistoryOrder.Compare(a,b,field,desc))).ToArray();
    Check(ordered.Length==3&&ordered.Select(x=>x.Id).Distinct().Count()==3,"local history stable ordering: "+field+" "+desc);
    if(field is "pid" or "user")Check(ordered[^1].Id=="a","local unknown remains last: "+field+" "+desc);
    if(field=="pid")Check(ordered[0].Pid==(desc?10:2),"local PID numeric ordering");
}
Check(LocalHistoryOrder.Compare(orderRows[0],orderRows[0] with{Id="z"},"time",true)<0,"local identity tie-break independent of direction");
Check(DecoyDeploymentCatalog.Types.Count==19&&DecoyDeploymentCatalog.Types.Select(x=>x.Id).Distinct().Count()==19,"nineteen separately identified virtual/non-file catalog entries");
foreach(var type in DecoyDeploymentCatalog.Types)
{
    var request=new DecoyDeploymentRequest(Guid.NewGuid().ToString("N"),type.Id,type.Platforms[0],"/synthetic-only","Test only");
    Check(DecoyDeploymentPlanner.Preview(request).State=="Disabled","default-off decoy type "+type.Id);
    Check(!DecoyDeploymentPlanner.Preview(request with{Enabled=true}).CanDeploy,"missing provider cannot claim deployment "+type.Id);
}
var invalidType=false;try{DecoyDeploymentPlanner.Preview(new(Guid.NewGuid().ToString("N"),"unknown","linux","/synthetic","Test"));}catch(ArgumentException){invalidType=true;}Check(invalidType,"unknown decoy type rejected");
File.WriteAllLines(Path.Combine(root,"results.txt"),results);Console.WriteLine(root);Console.WriteLine("Pure contract checks only; no native sensor, deployment, response or external delivery acceptance.");
