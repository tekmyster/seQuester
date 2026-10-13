using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree;
using RansomFree.Contracts;
using RansomFree.Server;

if(args is ["--owned-child"]){await Task.Delay(TimeSpan.FromMinutes(2));return;}
if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
var root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-response-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
var checks=new List<string>();void Check(bool result,string name){if(!result)throw new InvalidDataException(name);checks.Add(name);Console.WriteLine("PASS: "+name);}
var sensor=Guid.NewGuid().ToString("N");var id=Guid.NewGuid().ToString("N");var now=DateTimeOffset.UtcNow;
var target=new ActiveResponseTarget(sensor,id,"windows",new(sensor,900,"133000000000000000","windows:fixture"),new string('A',64),@"C:\QA\actor.exe",@"C:\QA\target.txt",null,"effective-user");
var policy=new AssignedPolicy(Guid.NewGuid().ToString("N"),1,MonitoringPolicy.Default with{ActiveResponse=new(){Mode="manual",Actions=["end-process"],MaximumActionsPerMinute=1}});
var command=new ResponseCommand(Guid.NewGuid().ToString("N"),id,"end-process","fixture","owned fixture",now,now.AddMinutes(1)){Target=target,PolicyRevision=policy.Revision,PolicyDigest=ResponseCommandPolicy.Digest(policy)};
var state=new AgentConsoleState();var journal=new ResponseJournal(root);
var rejected=journal.Execute(command,state,policy:policy with{Revision=2},sensor:sensor);
Check(rejected.Outcome=="Rejected","revoked policy is rejected before an execution intent");
Check(new ResponseJournal(root).Execute(command,state,policy:policy,sensor:sensor)==rejected,"rejection survives restart and cannot become execution on retry");
try{journal.Execute(command with{Reason="changed"},state,policy:policy,sensor:sensor);throw new Exception("Changed request accepted");}catch(InvalidDataException){Check(true,"same response ID cannot change command contents");}
var notApproved=journal.Execute(command with{Id=Guid.NewGuid().ToString("N")},state,policy:policy,sensor:sensor);
Check(notApproved.Outcome=="Rejected"&&notApproved.Message.Contains("locally"),"server policy alone cannot bypass local process-stop approval");
File.WriteAllText(Path.Combine(root,"response-permissions.json"),"{\"AllowRemoteProcessStop\":true}");
var missing=journal.Execute(command with{Id=Guid.NewGuid().ToString("N")},state,policy:policy,sensor:sensor);
Check(missing.Outcome=="Failed","missing native operation evidence fails without stopping a process");
var limited=new ResponseJournal(root).Execute(command with{Id=Guid.NewGuid().ToString("N")},state,policy:policy,sensor:sensor);
Check(limited.Outcome=="Rejected"&&limited.Message.Contains("rate limit"),"native action rate limit survives journal restart");
var pendingId=Guid.NewGuid().ToString("N");var pending=command with{Id=pendingId};var digest=Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(pending)));
var pendingRoot=Path.Combine(root,"indeterminate");Directory.CreateDirectory(pendingRoot);
File.WriteAllText(Path.Combine(pendingRoot,"response-journal.json"),JsonSerializer.Serialize(new Dictionary<string,object>{[pendingId]=new{Digest=digest,Receipt=new ResponseReceipt(pendingId,"Indeterminate","Recorded before crash"),Acknowledged=false,RecordedUtc=now}}));
Check(new ResponseJournal(pendingRoot).Execute(pending,state,policy:policy,sensor:sensor).Outcome=="Indeterminate","crash after intent is not blindly retried");

// Actual Windows process-handle checks against a child created by this fixture.
// The synthetic legacy event exercises journal integration, not native file capture.
var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false};
if(Path.GetFileNameWithoutExtension(Environment.ProcessPath!).Equals("dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(System.Reflection.Assembly.GetExecutingAssembly().Location);
start.ArgumentList.Add("--owned-child");using var child=Process.Start(start)!;
try
{
    var identity=ProcessControls.Capture(child.Id,Environment.ProcessPath!,DateTime.UtcNow);
    Check(identity is {TrustVerified:true},"owned child identity is read from a live Windows process handle");
    try{ProcessControls.End(identity! with{CreatedUtcFileTime=identity!.CreatedUtcFileTime-1});throw new Exception("Wrong birth accepted");}catch(InvalidOperationException){Check(!child.HasExited,"PID-reuse guard rejects a different creation time without terminating the child");}
    try{ProcessControls.End(identity! with{Hash=new string('B',64)});throw new Exception("Wrong hash accepted");}catch(InvalidOperationException){Check(!child.HasExited,"changed actor hash does not terminate the child");}
    var legacyId=Guid.NewGuid().ToString("N");state.Record(new Alert(DateTime.Now,"Fixture read",Path.Combine(root,"owned-canary.txt"),identity!.Executable,"fixture","Windows audit 4663"){EventId=legacyId,ProcessId=child.Id,Identity=identity});
    var legacy=new ResponseCommand(Guid.NewGuid().ToString("N"),legacyId,"end-process","fixture","owned child",DateTimeOffset.UtcNow,DateTimeOffset.UtcNow.AddMinutes(1));
    var result=journal.Execute(legacy,state);
    Check(result.Outcome=="Succeeded"&&child.WaitForExit(5000),"legacy adapter confirms termination of the exact owned child");
    Check(new ResponseJournal(root).Execute(legacy,state)==result,"lost receipt replay returns durable success without another termination");
}
finally{if(!child.HasExited)child.Kill();}

var store=new Store(Path.Combine(root,"server"));var enrolled=store.Enroll(new(store.CreateCode().Code,"response isolated fixture","fixture"))!;
Check(store.RecordResponseCapabilities(enrolled.EndpointId,new(1,"windows",1)),"enrolled sensor can report the native process adapter");
Check(store.RecordResponseCapabilities(enrolled.EndpointId,new(1,"windows",0)),"sensor can withdraw its adapter capability");
Check(!store.RecordResponseCapabilities(Guid.NewGuid().ToString("N"),new(1,"windows",1)),"unknown sensor cannot add response authority");
Check(!new NativeResponseCapabilities(1,"linux",1).IsValid(),"unimplemented Linux native adapter cannot advertise Windows support");
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Root=root,Scope="Durable journal/policy gates, actual owned Windows process termination, SQLite capability storage. Native file-event-to-response execution and deployment are separate qualification."}));
