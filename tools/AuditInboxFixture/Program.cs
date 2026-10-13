using System.Linq.Expressions;
using System.Reflection;
using System.Text;
using System.Text.Json;
using RansomFree.Contracts;

if(!OperatingSystem.IsLinux()||args.Length!=1||Environment.GetEnvironmentVariable("SQ_PRIVATE_MOUNT_TEST")!="yes")throw new ArgumentException("Run only inside the isolated mount namespace fixture");
var root=Path.GetFullPath(args[0]);var inbox="/var/lib/sequester-audit";
if(!File.Exists(Path.Combine(inbox,"fixture-marker")))throw new Exception("Private inbox mount missing");
var assembly=Assembly.Load("RansomFree.LinuxAgent");
Type T(string name)=>assembly.GetType("RansomFree.LinuxAgent."+name,true)!;
object New(string name,params object[] values)=>Activator.CreateInstance(T(name),values)!;
var state=New("PrivateState",Path.Combine(root,"state"));
var sensor=New("AuditInbox",state,true);var targets=Array.CreateInstance(T("Canary"),1);
targets.SetValue(New("Canary",Guid.NewGuid().ToString("N"),"/fixture/bait","digest","plan",true,1L,0L),0);
var receiver=new Receiver();var observation=T("Observation");var parameter=Expression.Parameter(observation);
var callback=Expression.Lambda(typeof(Func<,>).MakeGenericType(observation,typeof(bool)),Expression.Call(Expression.Constant(receiver),typeof(Receiver).GetMethod(nameof(Receiver.Record))!,Expression.Convert(parameter,typeof(object))),parameter).Compile();
void Poll()=>T("AuditInbox").GetMethod("Poll")!.Invoke(sensor,[targets,callback]);
object? Get(object row,string field)=>row.GetType().GetProperty(field)!.GetValue(row);
long Cursor()=>JsonDocument.Parse(File.ReadAllText(Path.Combine(root,"state/audit-cursor.json"))).RootElement.GetProperty("Sequence").GetInt64();
var results=new List<string>();void Check(bool test,string name){if(!test)throw new Exception(name);results.Add(name);Console.WriteLine("PASS: "+name);}
void Put(string file,string content){File.WriteAllText(file,content,new UTF8Encoding(false));File.SetUnixFileMode(file,UnixFileMode.UserRead|UnixFileMode.UserWrite);}
var epoch=Guid.NewGuid().ToString("N");long heartbeat=0;
void Status(int count){var now=DateTimeOffset.UtcNow;Put(Path.Combine(inbox,"status.json"),JsonSerializer.Serialize(new{Epoch=epoch,UpdatedUtc=now,LastSequence=count,FirstSequence=1,DroppedInputRecords=0,RejectedRecords=0,RetiredPackets=0,Message="Isolated fixture",Running=true,BootId=File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim(),InstanceId=epoch,DispatcherPid=Environment.ProcessId,DispatcherStartTicks="1",HeartbeatSequence=++heartbeat,CollectorHealth=new{Version=1,CheckedUtc=now,Failure=(string?)null}}));}
string PathFor(int sequence)=>Path.Combine(inbox,sequence.ToString("D20")+".json");
void Packet(int sequence,int? pid,string? executable,EventAttribution? attribution)=>Put(PathFor(sequence),JsonSerializer.Serialize(new{Identity="fixture:"+sequence,ObservedUtc=DateTimeOffset.UtcNow,Pid=pid,Executable=executable,Operation="openat",Attribution=attribution,Paths=new[]{new{Path="/fixture/bait",Role="NORMAL"}}}));
var complete=new EventAttribution{Provider="Linux Audit",Level="Full attribution",Basis="Isolated fixture",UserId=0,EffectiveUserId=0,FileSystemUserId=0,Outcome="Success"};
Packet(1,42,"/usr/bin/cat",complete);Packet(2,43,null,complete);Packet(3,null,null,null);Put(PathFor(4),"{ malformed fixture packet");Put(PathFor(5),JsonSerializer.Serialize(new{Identity="fixture:5",ObservedUtc=DateTimeOffset.UtcNow,Pid=45,Executable="/usr/bin/cat",Operation="openat",Attribution=complete with{CompleteRecordSet=false,PathRole="UNAVAILABLE",Level="Partial attribution"},Paths=Array.Empty<object>()}));Status(5);
receiver.Reject=row=>(int?)Get(row,"Pid")==43;Poll();Check(Cursor()==1,"Cursor stops when durable outbox refuses the next event");
receiver.Reject=row=>(int?)Get(row,"Pid")==45;receiver.Accepted.Clear();Poll();Check(Cursor()==4,"Pathless actor waits for durable outbox acceptance");receiver.Reject=null;Poll();Check(Cursor()==5,"Malformed packet is quarantined and later valid packets continue");
var pathless=receiver.Accepted.Single(row=>(int?)Get(row,"Pid")==45);Check(((EventAttribution)Get(pathless,"Attribution")!).PathRole=="UNAVAILABLE"&&Get(pathless,"Executable") as string=="/usr/bin/cat"&&Get(pathless,"User")!=null,"Pathless actor delivered with original user and process");
var partial=receiver.Accepted.Single(row=>(int?)Get(row,"Pid")==43);Check(((EventAttribution)Get(partial,"Attribution")!).Level=="Partial attribution"&&Get(partial,"Executable") as string=="","Partial executable remains a detection");
var missing=receiver.Accepted.Single(row=>Get(row,"Source") as string=="Linux Audit"&&Get(row,"Pid")==null);Check(Get(missing,"User")==null&&((EventAttribution)Get(missing,"Attribution")!).Level=="Detection only","Missing all actor fields stays explicit and is delivered");
var quarantine=Directory.GetFiles(Path.Combine(root,"state"),"audit-quarantine-*.json").Single();using(var record=JsonDocument.Parse(File.ReadAllText(quarantine)))Check(Encoding.UTF8.GetString(Convert.FromBase64String(record.RootElement.GetProperty("OriginalBase64").GetString()!))=="{ malformed fixture packet","Quarantine retains the exact original bytes");
receiver.Accepted.Clear();sensor=New("AuditInbox",state,true);Poll();Check(receiver.Accepted.Count==0,"Reopened sensor resumes after the persisted cursor without duplicate delivery");
Put(PathFor(6),"{ another malformed packet");Status(6);receiver.Reject=row=>Get(row,"Source") as string=="Linux monitor health";Poll();Check(Cursor()==5,"Quarantine health event also waits for durable outbox acceptance");
for(var i=0;i<1022;i++)Put(Path.Combine(root,"state","audit-quarantine-fill-"+i+".json"),"{}");
receiver.Reject=null;Poll();Check(Cursor()==6,"Already retained quarantine retries successfully at full capacity");
Put(PathFor(7),"{ capacity boundary packet");Packet(8,48,"/usr/bin/cat",complete);Status(8);Poll();Check(Cursor()==6&&File.ReadAllText(PathFor(7))=="{ capacity boundary packet","New malformed input at full capacity retains source and cursor with explicit backpressure");
File.WriteAllText(Path.Combine(root,"result.json"),JsonSerializer.Serialize(new{Passed=results.Count,Cases=results,Scope="Actual AuditInbox, PrivateState and native protected file access in a private mount namespace"}));
Console.WriteLine($"{results.Count} native audit inbox cases passed.");

public sealed class Receiver{
 public List<object> Accepted {get;}=[];public Func<object,bool>? Reject {get;set;}
 public bool Record(object row){if(Reject?.Invoke(row)==true)return false;Accepted.Add(row);return true;}
}
