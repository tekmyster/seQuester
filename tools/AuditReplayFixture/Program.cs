using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.LinuxAgent;

if(!OperatingSystem.IsLinux()||args.Length!=1)throw new ArgumentException("Run on Linux in an owned root-private fixture directory.");
var root=Path.GetFullPath(args[0]);if(!root.StartsWith("/root/sequester-audit-replay-fixture-",StringComparison.Ordinal)||!File.Exists(Path.Combine(root,"fixture-marker")))throw new ArgumentException("Exact isolated root-owned fixture marker required.");
var native=Assembly.Load("RansomFree.LinuxAgent").GetType("RansomFree.LinuxAgent.Native",true)!;
var guard=native.GetMethod("ValidateAdminPath",BindingFlags.Public|BindingFlags.Static)!;
void Validate(string p,bool d){try{guard.Invoke(null,[p,d,false]);}catch(TargetInvocationException ex) when(ex.InnerException!=null){System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(ex.InnerException).Throw();}}
Validate(root,true);
var checks=new List<string>();void Check(bool yes,string label){if(!yes)throw new Exception(label);checks.Add(label);}
void Refuse(Action fn,string label){var refused=false;try{fn();}catch(InvalidDataException){refused=true;}catch(IOException){refused=true;}catch(UnauthorizedAccessException){refused=true;}Check(refused,label);}
string Area(string name)=>Path.Combine(root,name);
AuditReplayJournal Open(string name)=>new(Area(name),Validate);
var peer=Guid.NewGuid();var original=new byte[]{10,20,30};var a=new AuditReplayFrame(peer,1,3,original);var b=new AuditReplayFrame(peer,2,3,[40,50]);
Check(AuditReplayFrame.Decode(a.Encode()).Encode().SequenceEqual(a.Encode()),"protocol identity, sequence, counter and bytes round trip");
foreach(var bad in new[]{new AuditReplayFrame(Guid.Empty,1,0,[]),new(peer,0,0,[]),new(peer,1,-1,[]),new(peer,1,0,new byte[8193])})Refuse(()=>bad.Encode(),"invalid frame fields refused");
using(var journal=Open("normal"))
{
 var first=journal.Admit(a);original[0]=99;
 Check(first.Entry is {Order:1,LossDelta:3}&&!first.Duplicate&&journal.Pending()[0].Frame.Bytes[0]==10,"durable admission owns bytes independently of caller buffer");
 a=a with{Bytes=[10,20,30]};journal.Admit(b);
 Check(journal.Pending().Select(x=>x.Order).SequenceEqual(new long[]{1,2}),"raw input retains admission order");
 Check(journal.Admit(a).Duplicate&&journal.Admit(b).Duplicate&&journal.Pending().Length==2,"lost acknowledgement replay does not duplicate raw admission");
 Refuse(()=>journal.Admit(b with{Bytes=[99]}),"changed duplicate bytes refused");
 Refuse(()=>journal.Admit(b with{Sequence=4}),"sequence gap refused without dropping pending input");
 Refuse(()=>journal.Admit(b with{Sequence=3,LossTotal=2}),"decreasing counter refused");
 Refuse(()=>Open("normal").Dispose(),"second collector cannot own same replay journal");
}
using(var journal=Open("normal"))
{
 Check(journal.Pending().Select(x=>x.LossDelta).SequenceEqual(new long[]{3,0}),"reopening retains exact loss deltas without recounting cumulative totals");
 Check(journal.Admit(b).Duplicate,"same relay replay recognized after collector restart");
 journal.RetireThrough(1);Check(journal.Pending().Length==1&&journal.Pending()[0].Order==2,"retirement preserves unconsumed suffix");
 Refuse(()=>journal.RetireThrough(3),"future parser cursor cannot retire unseen input");
}
using(var journal=Open("normal"))
{
 Check(journal.Pending().Length==1&&journal.Pending()[0].Order==2,"partial retirement persists across restart");
 journal.RetireThrough(2);Check(journal.Admit(b).Duplicate&&journal.Pending().Length==0,"retired last frame remains duplicate-safe after lost acknowledgement");
 Check(journal.Admit(new(peer,3,5,[60])).Entry?.LossDelta==2,"only new losses counted after reconnect");
 Check(journal.Admit(new(Guid.NewGuid(),1,1,[70])).Entry?.LossDelta==1,"new relay instance gets independent counter even with recycled OS PID");
}
byte[] earlier;
using(var journal=Open("interrupted-admission")){journal.Admit(new(peer,1,0,[1]));earlier=File.ReadAllBytes(Path.Combine(Area("interrupted-admission"),"checkpoint.json"));journal.Admit(new(peer,2,4,[2]));}
File.WriteAllBytes(Path.Combine(Area("interrupted-admission"),"checkpoint.json"),earlier);
using(var journal=Open("interrupted-admission")){Check(journal.Pending().Length==2&&journal.Pending()[1].LossDelta==4&&journal.Admit(new(peer,2,4,[2])).Duplicate,"raw-before-checkpoint interruption recovered before duplicate acknowledgement");}
using(var journal=Open("missing")){journal.Admit(new(peer,1,0,[1]));}
File.Delete(Directory.GetFiles(Area("missing"),"*.frame").Single());Refuse(()=>Open("missing").Dispose(),"missing acknowledged raw record fails visibly");
using(var journal=Open("corrupt")){journal.Admit(new(peer,1,0,[1]));}
var damaged=Directory.GetFiles(Area("corrupt"),"*.frame").Single();var damagedBytes=File.ReadAllBytes(damaged);damagedBytes[^1]^=1;File.WriteAllBytes(damaged,damagedBytes);
Refuse(()=>Open("corrupt").Dispose(),"corrupt retained bytes fail integrity validation");Check(File.ReadAllBytes(damaged).SequenceEqual(damagedBytes),"corrupt input retained byte for byte for diagnosis");
using(var journal=Open("full"))
{
 for(var i=1;i<=4096;i++)journal.Admit(new(peer,i,0,[(byte)i]));
 Refuse(()=>journal.Admit(new(peer,4097,0,[0])),"full storage refuses admission without overwriting prior evidence");
 Check(journal.Pending().Length==4096,"all bounded entries retained at capacity");journal.RetireThrough(4096);
 Check(journal.Admit(new(peer,4097,0,[0])).Entry?.Order==4097,"capacity available only after explicit parser retirement");
}
var broad=Area("broad-permissions");Directory.CreateDirectory(broad);File.SetUnixFileMode(broad,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute|UnixFileMode.GroupRead);
Refuse(()=>Open("broad-permissions").Dispose(),"group-readable raw evidence store refused");
var result=new{Passed=true,Checks=checks.Count,Cases=checks,Scope="Actual Linux file flush, directory fsync, protected ownership checks, bounded replay journal and framing. No live audit subscription, service restart, socket acknowledgement integration or end-to-end sensor acceptance."};
File.WriteAllText(Path.Combine(root,"result.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
