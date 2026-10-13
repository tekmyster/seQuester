using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned SYSTEM guest and new output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var parent=Path.GetDirectoryName(root)!;var target=Path.Combine(root,"race-impersonated-read.bin");File.WriteAllBytes(target,new byte[8192]);
var liveActor=File.Exists(Path.Combine(parent,"live-actor-stop.enabled"));
var reports=Path.Combine(root,"reports");Directory.CreateDirectory(reports);var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);
var localService=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var d=new DirectoryInfo(path);var a=d.GetAccessControl();a.AddAccessRule(new FileSystemAccessRule(localService,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));d.SetAccessControl(a);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var actorBytes=File.ReadAllBytes(actorPath);var actorHash=Convert.ToHexString(SHA256.HashData(actorBytes));
var sensor=Guid.NewGuid().ToString("N");var checks=new List<string>();var cases=new List<object>();var phases=new List<object>();
void Check(bool value,string label){if(!value)throw new IOException(label);checks.Add(label);}
void Phase(string phase,string eventId){phases.Add(new{Order=phases.Count+1,Phase=phase,EventId=eventId,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp()});}
string? error=null;bool passed=false;object? resources=null;var background=0;int pid=0;long created=0;
using var creator=Process.GetCurrentProcess();var creatorPid=creator.Id;var creatorCreated=creator.StartTime.ToUniversalTime().ToFileTimeUtc();uint creatorTid=0;Process? ownedChild=null;Task<string>? childErrors=null;
try
{
 Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
 using(port)
 {
  byte[] Send(byte[] request,int length){var output=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,(uint)request.Length,output,(uint)length,out var n));if(n!=length)throw new IOException("Reply size differs");return output;}
  byte[] Get(uint command,int length)=>Send(WindowsStagedActorProtocol.Message(command),length);
  void Reject(byte[] request,int length,string label)=>Check(Native.FilterSendMessage(port,request,(uint)request.Length,new byte[length],(uint)length,out _) < 0,label);
  void Drain()
  {
   foreach(var (command,length,name) in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
   {
    using var file=new FileStream(Path.Combine(capture,name+".journal"),FileMode.Append,FileAccess.Write,FileShare.Read);
    for(var i=0;i<1024;i++){var bytes=new byte[length];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,bytes,(uint)length,out var n);if(IsEmpty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(n==length,"diagnostic record size");file.Write(bytes);}
   }
  }
  void Ack(byte[] raw){var ack=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(ack,0);}
  async Task WaitFor(Func<bool> ready,string label){var watch=Stopwatch.StartNew();while(!ready()){if(watch.Elapsed>TimeSpan.FromSeconds(3))throw new TimeoutException(label);await Task.Delay(10);}}
  Get(6,0);var binding=Get(20,88);var provider=Convert.ToHexString(binding.AsSpan(8,16));
  var device=new StringBuilder(32768);Check(Native.QueryDosDevice(target[..2],device,device.Capacity)>0,"target device resolved");
  var scope=WindowsStagedActorProtocol.Message(5,1548);WindowsStagedActorProtocol.Put32(scope,8,1);Encoding.Unicode.GetBytes(device+target[2..]).CopyTo(scope,12);Send(scope,0);
  var report=Path.Combine(reports,"impersonated-read.json");var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden};
  foreach(var a in new[]{"impersonated-read",target,report})start.ArgumentList.Add(a);start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";start.RedirectStandardError=true;
  if(liveActor)start.Environment["SQ_FIXTURE_WAIT_FOR_RELEASE"]="1";else start.ArgumentList.Add("--exit-immediately");
  creatorTid=Native.GetCurrentThreadId();ownedChild=Process.Start(start)??throw new IOException("Owned actor launch failed");var owned=ownedChild.Handle;pid=ownedChild.Id;created=ownedChild.StartTime.ToUniversalTime().ToFileTimeUtc();childErrors=ownedChild.StandardError.ReadToEndAsync();
  if(liveActor){var ready=Stopwatch.StartNew();while(!File.Exists(report+".held")&&!ownedChild.HasExited){if(ready.ElapsedMilliseconds>15000)throw new TimeoutException("Live actor did not report within startup deadline");await Task.Delay(50);}Check(File.Exists(report+".held")&&!ownedChild.HasExited,"live actor remains running after file operation");}
  else Check(ownedChild.WaitForExit(15000)&&ownedChild.ExitCode==0,"immediate-exit actor finished within deadline");
  using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
  Check(t.GetProperty("ProcessId").GetInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created&&t.GetProperty("WaitForRelease").GetBoolean()==liveActor&&t.GetProperty("PostOperationDelayMs").GetInt32()==(liveActor?750:0),"actor ground truth identity and declared lifetime mode");
  for(var index=0;index<100;index++)
  {
   var raw=new byte[3800];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(2),8,raw,3800,out var n);if(IsEmpty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(n==3800,"raw operation size");
   var e=WindowsKernelDecoder.Decode(raw,sensor,p=>p,false);var k=e.Attribution!.WindowsKernel!;
   // Preserve every operation before changing its queue ownership.
   using(var f=new FileStream(Path.Combine(capture,e.EventId+".record"),FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough)){f.Write(raw);f.Flush(true);}
   File.AppendAllText(Path.Combine(capture,"events.jsonl"),JsonSerializer.Serialize(e)+"\n");
   if(e.ProcessId!=pid||k.ProcessCreatedFileTime!=created){background++;Ack(raw);Drain();continue;}
   Check(k.Major is 0 or 3&&cases.Count<2,"expected actor CREATE/read sequence only");
   Check(k.ThreadId==t.GetProperty("ThreadId").GetUInt32()&&TokenMatches(k.RequestorPrimary,t.GetProperty("Primary"))&&TokenMatches(k.ThreadEffective,t.GetProperty("Effective")),"actual request thread and owner match ground truth");
   var a=WindowsStagedActorProtocol.Companion(Send(WindowsStagedActorProtocol.CompanionRequest(e,provider),88),e,provider);
   Check(a.BindingKind=="bytes-pinned","exact operation retains executable pin");
   var creationRequest=WindowsStagedActorProtocol.OperationRequest(a,27);var creationRaw=Send(creationRequest,WindowsProcessCreationProtocol.ReplyBytes);
   var creationRecord=WindowsProcessCreationProtocol.Query(creationRequest,a,(_,_)=>creationRaw);
   var process=WindowsProcessCreationProtocol.Apply(creationRecord,a,new(),sensor);
   Check(process.Creation is {Status.State:"captured",CreatorStatus.State:"captured"} pm&&pm.CreatorPid==(ulong)creatorPid&&pm.CreatorTid==creatorTid&&pm.CreatorCreatedFileTime==creatorCreated&&process.ParentPid==creatorPid&&process.ParentStartKey==creatorCreated.ToString()&&process.CommandLine==t.GetProperty("CommandLine").GetString(),"creation metadata matches held creator and native actor command before race");
   File.WriteAllBytes(Path.Combine(capture,e.EventId+".creation"),creationRaw);
   var metadata=Send(WindowsStagedActorProtocol.OperationRequest(a,13),144);var total=WindowsStagedActorProtocol.U32(metadata,8);
   WindowsStagedActorProtocol.CheckReply(metadata,a,total,0,0);Check(total==actorBytes.Length,"actor file length matches bound bytes");
   foreach(var (offset,length,label) in new[]{(total,1u,"read beyond EOF"),(total+1,0u,"offset beyond EOF"),(uint.MaxValue,2u,"offset arithmetic overflow"),(0u,65537u,"oversized chunk")})
    Reject(WindowsStagedActorProtocol.OperationRequest(a,10,offset,length),checked(144+(int)length),label+" rejected");
   var eof=Send(WindowsStagedActorProtocol.OperationRequest(a,10,total,0),144);WindowsStagedActorProtocol.CheckReply(eof,a,total,total,0,metadata);Check(true,"zero-length EOF read accepted");
   var offsetForRace=total>65536?total-65536:0;var count=Math.Min(total,65536u);var request=WindowsStagedActorProtocol.OperationRequest(a,10,offsetForRace,count);
   Task<byte[]>? publication=null;Task<byte[]>? stopTask=null;var kind=cases.Count==0?"ACK":"STOP";
   Get(16,0);
   try
   {
    publication=Task.Factory.StartNew(()=>Send(request,checked(144+(int)count)),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    await WaitFor(()=>WindowsStagedActorProtocol.U32(Get(12,224),216)==1,"publication pause not entered");
    var held=Get(12,224);Check(WindowsStagedActorProtocol.U32(held,208)==1&&!publication.IsCompleted,"transfer holds publication rundown before race");Phase("publication-paused",e.EventId);
    if(liveActor)Check(!ownedChild.HasExited,"actor is alive at ownership race");
    if(kind=="ACK")
    {
     Check(k.Major==0,"ACK race uses actor CREATE");Ack(raw);Phase("operation-acknowledged",e.EventId);
     Reject(WindowsStagedActorProtocol.OperationRequest(a,13),144,"new retrieval rejected after concurrent ACK");
     Reject(creationRequest,WindowsProcessCreationProtocol.ReplyBytes,"metadata retrieval rejected after concurrent ACK");
    }
    else
    {
     Check(k.Major==3,"STOP race uses actor READ");
     stopTask=Task.Factory.StartNew(()=>Get(9,0),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
     await WaitFor(()=>WindowsStagedActorProtocol.U32(Get(12,224),8)==0,"STOP did not close admission");
     var stopping=Get(12,224);Check(!stopTask.IsCompleted&&WindowsStagedActorProtocol.U32(stopping,212)==0,"STOP waits for in-flight byte publication");Phase("stop-waiting",e.EventId);
     Reject(WindowsStagedActorProtocol.OperationRequest(a,13),144,"new retrieval rejected during STOP");
     Reject(creationRequest,WindowsProcessCreationProtocol.ReplyBytes,"metadata retrieval rejected during STOP");
    }
    Check(WindowsStagedActorProtocol.U32(Get(28,48),12)>0,"creation metadata remains owned while byte publication is retained");
    Get(17,0);Phase("publication-released",e.EventId);
    var reply=await publication.WaitAsync(TimeSpan.FromSeconds(6));WindowsStagedActorProtocol.CheckReply(reply,a,total,offsetForRace,count,metadata);
    Check(reply.AsSpan(144).SequenceEqual(actorBytes.AsSpan((int)offsetForRace,(int)count)),kind+" race retained exact executable bytes");Phase("publication-completed",e.EventId);
    File.WriteAllBytes(Path.Combine(capture,e.EventId+".request"),request);File.WriteAllBytes(Path.Combine(capture,e.EventId+".reply"),reply);
    if(stopTask!=null){await stopTask.WaitAsync(TimeSpan.FromSeconds(6));Phase("stop-completed",e.EventId);Ack(raw);}
    if(liveActor&&stopTask!=null)Check(!ownedChild.HasExited,"STOP releases registry and metadata without requiring actor exit");
    Reject(WindowsStagedActorProtocol.OperationRequest(a,13),144,"completed race identity cannot retrieve later bytes");
    cases.Add(new{Kind=kind,EventId=e.EventId,Major=k.Major,Acquisition=a,Process=process,CreationSha256=creationRecord.Sha256,ActorAlive=liveActor&&!ownedChild.HasExited,Offset=offsetForRace,Length=count,ReplySha256=Convert.ToHexString(SHA256.HashData(reply)),BodySha256=Convert.ToHexString(SHA256.HashData(reply.AsSpan(144)))});
   }
   finally
   {
    // The kernel pause also has an independent five-second timeout. Always
    // release it and await outstanding calls before closing the port.
    Get(17,0);if(publication!=null)try{await publication.WaitAsync(TimeSpan.FromSeconds(6));}catch(Exception){}if(stopTask!=null)try{await stopTask.WaitAsync(TimeSpan.FromSeconds(6));}catch(Exception){}
   }
   Drain();
  }
  Check(cases.Count==2,"both deterministic operation-pin races completed");Drain();
  var s=Get(12,224);var b=Get(20,88);var h=Get(3,48);var admission=Get(24,48);var creationHealth=Get(28,48);
  resources=new{Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(b),Operations=Convert.ToHexString(h),Admission=Convert.ToHexString(admission),ProcessCreation=Convert.ToHexString(creationHealth)};
  Check(WindowsStagedActorProtocol.U32(creationHealth,0)==1&&WindowsStagedActorProtocol.U32(creationHealth,4)==48&&WindowsStagedActorProtocol.U32(creationHealth,8)==256&&WindowsStagedActorProtocol.U32(creationHealth,12)==0&&WindowsStagedActorProtocol.U64(creationHealth,16)>0&&WindowsStagedActorProtocol.U64(creationHealth,16)==WindowsStagedActorProtocol.U64(creationHealth,24)&&WindowsStagedActorProtocol.U64(creationHealth,32)==0,"creation metadata allocations fully released without refusal after both races");
  Check(WindowsStagedActorProtocol.U64(s,24)==0&&WindowsStagedActorProtocol.U32(s,12)==0&&WindowsStagedActorProtocol.U32(s,16)==0&&WindowsStagedActorProtocol.U32(s,208)==0&&WindowsStagedActorProtocol.U32(s,212)==1&&WindowsStagedActorProtocol.U32(s,216)==0&&WindowsStagedActorProtocol.U32(s,220)==0,"all native bytes/copies/publications released; STOP completed without pause timeout");
  Check(WindowsStagedActorProtocol.U64(b,40)==WindowsStagedActorProtocol.U64(b,48)&&WindowsStagedActorProtocol.U64(b,72)==WindowsStagedActorProtocol.U64(b,80)&&WindowsStagedActorProtocol.U32(b,64)==0,"process references and operation pins balanced");
  Check(WindowsStagedActorProtocol.U64(s,96)==0&&WindowsStagedActorProtocol.U64(s,192)==0&&WindowsStagedActorProtocol.U64(b,56)==0&&WindowsStagedActorProtocol.U64(h,24)==0&&WindowsStagedActorProtocol.U32(h,40)==0,"no capacity, lifecycle, registry or operation losses");
  if(liveActor){Check(!ownedChild.HasExited,"live actor remained running through final resource accounting");using(var release=new FileStream(report+".release",FileMode.CreateNew,FileAccess.Write,FileShare.Read)){release.WriteByte(1);release.Flush(true);}Check(ownedChild.WaitForExit(15000)&&ownedChild.ExitCode==0,"owned actor exits normally after explicit release");}
  Check(string.IsNullOrWhiteSpace(await childErrors),"actor has no error output");
  passed=true;
 }
}
catch(Exception ex){error=ex.ToString();}
finally
{
 if(ownedChild!=null)
 {
  try
  {
   if(!ownedChild.HasExited){ownedChild.Kill();if(!ownedChild.WaitForExit(15000))throw new IOException("Owned actor cleanup did not complete");}
   if(childErrors!=null)File.WriteAllText(Path.Combine(reports,"actor.stderr.txt"),await childErrors.WaitAsync(TimeSpan.FromSeconds(5)));
  }
  catch(Exception cleanup){passed=false;error+="; owned actor cleanup: "+cleanup;}
  finally{ownedChild.Dispose();}
 }
}
var result=new{Schema="sequester.windows-pinned-actor-races/v1",AccountingPassed=passed,AllChildrenObserved=passed,Children=cases.Count==2?1:0,Matches=cases.Count,ByteCaptureImplemented=true,Sensor=sensor,Pid=pid,Created=created,CreatorPid=creatorPid,CreatorTid=creatorTid,CreatorCreated=creatorCreated,LiveActor=liveActor,ActorHash=actorHash,Cases=cases,Phases=phases,Checks=checks,BackgroundOperations=background,Resources=resources,Error=error,ProductionReady=false,Scope="Deterministic command-22 ACK/STOP byte and creation-metadata ownership, range validation and declared actor lifetime; separate from full operation matrix or deployment"};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{passed,result.Matches,error}));if(!passed)Environment.ExitCode=2;
static bool IsEmpty(int hr)=>hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A);
static bool TokenMatches(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static class Native
{
 [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]internal static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
