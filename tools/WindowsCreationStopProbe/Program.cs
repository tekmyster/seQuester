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

// One attempt per driver load. The guest wrapper predeclares exactly eight.
// No delay, pause, or wait is injected into the process callback.
if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned SYSTEM guest and new output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var package=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,".."));
var capture=Path.Combine(root,"capture");var reports=Path.Combine(root,"reports");Directory.CreateDirectory(capture);Directory.CreateDirectory(reports);
var target=Path.Combine(root,"stop-impersonated-read.bin");File.WriteAllBytes(target,new byte[8192]);
var localService=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var d=new DirectoryInfo(path);var acl=d.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(localService,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));d.SetAccessControl(acl);}
Grant(package,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var actorPath=Path.Combine(AppContext.BaseDirectory,"actor","WindowsActorFixture.exe");var actorHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actorPath)));
using var creator=Process.GetCurrentProcess();var creatorPid=(ulong)creator.Id;var creatorCreated=(ulong)creator.StartTime.ToUniversalTime().ToFileTimeUtc();
var checks=new List<string>();var events=new List<object>();var rejections=new List<object>();var sensor=Guid.NewGuid().ToString("N");
bool passed=false,overlap=false,actorObserved=false;string? error=null;object? resources=null;object? identity=null;uint polls=0;int matches=0;
uint N(byte[] b,int o)=>WindowsStagedActorProtocol.U32(b,o);ulong Q(byte[] b,int o)=>WindowsStagedActorProtocol.U64(b,o);
void Check(bool value,string label){if(!value)throw new IOException(label);checks.Add(label);}
void Save(string name,byte[] bytes){using var file=new FileStream(Path.Combine(capture,name),FileMode.CreateNew,FileAccess.Write,FileShare.Read);file.Write(bytes);file.Flush(true);}
try
{
 Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));using(port)
 {
  byte[] Send(byte[] request,int length){var output=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,(uint)request.Length,output,(uint)length,out var n));if(n!=length)throw new IOException("Wire reply size differs");return output;}
  byte[] Get(uint command,int length)=>Send(WindowsStagedActorProtocol.Message(command),length);
  void Reject(byte[] request,int size,string label){var hr=Native.FilterSendMessage(port,request,(uint)request.Length,new byte[size],(uint)size,out var n);rejections.Add(new{Label=label,Request=Convert.ToHexString(request),Capacity=size,HResult="0x"+hr.ToString("X8"),Returned=n});Check(hr<0,label);}
  Get(6,0);var binding=Get(20,88);var provider=Convert.ToHexString(binding.AsSpan(8,16));
  byte[] Fault(uint command,ulong scenario=0,uint mode=0,uint count=0,uint index=0)
  {
   var request=WindowsStagedActorProtocol.Message(command,64);Convert.FromHexString(provider).CopyTo(request,8);
   WindowsStagedActorProtocol.Put(request,24,creatorPid);WindowsStagedActorProtocol.Put(request,32,creatorCreated);WindowsStagedActorProtocol.Put(request,40,scenario);
   WindowsStagedActorProtocol.Put32(request,48,mode);WindowsStagedActorProtocol.Put32(request,52,count);WindowsStagedActorProtocol.Put32(request,56,index);return request;
  }
  var initial=Send(Fault(31),80);Save("initial.state",initial);Check(N(initial,0)==1&&N(initial,4)==80&&N(initial,8)==0&&N(initial,12)==0&&N(initial,72)==0&&N(initial,76)==1,"fresh load has empty selection and no STOP");
  var device=new StringBuilder(32768);Check(Native.QueryDosDevice(target[..2],device,device.Capacity)>0,"target volume resolves");
  var scope=WindowsStagedActorProtocol.Message(5,1548);WindowsStagedActorProtocol.Put32(scope,8,1);Encoding.Unicode.GetBytes(device+target[2..]).CopyTo(scope,12);Send(scope,0);
  var report=Path.Combine(reports,"actor.json");var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};
  foreach(var arg in new[]{"impersonated-read",target,report,"--exit-immediately"})start.ArgumentList.Add(arg);start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";
  using var ready=new ManualResetEventSlim();using var go=new ManualResetEventSlim();
  var launched=new TaskCompletionSource<(Process Child,uint Tid)>(TaskCreationOptions.RunContinuationsAsynchronously);
  var launcher=new Thread(()=>{ready.Set();go.Wait();try{var tid=Native.GetCurrentThreadId();var child=Process.Start(start)??throw new IOException("Actor launch failed");_ = child.Handle;launched.SetResult((child,tid));}catch(Exception ex){launched.SetException(ex);}}){IsBackground=true,Name="Owned single actor creator"};
  launcher.Start();if(!ready.Wait(5000))throw new IOException("Owned launcher not ready");
  var arm=Send(Fault(29,mode:1,count:1),80);Save("arm.state",arm);var scenario=Q(arm,32);var generation=Q(arm,40);var selectedIndex=N(arm,76)-2;
  Reject(Fault(33,scenario),64,"callback removal requires STOP");
  var pollRequest=Fault(32,index:selectedIndex);var pollRow=new byte[128];var watch=Stopwatch.StartNew();
  go.Set();
  Exception? selectionError=null;
  try
  {
   while(true)
   {
    var hr=Native.FilterSendMessage(port,pollRequest,64,pollRow,128,out var n);polls++;
    if(hr>=0){Check(n==128&&N(pollRow,8)==2,"fixed selected journal row observed");break;}
    if(hr!=unchecked((int)0x80070490))Marshal.ThrowExceptionForHR(hr);
    if(watch.ElapsedMilliseconds>15000)throw new TimeoutException("No selected callback within original actor deadline");
    Thread.Yield();
   }
   // Send STOP immediately after observing selection, before writing evidence.
   Get(9,0);
   Save("observed-selection.journal",pollRow);
  }
  catch(Exception ex){selectionError=ex;}
  finally
  {
   // Ensure the one-way STOP request also runs on a failed selection observation.
   Get(9,0);
  }
  var actor=await launched.Task.WaitAsync(TimeSpan.FromSeconds(15));using var child=actor.Child;
  var pid=child.Id;var created=child.StartTime.ToUniversalTime().ToFileTimeUtc();var stderr=child.StandardError.ReadToEndAsync();
  try{Check(child.WaitForExit(15000)&&child.ExitCode==0,"owned actor exits within original 15-second deadline");Check(string.IsNullOrWhiteSpace(await stderr.WaitAsync(TimeSpan.FromSeconds(5))),"actor stderr empty");}
  finally{if(!child.HasExited){child.Kill();if(!child.WaitForExit(15000))throw new IOException("Owned actor cleanup failed");}}
  if(selectionError is not null)throw selectionError;
  using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
  Check(t.GetProperty("ProcessId").GetInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created&&t.GetProperty("Outcome").GetString()=="Success","independent actor report binds exact PID/start and successful read");
  var row=Send(Fault(32,index:selectedIndex),128);Save("finished-selection.journal",row);
  var stop=Send(Fault(32,index:0),128);Save("stop.journal",stop);
  Check(N(row,0)==1&&N(row,4)==128&&N(row,8)==2&&N(row,12)==1&&Q(row,32)==scenario&&Q(row,40)==generation&&Q(row,48)==creatorPid&&Q(row,56)==creatorCreated&&Q(row,72)==(ulong)pid&&Q(row,80)==(ulong)created,"selected callback identifies exact creator and actor instance");
  Check(N(row,124) is >=1 and <=6&&Q(row,104)>=Q(row,96)&&Q(row,104)>0,"selected callback finishes with valid terminal and ordering");
  Check(N(stop,8)==4&&Q(stop,32)==scenario&&Q(stop,96)==Q(stop,104)&&Q(stop,96)>=Q(row,96),"one STOP row follows observed selection");
  overlap=Q(row,96)<Q(stop,96)&&Q(stop,96)<Q(row,104);actorObserved=true;
  Check(N(row,124)<=3?Q(row,104)<=Q(stop,96):Q(stop,96)<=Q(row,104),"terminal agrees with actual STOP ordering, retaining equal-QPC ambiguity");
  var stopped=Send(Fault(31),80);Save("stopped.state",stopped);Check(N(stopped,8)==0&&N(stopped,12)==1&&N(stopped,72)==0,"actor exit leaves no pending selected callback");
  Reject(Fault(29,mode:1,count:1),80,"no ARM after STOP");
  var wrongOwner=Fault(33,scenario);WindowsStagedActorProtocol.Put(wrongOwner,32,creatorCreated+1);Reject(wrongOwner,64,"PID with wrong start cannot remove callbacks");
  // STOP may precede every target operation. Preserve all events; do not invent
  // a required alert count or interpret zero events as an attribution pass.
  for(var index=0;index<100;index++)
  {
   var raw=new byte[3800];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(2),8,raw,3800,out var count);if(Native.Empty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(count==3800,"raw operation size");
   var e=WindowsKernelDecoder.Decode(raw,sensor,p=>p,false);Save(e.EventId+".record",raw);var k=e.Attribution!.WindowsKernel!;
   if(e.ProcessId==pid&&k.ProcessCreatedFileTime==created){Check(k.ThreadId==t.GetProperty("ThreadId").GetUInt32()&&Token(k.RequestorPrimary,t.GetProperty("Primary"))&&Token(k.ThreadEffective,t.GetProperty("Effective")),"any recorded controlled event has exact owner and accessing-thread token");matches++;}
   var ack=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(ack,0);events.Add(e);
  }
  foreach(var (command,length,name) in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
  {
   using var file=new FileStream(Path.Combine(capture,name+".journal"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
   for(var i=0;i<4096;i++){var raw=new byte[length];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,raw,(uint)length,out var n);if(Native.Empty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(n==length,"notice size");file.Write(raw);}
  }
  var h=Get(28,48);var b=Get(20,88);var s=Get(12,224);var op=Get(3,48);resources=new{ProcessCreation=Convert.ToHexString(h),Binding=Convert.ToHexString(b),Staging=Convert.ToHexString(s),Operations=Convert.ToHexString(op)};
  Check(N(h,12)==0&&Q(h,16)==Q(h,24)&&Q(h,32)==0,"metadata references balanced with no allocation refusal");
  Check(Q(b,40)==Q(b,48)&&Q(b,72)==Q(b,80)&&N(b,64)==0&&Q(b,56)==0&&Q(s,24)==0&&N(s,12)==0&&N(s,16)==0&&Q(s,96)==0&&Q(s,192)==0&&N(s,212)==1&&Q(op,24)==0&&N(op,40)==0,"native references bytes queue and loss balanced before callback removal");
  var health=Send(Fault(33,scenario),64);Save("removed.health",health);
  Check(N(health,0)==1&&N(health,4)==64&&N(health,8)==1&&N(health,12)==0&&Convert.ToHexString(health.AsSpan(16,16))==provider&&N(health,32)==1&&N(health,36)==1&&N(health,40)==1&&N(health,44)==0&&Q(health,48)>=Q(health,56)&&Q(health,56)==Q(row,104),"actual callback removal returns balanced final selected accounting");
  var again=Send(Fault(33,scenario),64);Save("removed-repeat.health",again);Check(health.AsSpan().SequenceEqual(again),"repeated removal returns immutable completed health");
  Check(stop.AsSpan().SequenceEqual(Send(Fault(32,index:0),128))&&row.AsSpan().SequenceEqual(Send(Fault(32,index:selectedIndex),128)),"repeated STOP and removal do not mutate terminal journal rows");
  identity=new{Provider=provider,Scenario=scenario,ArmGeneration=generation,JournalIndex=selectedIndex,Pid=pid,Created=created,CreatorTid=actor.Tid,SelectedQpc=Q(row,96),StopQpc=Q(stop,96),FinishedQpc=Q(row,104),RemovedQpc=Q(health,48),Terminal=N(row,124)};passed=true;
 }
}
catch(Exception ex){error=ex.ToString();}
File.WriteAllText(Path.Combine(capture,"events.json"),JsonSerializer.Serialize(events));
var result=new{Schema="sequester.windows-creation-stop-native/v1",AccountingPassed=passed,AllChildrenObserved=actorObserved,Children=actorObserved?1:0,Matches=matches,Events=events.Count,Sensor=sensor,CreatorPid=creatorPid,CreatorCreated=creatorCreated,ActorHash=actorHash,Identity=identity,OverlapObserved=overlap,Polls=polls,LabInjected=true,Checks=checks,Rejections=rejections,Resources=resources,Error=error,ByteCaptureImplemented=true,ProductionReady=false,Scope="One real process/STOP attempt per fresh diagnostic load; no callback pause. Accounting acceptance is separate from observed natural overlap and file-operation attribution coverage."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{passed,overlap,error}));if(!passed)Environment.ExitCode=2;
static bool Token(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.ModifiedId==t.GetProperty("ModifiedId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static class Native
{
 internal static bool Empty(int hr)=>hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A);
 [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]internal static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
