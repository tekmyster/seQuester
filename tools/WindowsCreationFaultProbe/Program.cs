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

if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned isolated SYSTEM guest and new output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var parent=Path.GetDirectoryName(root)!;var capture=Path.Combine(root,"capture");var reports=Path.Combine(root,"reports");Directory.CreateDirectory(capture);Directory.CreateDirectory(reports);
var target=Path.Combine(root,"fault-impersonated-read.bin");File.WriteAllBytes(target,new byte[8192]);
var localService=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var d=new DirectoryInfo(path);var acl=d.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(localService,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));d.SetAccessControl(acl);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var actorBytes=File.ReadAllBytes(actorPath);var actorHash=Convert.ToHexString(SHA256.HashData(actorBytes));
using var creator=Process.GetCurrentProcess();var creatorPid=(ulong)creator.Id;var creatorCreated=(ulong)creator.StartTime.ToUniversalTime().ToFileTimeUtc();
var checks=new List<string>();var cases=new List<object>();var observed=new List<object>();var controlledIds=new List<string>();var backgroundIds=new List<string>();var rejections=new List<object>();var sensor=Guid.NewGuid().ToString("N");bool passed=false;string? error=null;object? resources=null;
uint N(byte[] b,int o)=>WindowsStagedActorProtocol.U32(b,o);ulong Q(byte[] b,int o)=>WindowsStagedActorProtocol.U64(b,o);
void Check(bool value,string label){if(!value)throw new IOException(label);checks.Add(label);}
try
{
 Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));using(port)
 {
  byte[] Send(byte[] request,int length){var output=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,(uint)request.Length,output,(uint)length,out var n));if(n!=length)throw new IOException("Wire reply size differs");return output;}
  byte[] Get(uint command,int length)=>Send(WindowsStagedActorProtocol.Message(command),length);
  void Reject(byte[] request,int size,string label){var hr=Native.FilterSendMessage(port,request,(uint)request.Length,new byte[size],(uint)size,out var returned);rejections.Add(new{Label=label,Request=Convert.ToHexString(request),Capacity=size,HResult="0x"+hr.ToString("X8"),Returned=returned});Check(hr<0,label);}
  void Save(string name,byte[] bytes){using var file=new FileStream(Path.Combine(capture,name),FileMode.CreateNew,FileAccess.Write,FileShare.Read);file.Write(bytes);file.Flush(true);}
  void DrainNotices()
  {
   foreach(var (command,length,name) in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
   {
    using var file=new FileStream(Path.Combine(capture,name+".journal"),FileMode.Append,FileAccess.Write,FileShare.Read);
    for(var i=0;i<4096;i++){var bytes=new byte[length];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,bytes,(uint)length,out var count);if(Native.Empty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(count==length,"diagnostic record size");file.Write(bytes);}
   }
  }
  Get(6,0);var binding=Get(20,88);var provider=Convert.ToHexString(binding.AsSpan(8,16));
  byte[] Fault(uint command,ulong scenario=0,uint mode=0,uint count=0,uint index=0)
  {
   var request=WindowsStagedActorProtocol.Message(command,64);Convert.FromHexString(provider).CopyTo(request,8);
   WindowsStagedActorProtocol.Put(request,24,creatorPid);WindowsStagedActorProtocol.Put(request,32,creatorCreated);WindowsStagedActorProtocol.Put(request,40,scenario);
   WindowsStagedActorProtocol.Put32(request,48,mode);WindowsStagedActorProtocol.Put32(request,52,count);WindowsStagedActorProtocol.Put32(request,56,index);return request;
  }
  var initial=Send(Fault(31),80);Check(N(initial,0)==1&&N(initial,4)==80&&N(initial,8)==0&&N(initial,12)==0&&N(initial,72)==0&&N(initial,76)==1,"fault diagnostic starts with empty reserved journal and no pending callback");
  Reject(Fault(32,index:0),128,"STOP row unavailable before STOP");
  var device=new StringBuilder(32768);Check(Native.QueryDosDevice(target[..2],device,device.Capacity)>0,"target device resolves");
  var scope=WindowsStagedActorProtocol.Message(5,1548);WindowsStagedActorProtocol.Put32(scope,8,1);Encoding.Unicode.GetBytes(device+target[2..]).CopyTo(scope,12);Send(scope,0);
  var actors=new Dictionary<(int,long),(JsonElement Truth,uint Mode,byte[] Journal)>();
  foreach(var mode in new uint[]{1,2,3,4,5})
  {
   DrainNotices();var before=Get(28,48);var beforeBinding=Get(20,88);
   Check(N(before,12)==0&&Q(before,16)==Q(before,24)&&Q(beforeBinding,72)==Q(beforeBinding,80),"quiescent metadata and operation-pin baseline before mode "+mode);
   var state=Send(Fault(29,mode:mode,count:mode==5?3u:1u),80);var scenario=Q(state,32);var generation=Q(state,40);var endIndex=N(state,76)-1;var firstIndex=endIndex-(mode==5?3u:1u);
   Save($"scenario-{scenario}.arm",state);Reject(Fault(32,index:endIndex),128,"future CLEAR row unavailable");
   for(var actorIndex=0u;actorIndex<(mode==5?3u:1u);actorIndex++)
   {
    if(mode==5){var live=Get(28,48);Check(N(live,12)==Math.Min(actorIndex,2),"capacity scenario retains only expected metadata objects before next child");}
    var report=Path.Combine(reports,$"mode-{mode}-{actorIndex}.json");var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};
    foreach(var arg in new[]{"impersonated-read",target,report,"--exit-immediately"})start.ArgumentList.Add(arg);start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";
    var creatorTid=Native.GetCurrentThreadId();using var child=Process.Start(start)??throw new IOException("Actor launch failed");var handle=child.Handle;var pid=child.Id;var created=child.StartTime.ToUniversalTime().ToFileTimeUtc();var stderr=child.StandardError.ReadToEndAsync();
    try{Check(child.WaitForExit(15000)&&child.ExitCode==0,"owned actor completes within original 15-second deadline");Check(string.IsNullOrWhiteSpace(await stderr.WaitAsync(TimeSpan.FromSeconds(5))),"actor stderr empty");}
    finally{if(!child.HasExited){child.Kill();if(!child.WaitForExit(15000))throw new IOException("Owned child cleanup failed");}}
    using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement.Clone();Check(t.GetProperty("ProcessId").GetInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created&&t.GetProperty("Outcome").GetString()=="Success","actor truth identifies exact successful process instance");
    var row=Send(Fault(32,index:firstIndex+actorIndex),128);Save($"scenario-{scenario}-actor-{actorIndex}.journal",row);
    Check(N(row,0)==1&&N(row,4)==128&&N(row,8)==2&&N(row,12)==mode&&Q(row,32)==scenario&&Q(row,40)==generation&&Q(row,48)==creatorPid&&Q(row,56)==creatorCreated&&Q(row,72)==(ulong)pid&&Q(row,80)==(ulong)created&&N(row,112)==0&&N(row,124)==(mode==4?2:1),"final lab-injected journal preserves full creator/candidate/actor identity");
    var expectedOutcome=mode==3?3u:mode==5&&actorIndex==2?2u:1u;Check(N(row,120)==expectedOutcome,"journal follows expected native metadata admission branch");
    actors.Add((pid,created),(t,mode,row));
    if(mode!=4)
    {
     var key=new ActorAcquisitionEvidence{Provider=provider,ProcessGeneration=Q(row,88).ToString("X16"),CandidateId=Q(row,64).ToString("X16"),ProcessId=pid,ProcessCreatedFileTime=created};
     var metadata=Send(WindowsStagedActorProtocol.CandidateRequest(key,13),144);var total=N(metadata,8);WindowsStagedActorProtocol.CheckReply(metadata,key,total,0,0);Check(total==actorBytes.Length,"eligible actor bytes remain available despite metadata fault");
     using var bytes=new MemoryStream();for(uint offset=0;offset<total;){var count=Math.Min(65536u,total-offset);var chunk=Send(WindowsStagedActorProtocol.CandidateRequest(key,10,offset,count),checked(144+(int)count));WindowsStagedActorProtocol.CheckReply(chunk,key,total,offset,count,metadata);bytes.Write(chunk,144,(int)count);offset+=count;}
     Check(bytes.ToArray().AsSpan().SequenceEqual(actorBytes),"exact actor copy survives selected metadata branch");Save($"scenario-{scenario}-actor-{actorIndex}.bin",bytes.ToArray());Save($"scenario-{scenario}-actor-{actorIndex}.metadata",metadata);
     var request=WindowsStagedActorProtocol.CandidateRequest(key,27);var raw=Send(request,WindowsProcessCreationProtocol.ReplyBytes);Save($"scenario-{scenario}-actor-{actorIndex}.creation",raw);
     var record=WindowsProcessCreationProtocol.Query(request,key,(_,_)=>raw);var process=WindowsProcessCreationProtocol.Apply(record,key,new(),sensor);
     if(expectedOutcome is 2 or 3){Check(N(raw,8)==0xC000009A&&N(raw,92)==expectedOutcome&&raw.AsSpan(96).ContainsAnyExcept((byte)0)==false&&process.Creation?.Status.State=="unavailable"&&process.CommandLine==null,"allocation/capacity failure has explicit unavailable metadata without another actor's fields");}
     else{Check(process.CommandLine==t.GetProperty("CommandLine").GetString()&&process.Creation?.CreatorPid==creatorPid&&process.Creation.CreatorTid==creatorTid,"native command/creator remain exact");if(mode is 1 or 2)Check(process.Creation!.CreatorCreatedFileTime==null&&process.ParentInstanceId==null&&process.Creation.CreatorStatus.State=="unavailable"&&N(raw,152)==(mode==2?0xC0000022u:0u)&&(N(raw,92)&2)==(mode==2?2u:0u),"simulated creator failure preserves explicit lookup-attempt distinction");}
     File.WriteAllText(Path.Combine(capture,$"scenario-{scenario}-actor-{actorIndex}.process.json"),JsonSerializer.Serialize(process));
     Send(WindowsStagedActorProtocol.CandidateRequest(key,11),0);Reject(WindowsStagedActorProtocol.CandidateRequest(key,27),WindowsProcessCreationProtocol.ReplyBytes,"candidate metadata closes after exact-key ACK");
    }
    else
    {
     Check(Q(row,88)==0,"forced binding failure publishes no generation");
     var unbound=new ActorAcquisitionEvidence{Provider=provider,ProcessGeneration="0000000000000001",CandidateId=Q(row,64).ToString("X16"),ProcessId=pid,ProcessCreatedFileTime=created};
     foreach(var (operation,size) in new[]{(13u,144),(10u,144),(26u,224),(27u,5304),(11u,0)})Reject(WindowsStagedActorProtocol.CandidateRequest(unbound,operation),size,"unbound candidate rejects strong operation "+operation);
    }
    DrainNotices();var liveAfter=Get(28,48);Save($"scenario-{scenario}-actor-{actorIndex}.health",liveAfter);
    if(mode==5)Check(N(liveAfter,12)==Math.Min(actorIndex+1,2),"retained raw operation pins own exactly A/B metadata after candidate ACK and process exit");
    cases.Add(new{Mode=mode,Scenario=scenario,ActorIndex=actorIndex,Pid=pid,Created=created,CreatorTid=creatorTid,ExpectedOutcome=expectedOutcome,JournalIndex=firstIndex+actorIndex,LabInjected=true});
   }
   var clear=Send(Fault(30,scenario),80);Save($"scenario-{scenario}.clear",clear);Check(N(clear,8)==0&&N(clear,72)==0,"CLEAR closes selection with no pending callback");Save($"scenario-{scenario}.clear-row",Send(Fault(32,index:endIndex),128));
   if(mode==5)Check(N(Get(28,48),12)==2,"CLEAR does not reset live metadata or release operation pins");
   var matched=0;var operationKeys=new HashSet<(int Pid,long Created,uint Major)>();
   for(var index=0;index<100;index++)
   {
    var raw=new byte[3800];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(2),8,raw,3800,out var count);if(Native.Empty(hr))break;Marshal.ThrowExceptionForHR(hr);Check(count==3800,"raw operation size");var e=WindowsKernelDecoder.Decode(raw,sensor,p=>p,false);var k=e.Attribution!.WindowsKernel!;Save(e.EventId+".record",raw);
    var controlled=e.ProcessId.HasValue&&k.ProcessCreatedFileTime.HasValue&&actors.ContainsKey((e.ProcessId.Value,k.ProcessCreatedFileTime.Value));
    var actor=controlled?actors[(e.ProcessId!.Value,k.ProcessCreatedFileTime!.Value)]:default;
    if(controlled){Check(actor.Mode==mode,"controlled actor cannot leak operations into another scenario");Check(k.Major is 0 or 3&&operationKeys.Add((e.ProcessId!.Value,k.ProcessCreatedFileTime!.Value,k.Major))&&k.ThreadId==actor.Truth.GetProperty("ThreadId").GetUInt32()&&Token(k.RequestorPrimary,actor.Truth.GetProperty("Primary"))&&Token(k.ThreadEffective,actor.Truth.GetProperty("Effective")),"unique raw accessing-thread and owner tokens survive metadata fault");}
    var companionRaw=Send(WindowsStagedActorProtocol.CompanionRequest(e,provider),88);Save(e.EventId+".binding",companionRaw);var companion=WindowsStagedActorProtocol.Companion(companionRaw,e,provider);
    if(controlled)Check(companion.BindingKind==(mode==4?"unavailable":"bytes-pinned"),"operation binding reflects actual native outcome");
    if(companion.BindingKind=="bytes-pinned"){var creationRaw=Send(WindowsStagedActorProtocol.OperationRequest(companion,27),WindowsProcessCreationProtocol.ReplyBytes);Save(e.EventId+".creation",creationRaw);if(controlled)Check(Q(creationRaw,40)==Q(actor.Journal,64)&&Q(creationRaw,48)==(ulong)e.ProcessId!.Value&&Q(creationRaw,56)==(ulong)k.ProcessCreatedFileTime!.Value,"retained operation metadata cannot cross process instances");}
    // Cache-manager/System and other background accesses are observations too.
    // Retain their raw evidence, binding and explicit unavailable fields. Only
    // the independently launched actors count toward controlled truth matching.
    var ack=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(ack,0);observed.Add(e);
    if(controlled){matched++;controlledIds.Add(e.EventId);}else{backgroundIds.Add(e.EventId);Check(backgroundIds.Count<=32,"background observations remain within the predeclared diagnostic bound");}
   }
   Check(matched==(mode==5?6:2),"exact CREATE and READ count for selected actor instances");var after=Get(28,48);Save($"scenario-{scenario}.after",after);Check(N(after,12)==0&&Q(after,16)==Q(after,24),"normal draining releases all metadata after selected scenario");
  }
  Get(9,0);DrainNotices();var stopped=Send(Fault(31),80);Save("fault-stop.state",stopped);Save("fault-stop.journal",Send(Fault(32,index:0),128));Check(N(stopped,8)==0&&N(stopped,12)==1&&N(stopped,72)==0,"STOP closes fault configuration without pending underflow");Reject(Fault(29,mode:1,count:1),80,"ARM rejected after STOP");
  var h=Get(28,48);var b=Get(20,88);var s=Get(12,224);var op=Get(3,48);resources=new{ProcessCreation=Convert.ToHexString(h),Binding=Convert.ToHexString(b),Staging=Convert.ToHexString(s),Operations=Convert.ToHexString(op)};
  Check(N(h,12)==0&&Q(h,16)==Q(h,24)&&Q(h,32)==2,"only selected allocation/capacity refusals and balanced metadata");
  Check(Q(b,40)==Q(b,48)&&Q(b,72)==Q(b,80)&&N(b,64)==0&&Q(b,56)==0&&Q(s,24)==0&&N(s,12)==0&&N(s,16)==0&&Q(s,96)==0&&Q(s,192)==0&&N(s,212)==1&&Q(op,24)==0&&N(op,40)==0,"native references bytes queue and loss counters balanced after fault cases");passed=true;
 }
}
catch(Exception ex){error=ex.ToString();}
var result=new{Schema="sequester.windows-creation-fault-native/v2",AccountingPassed=passed,AllChildrenObserved=passed,Children=cases.Count,Matches=controlledIds.Count,Events=observed.Count,ControlledEventIds=controlledIds,BackgroundEventIds=backgroundIds,Sensor=sensor,CreatorPid=creatorPid,CreatorCreated=creatorCreated,ActorHash=actorHash,LabInjected=true,Cases=cases,Checks=checks,Rejections=rejections,Resources=resources,Error=error,ByteCaptureImplemented=true,ProductionReady=false,Scope="Explicit diagnostic metadata branches; raw tokens and actor bytes retained. Background observations retained separately without controlled-actor ground-truth claims. No natural OS failure or deterministic pending-callback STOP race claim."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));File.WriteAllText(Path.Combine(capture,"events.json"),JsonSerializer.Serialize(observed));Console.WriteLine(JsonSerializer.Serialize(new{passed,error}));if(!passed)Environment.ExitCode=2;
static bool Token(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.ModifiedId==t.GetProperty("ModifiedId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static class Native
{
 internal static bool Empty(int hr)=>hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A);
 [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]internal static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
