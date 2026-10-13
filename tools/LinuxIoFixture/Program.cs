using System.Buffers.Binary;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;
if(args is ["manifest-definition",var receipt])
{
    using var document=JsonDocument.Parse(File.ReadAllBytes(receipt));
    var manifest=document.RootElement.GetProperty("CandidateManifest").Deserialize<LinuxNativeInstallation.Manifest>()!;
    LinuxNativeInstallation.Validate(manifest);LinuxNativeInstallation.RequireModule(manifest);
    Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Scope="Offline exact manifest validation only",ManifestBase64=Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(manifest))}));return;
}

var checks=new List<string>();
void Check(bool ok,string name){if(!ok)throw new InvalidDataException(name);checks.Add(name);}
void Reject(Action action,string name){try{action();}catch(InvalidDataException){checks.Add(name);return;}throw new InvalidDataException("Accepted "+name);}
byte[] Frame(uint stage,long result=0,uint fileFlags=0,uint rwFlags=0,uint hook=3)
{
    var b=new byte[304];void U(int n,uint v)=>BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(n),v);void Q(int n,ulong v)=>BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(n),v);
    U(0,3);U(4,304);U(8,hook);U(12,stage);
    ulong[] key=[1,12,31,31,1000,1000,1,2,7,257,88,257,99,15];for(int i=0;i<key.Length;i++)Q(16+8*i,key[i]);
    Q(128,stage==1?2000ul:2001ul);Q(136,2000);Q(144,4096);Q(152,1);U(172,2);U(192,0);U(196,63);U(224,7);
    Q(232,16);BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(240),result);Q(248,4);Q(264,64);U(280,fileFlags);U(284,rwFlags);
    U(288,stage==2?127u:107u);
    if(stage==2){Q(256,result>0?(ulong)(4+result):4);Q(272,64);}
    return b;
}
byte[] Envelope(byte[] b,int version=8)=>JsonSerializer.SerializeToUtf8Bytes(new{schemaVersion=version,atomicObservation=Convert.ToBase64String(b)});
var sensor=Guid.NewGuid().ToString("N");var collector=Guid.NewGuid().ToString("N");long sequence=0;
AgentEvent Decode(byte[] b,int version=8)=>LinuxKernelDecoder.Decode(Envelope(b,version),sensor,collector,++sequence,DateTimeOffset.UtcNow);
var entered=Decode(Frame(1));var done=Decode(Frame(2,16));
Check(entered.Attribution!.LinuxKernel is {Version:4,NativeSchemaVersion:8,Lease:1,IoObservation.Stage:1},"entry preserves atomic actor reservation authority");
Check(done.Attribution!.LinuxKernel is {Lease:0,IoObservation.Stage:2},"return cannot issue a second actor-copy capability");
Check(LinuxKernelEvidence.Matches(entered)&&LinuxKernelEvidence.Matches(done),"I/O mappings pass cross-field evidence validation");
Check(EventActivity.From(entered) is {Evidence:"io-entry",Outcome:"unknown",Actions:["write-request"]},"entry is write intent, not successful I/O");
Check(EventActivity.From(done) is {Evidence:"kernel-operation",Outcome:"success",Actions:["write"]},"completed write interpreted separately from permission");
Check(done.Attribution.LinuxKernel!.IoObservation is {TransferredBytes:"16",OffsetBefore:"4",OffsetAfter:"20",SizeBefore:"64",SizeAfter:"64"},"exact byte count and size/offset samples retained");
var appended=Decode(Frame(2,16,0x400));
Check(appended.Operation=="File append completed"&&EventActivity.From(appended).Actions.SequenceEqual(["append"]),"O_APPEND operation identified from actual file flags");
Check(Decode(Frame(2,16,0,0x10,4)).Attribution!.LinuxKernel!.IoObservation!.AppendRequested==true,"vector RWF_APPEND identified");
Check(Decode(Frame(2,16,0x400,0x20,4)).Operation=="File write completed","RWF_NOAPPEND overrides O_APPEND for positioned vector writes");
var shortWrite=Decode(Frame(2,3));Check(shortWrite.Attribution!.LinuxKernel!.IoObservation!.TransferredBytes=="3","partial write reports actual returned bytes");
var zero=Decode(Frame(2));Check(zero.Attribution!.LinuxKernel!.IoObservation is {TransferredBytes:"0",Outcome:"success"},"zero-byte return is explicit");
var failed=Decode(Frame(2,-13));Check(failed.Attribution!.LinuxKernel!.IoObservation is {Errno:13,TransferredBytes:null}&&EventActivity.From(failed).Outcome=="failed","denied VFS write retains errno without fabricated bytes");
var pending=Decode(Frame(2,-529));Check(pending.Attribution!.LinuxKernel!.IoObservation is {Outcome:"pending",Errno:null,TransferredBytes:null}&&EventActivity.From(pending).Outcome=="unknown","asynchronous queued result is neither failed nor completed bytes");
Check(!LinuxKernelEvidence.Supports(4,1,1,1)&&LinuxKernelEvidence.Supports(4,1,1,1,1),"new I/O evidence requires explicit server capability");
Reject(()=>Decode(Frame(1,1)),"entry asserting an I/O return rejected");
Reject(()=>Decode(Frame(2,17)),"returned bytes exceeding requested count rejected");
Reject(()=>Decode(Frame(2,16),7),"new native bytes cannot masquerade as schema 7");
var reserved=Frame(2,16);reserved[296]=1;Reject(()=>Decode(reserved),"nonzero reserved ABI bytes rejected");
var unavailable=Frame(2,16);BinaryPrimitives.WriteUInt32LittleEndian(unavailable.AsSpan(288),33);
var partial=Decode(unavailable).Attribution!.LinuxKernel!.IoObservation!;Check(partial.OffsetBefore==null&&partial.SizeBefore==null&&partial.RwFlags==null&&partial.AppendRequested==null,"unavailable offset/size/append metadata stays null");
using(var actor=ActorLease.Capture(done,sensor))
{
    var evidence=new ForensicCollector(sensor,Path.Combine(Path.GetTempPath(),"sq-io-fixture-"+Guid.NewGuid().ToString("N"))).Begin(done,actor);
    Check(evidence.Observation is {BytesTransferred:16,Offset:4,Length:16,PreSize:64,PostSize:64,Outcome:"success",IoStatus.State:"captured"},"forensic observation maps completed VFS details");
    Check(evidence.IsValid()&&LinuxKernelEvidence.Matches(done with{Forensics=evidence}),"SIEM forensic evidence remains internally consistent");
}
var reused=Frame(1);BinaryPrimitives.WriteUInt64LittleEndian(reused.AsSpan(48),1001);var reusedEvent=Decode(reused);
using(var a=ActorLease.Capture(entered,sensor))using(var b=ActorLease.Capture(reusedEvent,sensor))Check(a.Process.InstanceId!=b.Process.InstanceId,"same PID with different birth has distinct instance identity");
var exec=Frame(1);BinaryPrimitives.WriteUInt64LittleEndian(exec.AsSpan(64),2);var execEvent=Decode(exec);
using(var a=ActorLease.Capture(entered,sensor))using(var b=ActorLease.Capture(execEvent,sensor))Check(a.Process.InstanceId!=b.Process.InstanceId,"same PID with different exec generation has distinct instance identity");
var round=JsonSerializer.Deserialize<AgentEvent>(JsonSerializer.Serialize(done))!;Check(LinuxKernelEvidence.Matches(round)&&round.Attribution!.LinuxKernel!.IoObservation==done.Attribution.LinuxKernel!.IoObservation,"JSON round-trip preserves exact I/O evidence");
Check(LinuxKernelEvidence.SameIoOperation(entered.Attribution.LinuxKernel!,done.Attribution.LinuxKernel!),"entry and return pair by every captured operation identity field");
Check(!LinuxKernelEvidence.SameIoOperation(reusedEvent.Attribution!.LinuxKernel!,done.Attribution.LinuxKernel!),"return cannot pair with reused PID birth");
Check(!LinuxKernelEvidence.SameIoOperation(execEvent.Attribution!.LinuxKernel!,done.Attribution.LinuxKernel!),"return cannot pair with another exec generation");
var ioLink=new LinuxIoPairEvidence{Status="paired",Reason="EXACT_DURABLE_IO_PAIR",EntryEventId=entered.EventId,ReturnEventId=done.EventId,EntryKernel=entered.Attribution.LinuxKernel,
    ActorCompletionEventId=Guid.NewGuid().ToString("N"),ActorSha256=new string('A',64),ActorStatus=EvidenceStatus.Captured("EXACT_IO_ENTRY_VERIFIED_PRIVATE_ACTOR")};
Check(ioLink.Matches(done.Attribution.LinuxKernel!,done.EventId,null),"return references captured entry actor without granting copy authority");
Check(!(ioLink with{EntryKernel=reusedEvent.Attribution.LinuxKernel}).Matches(done.Attribution.LinuxKernel!,done.EventId,null),"cross-process captured actor reference rejected");
Check(!(ioLink with{ActorSha256=null}).Matches(done.Attribution.LinuxKernel!,done.EventId,null),"captured actor reference requires an actual SHA-256");
var programs=Enumerable.Range(1,11).ToArray();
var readyFields=new Dictionary<string,object>{
    ["controlledReady"]=true,["controlVersion"]=4,["schemaVersion"]=8,["loadedProgramIds"]=programs,["attachedProgramIds"]=programs.Take(3).ToArray(),
    ["permissionAttached"]=false,["ioAttached"]=false,["scratchMapFrozen"]=true,["scratchMapId"]=21,["fileCallMapId"]=26,["fileCallMapFrozen"]=true,
    ["configMapFrozen"]=true,["configMapId"]=22,["eventsMapId"]=23,["lostMapId"]=24,["providerEpoch"]=7,["activationNonce"]="11111111111111111111111111111111",
    ["targetCount"]=1,["targets"]=new[]{new{ordinal=0,device=257,inode=99}},["targetsPinned"]=true,["watchMapId"]=25,["watchMapFrozen"]=true,
    ["mode"]=0,["healthAtReady"]=new int[6],["activationFrame"]="one-command-then-eof",["scalarCallMapId"]=27,["scalarCallMapFrozen"]=true,["iterCallMapId"]=28,["iterCallMapFrozen"]=true};
byte[] ReadyBytes()=>JsonSerializer.SerializeToUtf8Bytes(readyFields);
var ready=LinuxControlledLoaderProtocol.ParseReady(ReadyBytes());
Check(ready.ControlVersion==4&&ready.SchemaVersion==8&&ready.Programs.Length==11&&ready.ScalarCallMapId==27&&ready.IterCallMapId==28,"control 4 admits all I/O programs and frozen task maps");
readyFields["iterCallMapId"]=27;Reject(()=>LinuxControlledLoaderProtocol.ParseReady(ReadyBytes()),"I/O task maps cannot share an identity");readyFields["iterCallMapId"]=28;
readyFields["ioAttached"]=true;Reject(()=>LinuxControlledLoaderProtocol.ParseReady(ReadyBytes()),"ready cannot claim prematurely attached I/O observers");readyFields["ioAttached"]=false;
readyFields["healthAtReady"]=new[]{0,0,0,1,0,0};Reject(()=>LinuxControlledLoaderProtocol.ParseReady(ReadyBytes()),"pre-activation loss cannot become healthy baseline");readyFields["healthAtReady"]=new int[6];
var session=Guid.NewGuid().ToString("N");
byte[] Activated(int[] order)=>JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=4,sessionId=session,providerEpoch=7,activationNonce="11111111111111111111111111111111",attachedProgramIds=order,permissionAttached=true,ioAttached=true,lostAtActivation=0});
Check(LinuxControlledLoaderProtocol.ParseActivated(Activated([1,2,3,5,7,9,11,4,6,8,10]),ready,session).Lost==0,"completion hooks attach before entry hooks");
Reject(()=>LinuxControlledLoaderProtocol.ParseActivated(Activated(programs),ready,session),"unsafe I/O activation order rejected");
NativeHashChecks.Run(entered,done,sensor,ReadyBytes(),Activated([1,2,3,5,7,9,11,4,6,8,10]),session,Check);
byte[] PermissionFrame(uint stage)
{
    var frame=Frame(stage)[..232];BinaryPrimitives.WriteUInt32LittleEndian(frame,1);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(4),232);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8),1);BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(172),4);return frame;
}
var permissionEntry=Decode(PermissionFrame(1),7);var permissionResult=Decode(PermissionFrame(2),7);
Check(LinuxKernelEvidence.SamePermissionOperation(permissionEntry.Attribution!.LinuxKernel!,permissionResult.Attribution!.LinuxKernel!),"permission result pairs by the same process lifetime, actor, target and credentials");
NativeHashChecks.Run(permissionEntry,permissionResult,sensor,ReadyBytes(),Activated([1,2,3,5,7,9,11,4,6,8,10]),session,Check);
var historyRoot=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-io-history-"+Guid.NewGuid().ToString("N"));
var store=new Store(historyRoot);
var enrollment=store.Enroll(new(store.CreateCode().Code,"io-qualification","0.9.43-linux-dev"))!;
store.Heartbeat(enrollment.EndpointId,new("0.9.43-linux-dev","Monitoring"){OperatingSystem="linux"},System.Net.IPAddress.Parse("192.0.2.51"));
var completion=done with{EventId=Guid.NewGuid().ToString("N"),Source="Forensic enrichment",Operation="Forensic evidence completed"};
AgentEvent[] historyEvents=[entered,done,appended,failed,pending,completion];
Check(store.Ingest(enrollment.EndpointId,new(historyEvents))?.Accepted==6,"server persistence accepts distinct I/O observations and completion records");
foreach(var expected in new[]{("Write Requested",entered),("File Changed",done),("File Appended",appended),("Access Denied",failed),("Write Pending",pending),("Forensic Evidence",completion)})
{
    Check(EventHistoryPresentation.Action(expected.Item2,EventActivity.From(expected.Item2))==expected.Item1,"history presentation: "+expected.Item1);
    var rows=await store.History(new(){Action=expected.Item1,Os="linux",Host="io-qualification",Ip="192.0.2.51",Pid=31,Uid=0});
    Check(rows.Items.Count==1&&rows.Items[0].Event.EventId==expected.Item2.EventId,"SQLite action/OS/host/IP/PID/UID filtering: "+expected.Item1);
}
Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Names=checks,HistoryRoot=historyRoot,Scope="I/O ABI, contracts, forensic mapping, server presentation and SQLite history filtering. Native capture and deployment require separate qualification."}));
