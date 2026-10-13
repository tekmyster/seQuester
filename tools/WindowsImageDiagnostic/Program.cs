using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

if(args.Length==1&&args[0]=="--table-codec-fixture"){TableCodecChecks.Run();return;}
if(args.Length==2&&args[0]=="--apc-pin-branch"){ApcPinChecks.Run(args[1]);return;}
if(args.Length==2&&args[0]=="--acquisition-outcome"){AcquisitionOutcomeChecks.Run(args[1]);return;}
if(args.Length==2&&args[0]=="--acquisition-release"){AcquisitionOutcomeChecks.Run(args[1],true);return;}
if(args.Length==2&&args[0]=="--acquisition-faults"){AcquisitionFaultChecks.Run(args[1]);return;}
if(args.Length==5&&args[0]=="--acquisition-child"){Environment.ExitCode=AcquisitionOutcomeChecks.Child(args);return;}
if(args.Length==3&&args[0]=="--touch-child"){Environment.ExitCode=OperationBindingChecks.Child(args);return;}
if(args.Length==3&&args[0]=="--barrier-child"){Environment.ExitCode=AdmissionChecks.BarrierChild(args);return;}
if(args.Length!=1)throw new ArgumentException("New diagnostic output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output already exists");Directory.CreateDirectory(root);
Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var port));
using(port)
{
 using var lifecycle=new LifecycleJournal(port,root);bool staging=false;
 var rows=new List<Row>();var children=new List<Child>();var copies=new List<StagedCopy>();
 using var binary=new FileStream(Path.Combine(root,"trace.bin"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
 using var output=new StreamWriter(new FileStream(Path.Combine(root,"trace.jsonl"),FileMode.CreateNew,FileAccess.Write,FileShare.Read));
 byte[] Send(uint command,int bytes=0){var input=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),command);var b=bytes==0?null:new byte[bytes];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,8,b,(uint)bytes,out var n));if(n!=bytes)throw new IOException("Diagnostic reply length mismatch");return b??[];}
 void DrainTrace(){while(true){var input=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),7);var b=new byte[88];var hr=Native.FilterSendMessage(port,input,8,b,88,out var n);if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;Marshal.ThrowExceptionForHR(hr);if(n!=88||U32(b,0)!=1||U32(b,4)!=88)throw new IOException("Invalid trace row");var r=new Row(U32(b,8),U32(b,12),U64(b,16),U64(b,24),U64(b,32),U64(b,40),U64(b,48),U64(b,56),I64(b,64),U32(b,72),U32(b,76),U32(b,80),U32(b,84));rows.Add(r);binary.Write(b);output.WriteLine(JsonSerializer.Serialize(r));}output.Flush();binary.Flush(true);}
 void Drain(){DrainTrace();if(staging)lifecycle.Drain();}
 var exe=Path.Combine(Environment.SystemDirectory,"cmd.exe");var renamed=Path.Combine(root,"renamed-actor.exe");File.Copy(exe,renamed);
 var started=false;AccessCheck[] accessChecks=[];BarrierCheck? barrier=null;BudgetCheck? budget=null;IdleExpiryCheck? expiry=null;StopRaceCheck? stopRace=null;BindingCheck? bindingCheck=null;
 try{
  Send(6);started=true;
  staging=U32(Send(8,72),68)==2;
  if(staging){accessChecks=AdmissionChecks.Run(port,root,exe);Drain();budget=AdmissionChecks.Budget(port,root,exe,()=>Staging.Health(Send(12,224)),Drain);}
  foreach(var group in new[]{("immediate-exit",exe,12,false),("renamed-image",renamed,6,false),("concurrent",exe,4,true)}){
   var active=new List<(Process P,Child C)>();
   for(var i=0;i<group.Item3;i++){
    var psi=new ProcessStartInfo(group.Item2){UseShellExecute=false,CreateNoWindow=true};psi.ArgumentList.Add("/d");psi.ArgumentList.Add("/c");psi.ArgumentList.Add("exit 0");
    var expectedHash=staging?Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(group.Item2))):"";
    var p=Process.Start(psi)??throw new IOException("Child launch failed");var ownedHandle=p.Handle;
    var c=new Child(group.Item1,p.Id,p.StartTime.ToUniversalTime().ToFileTimeUtc(),group.Item2);children.Add(c);active.Add((p,c));
    if(!group.Item4){if(!p.WaitForExit(15000))throw new TimeoutException("Child timed out");if(p.ExitCode!=0)throw new IOException("Child failed");if(staging)copies.Add(Staging.Collect(port,c,root,expectedHash));}
    Drain();
   }
   foreach(var item in active){try{if(!item.P.WaitForExit(15000))throw new TimeoutException("Concurrent child timed out");if(item.P.ExitCode!=0)throw new IOException("Concurrent child failed");if(group.Item4&&staging)copies.Add(Staging.Collect(port,item.C,root,Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(group.Item2)))));}finally{item.P.Dispose();}}
   Drain();
  }
  if(staging){barrier=AdmissionChecks.Barrier(Drain,c=>children.Add(c),(c,hash)=>copies.Add(Staging.Collect(port,c,root,hash)));bindingCheck=OperationBindingChecks.Run(port,root,Drain);expiry=LifecycleJournal.Expire(port,()=>Staging.Health(Send(12,224)),Drain,DrainTrace,exe);stopRace=LifecycleJournal.StopRace(port,c=>Send(c),()=>Staging.Health(Send(12,224)),Drain,exe);}
 }
 finally{if(started){Send(9);if(staging){var deadline=Stopwatch.GetTimestamp()+15*Stopwatch.Frequency;while(true){Drain();var pending=Staging.Health(Send(12,224));if(pending.InFlight==0&&pending.PublicationInFlight==0&&pending.Bytes==0)break;if(Stopwatch.GetTimestamp()>deadline)throw new TimeoutException("STOP resources still held");Thread.Sleep(10);}}Drain();}}
 var h=Send(8,72);if(U32(h,0)!=1||U32(h,4)!=72)throw new IOException("Invalid diagnostic health");
 var health=new{Epoch=U64(h,8),Sequence=U64(h,16),Lost=U64(h,24),PoolDrops=U64(h,32),ReferencesTaken=U64(h,40),ReferencesReleased=U64(h,48),Live=U32(h,56),Queued=U32(h,60),Enabled=U32(h,64),Mode=U32(h,68)};
 if(health.Mode>2)throw new IOException("Unknown diagnostic mode");
 var stagingHealth=staging?Staging.Health(Send(12,224)):null;
 var bindingHealth=staging?OperationBindingChecks.Health(port):null;
 var admissionHealth=staging?Staging.Admission(Send(24,48)):null;
 var lifecyclePassed=!staging||lifecycle.Validate(stagingHealth!,copies,expiry,stopRace);
 var stagingPassed=!staging||(lifecyclePassed&&bindingCheck?.Passed==true&&bindingHealth!.Live==0&&bindingHealth.ReferencesTaken==bindingHealth.ReferencesReleased&&bindingHealth.CapacityMisses==0&&bindingHealth.OperationPins>0&&bindingHealth.OperationPins==bindingHealth.OperationPinsReleased&&budget?.Passed==true&&accessChecks.Length==6&&accessChecks.All(c=>c.Passed)&&barrier?.AllFourAliveBeforeRelease==true&&barrier.Members.Length==4&&copies.Count==children.Count&&copies.All(c=>c.Passed)&&stagingHealth!.Enabled==0&&stagingHealth.InFlight==0&&stagingHealth.Live==0&&stagingHealth.Bytes==0&&stagingHealth.PeakBytes<=Staging.ByteLimit(stagingHealth.MetadataSlots)&&stagingHealth.ProvisionalEntries==stagingHealth.Released&&stagingHealth.PoolDrops==0&&(stagingHealth.MetadataSlots is 64 or 128)&&stagingHealth.MaxConcurrentCopies==32&&stagingHealth.PeakInFlight<=32&&admissionHealth!.MaxQualification==32&&admissionHealth.MaxFullCopies==16&&admissionHealth.QualificationPeak<=32&&admissionHealth.FullCopiesPeak<=16&&admissionHealth.QualificationInFlight==0&&admissionHealth.FullCopiesInFlight==0&&admissionHealth.QualificationRefusals==0&&admissionHealth.FullCopyRefusals==0);
 var cases=children.Select(c=>{var matching=rows.Where(r=>r.ProcessId==(ulong)c.ProcessId&&r.ProcessCreated==(ulong)c.CreatedFileTime).ToArray();var creates=matching.Where(r=>r.Kind==2).ToArray();var exits=matching.Where(r=>r.Kind==3).ToArray();var create=creates.SingleOrDefault();return new{Child=c,CreateRows=creates.Length,ExitRows=exits.Length,ImageRows=matching.Count(r=>r.Kind==1),MainFileObjectMatched=create?.Matches==1,MatchedCandidates=create?.Matches??0,CandidateId=create?.CandidateId??0,CreateIrql=create?.Irql,CreateApcFlags=create?.Flags,ImageBeforeCreate=creates.Length==1&&matching.Any(r=>r.Kind==1&&r.CandidateId==create!.CandidateId&&r.Sequence<create.Sequence),PostCreateBeforeProcess=creates.Length==1&&rows.Any(r=>r.Kind==5&&r.CandidateId!=0&&r.CandidateId==create!.CandidateId&&r.Sequence<create.Sequence),Trace=matching};}).ToArray();
 var accounting=!rows.Any(r=>(r.Flags&64)!=0)&&health.Enabled==0&&health.Live==0&&health.ReferencesTaken==health.ReferencesReleased&&health.Queued==0&&health.Lost==0&&health.PoolDrops==0&&rows.Count==(long)health.Sequence&&rows.Select((r,i)=>r.Epoch==health.Epoch&&r.Sequence==(ulong)i+1).All(x=>x);
 var observed=cases.All(c=>c.CreateRows==1&&c.ExitRows==1);
 var result=new{Schema="sequester.windows-image-association-diagnostic/v1",RecordedUtc=DateTimeOffset.UtcNow,Host=Environment.MachineName,Health=health,AccountingPassed=accounting,AllChildrenObserved=observed,Children=cases.Length,Matches=cases.Count(c=>c.MainFileObjectMatched&&(health.Mode>=1?c.PostCreateBeforeProcess:c.ImageBeforeCreate)),AssociationMode=health.Mode>=1?"post-create-to-process-create":"image-to-process-create",Cases=cases,ProductionReady=false,ByteCaptureImplemented=staging,StagingPassed=stagingPassed,StagingHealth=stagingHealth,AdmissionHealth=admissionHealth,StagedCopies=copies,AccessChecks=accessChecks,Barrier=barrier,Budget=budget,Binding=bindingCheck,BindingHealth=bindingHealth,IdleExpiry=expiry,StopRace=stopRace,LifecyclePassed=lifecyclePassed,LifecycleRows=lifecycle.Rows.Count,Scope=staging?"Opt-in laboratory raw backing bytes read during eligible post-CREATE, published after exact file-object bind; no immutable filesystem snapshot or process-memory claim":"No-I/O callback ordering and live file-object equality only; no main-image byte lease or immutable-content guarantee"};
 File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{result.AccountingPassed,result.AllChildrenObserved,result.Children,result.Matches,result.ByteCaptureImplemented,Root=root}));
 if(!accounting||!observed||!stagingPassed)Environment.ExitCode=2;
}
static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
static long I64(byte[] b,int o)=>BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(o));
record Child(string Scenario,int ProcessId,long CreatedFileTime,string Image);
record Row(uint Kind,uint Flags,ulong Epoch,ulong Sequence,ulong ProcessId,ulong ProcessCreated,ulong ThreadId,ulong CandidateId,long Qpc,uint Irql,uint Candidates,uint Matches,uint Released);
record StagingSlot(ulong Id,ulong Pid,ulong Created,ulong Deadline,uint Ready,uint Exited,ulong FileId,uint OriginalRequestedAccess,uint MappedRequestedAccess,uint QualificationVersion,uint CreateStatus);
record StagedCopy(Child Child,bool Passed,string? Error,int HResult,ulong CandidateId,uint Flags,uint Bytes,string? Path,string ExpectedSha256,string? PreservedSha256,ulong FileId,long CopyStarted,long CopyEnded,bool Acknowledged,StagingSlot[]? FailureSlots=null,int RejectedInvalidRequests=0,uint MappedRequestedAccess=0,uint OriginalRequestedAccess=0,uint QualificationVersion=0,uint CreateStatus=0);
record StagingHealth(uint Enabled,uint InFlight,uint Live,ulong Bytes,ulong PeakBytes,ulong Reads,ulong ReadFailures,ulong ProvisionalEntries,ulong Matched,ulong Released,ulong Acks,ulong Expired,ulong PoolDrops,ulong Skipped,ulong ReadCalls,uint LastStatus,uint LastReason,ulong BoundBuffersReady,ulong UnboundEvictions,ulong DuplicateDrops,uint LastMappedRequestedAccess,uint MetadataSlots,uint MaxConcurrentCopies,uint PeakInFlight,ulong IdleSweeps,ulong IdleExpired,ulong NoticeSequence,ulong NoticeLost,uint NoticeQueued,uint WorkerRunning,uint PublicationInFlight,uint StopCompleted,uint TestPauseEntered,uint TestPauseTimedOut);
record AdmissionHealth(uint MaxQualification,uint MaxFullCopies,uint QualificationInFlight,uint FullCopiesInFlight,uint QualificationPeak,uint FullCopiesPeak,ulong QualificationRefusals,ulong FullCopyRefusals);
static class Staging{
 static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
 static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
 internal static StagingHealth Health(byte[] h){if(U32(h,0)!=3||U32(h,4)!=224)throw new IOException("Invalid staging health");return new(U32(h,8),U32(h,12),U32(h,16),U64(h,24),U64(h,32),U64(h,40),U64(h,48),U64(h,56),U64(h,64),U64(h,72),U64(h,80),U64(h,88),U64(h,96),U64(h,104),U64(h,112),U32(h,120),U32(h,124),U64(h,128),U64(h,136),U64(h,144),U32(h,20),U32(h,152),U32(h,156),U32(h,160),U64(h,168),U64(h,176),U64(h,184),U64(h,192),U32(h,200),U32(h,204),U32(h,208),U32(h,212),U32(h,216),U32(h,220));}
 internal static ulong ByteLimit(uint slots)=>slots switch{64=>32UL*1024*1024,128=>64UL*1024*1024,_=>throw new IOException("Unsupported staging metadata capacity")};
 internal static AdmissionHealth Admission(byte[] b){
  if(b.Length!=48||U32(b,0)!=1||U32(b,4)!=48)throw new IOException("Admission health schema mismatch");
  return new(U32(b,8),U32(b,12),U32(b,16),U32(b,20),U32(b,24),U32(b,28),U64(b,32),U64(b,40));
 }
 internal static StagingSlot[] DecodeTable(byte[] b,uint slots){
  _=ByteLimit(slots);var expected=checked(8+(int)slots*64);var version=slots==64?2u:3u;
  if(b.Length!=expected||U32(b,0)!=version||U32(b,4)!=(uint)expected)throw new IOException("Invalid staging table shape or schema");
  return Enumerable.Range(0,(int)slots).Select(i=>{int o=8+64*i;return new StagingSlot(U64(b,o),U64(b,o+8),U64(b,o+16),U64(b,o+24),U32(b,o+32),U32(b,o+36),U64(b,o+40),U32(b,o+48),U32(b,o+52),U32(b,o+56),U32(b,o+60));}).Where(s=>s.Id!=0).ToArray();
 }
 internal static StagingSlot[] Table(SafeFileHandle port){
  var providerBefore=OperationBindingChecks.Health(port);
  var input=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),12);
  var health=new byte[224];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,8,health,224,out var n));if(n!=224)throw new IOException("Invalid staging health length");
  var slots=Health(health).MetadataSlots;_=ByteLimit(slots);var length=checked(8+(int)slots*64);
  BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),14);var b=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,8,b,(uint)length,out n));
  if(n!=(uint)length)throw new IOException("Truncated staging table");var table=DecodeTable(b,slots);
  var providerAfter=OperationBindingChecks.Health(port);
  BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),12);Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,input,8,health,224,out n));
  if(n!=224)throw new IOException("Invalid trailing staging health length");
  ValidateTableEpoch(providerBefore.Provider,providerAfter.Provider,slots,Health(health).MetadataSlots,providerBefore.Stopped,providerAfter.Stopped);
  return table;
 }
 internal static void ValidateTableEpoch(string before,string after,uint slotsBefore,uint slotsAfter,uint stoppedBefore,uint stoppedAfter){
  if(before!=after||slotsBefore!=slotsAfter||stoppedBefore!=stoppedAfter)throw new IOException("Staging table provider or capacity changed during collection");
 }
 internal static StagedCopy Collect(SafeFileHandle port,Child child,string root,string expected){
  ulong id=0,fileId=0;uint flags=0,total=0,requested=0,original=0,qualification=0,createStatus=0;long started=0,ended=0;string? path=null,hash=null;bool ack=false;int hr=0,rejected=0;
  void RequireRejected(uint command,ulong created,ulong candidateId,int expectedHr){
   var input=new byte[40];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),command);
   BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(8),(ulong)child.ProcessId);BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(16),created);BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(24),candidateId);
   var b=command==11?null:new byte[120];var result=Native.FilterSendMessage(port,input,40,b,(uint)(b?.Length??0),out var n);
   // FilterSendMessage output values are consumed only on success. Its failed
   // HRESULT is the rejection evidence; BytesReturned is not a failure contract.
   if(result!=expectedHr)throw new IOException($"Invalid generation/ID request not rejected as expected: {result:X8}");rejected++;
  }
  byte[] Request(uint command,uint offset,uint length){
   var input=new byte[40];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),command);
   BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(8),(ulong)child.ProcessId);BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(16),(ulong)child.CreatedFileTime);BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(24),id);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(32),offset);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(36),length);
   var b=command==11?null:new byte[120+length];hr=Native.FilterSendMessage(port,input,40,b,(uint)(b?.Length??0),out var n);Marshal.ThrowExceptionForHR(hr);
   if(command==11){if(n!=0)throw new IOException("Invalid acknowledgment reply");return [];}
   if(n!=120+length||U32(b!,0)!=2||U32(b!,4)!=120||U32(b!,12)!=offset||U32(b!,16)!=length||U32(b!,24)!=0||U64(b!,40)!=(ulong)child.ProcessId||U64(b!,48)!=(ulong)child.CreatedFileTime||(id!=0&&U64(b!,32)!=id))throw new IOException("Invalid staging chunk identity or length");return b!;
  }
  try{
   var metadata=Request(13,0,0);id=U64(metadata,32);flags=U32(metadata,20);requested=U32(metadata,28);total=U32(metadata,8);fileId=U64(metadata,56);started=(long)U64(metadata,88);ended=(long)U64(metadata,96);original=U32(metadata,104);qualification=U32(metadata,108);createStatus=U32(metadata,112);
   if(qualification!=2||createStatus!=0||(requested&0x21)!=0x21||id==0||total==0||total>8*1024*1024||(flags&15)!=15||started<=0||ended<started)throw new IOException("Incomplete bound/exited snapshot metadata");
   RequireRejected(10,(ulong)child.CreatedFileTime,0,unchecked((int)0x80070057));
   RequireRejected(10,(ulong)child.CreatedFileTime+1,id,unchecked((int)0x80070490));
   RequireRejected(10,(ulong)child.CreatedFileTime,id^(1UL<<63),unchecked((int)0x80070490));
   RequireRejected(11,(ulong)child.CreatedFileTime,id^(1UL<<63),unchecked((int)0x80070490));
   path=System.IO.Path.Combine(root,$"actor-{child.ProcessId}-{child.CreatedFileTime}-{id}.evidence.bin");
   using(var stream=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){for(uint offset=0;offset<total;){uint length=Math.Min(65536,total-offset);var b=Request(10,offset,length);if(U32(b,8)!=total||U64(b,56)!=fileId)throw new IOException("Staging identity changed");stream.Write(b,120,(int)length);offset+=length;}stream.Flush(true);}
   hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));if(hash!=expected)throw new IOException("Preserved fixture SHA-256 differs");Request(11,0,0);ack=true;
   return new(child,true,null,0,id,flags,total,path,expected,hash,fileId,started,ended,ack,null,rejected,requested,original,qualification,createStatus);
  }catch(Exception ex){
   StagingSlot[]? slots=null;try{slots=Table(port);}catch(COMException){}
   return new(child,false,ex.Message,hr,id,flags,total,path,expected,hash,fileId,started,ended,ack,slots,rejected,requested,original,qualification,createStatus);
  }
 }
}
static class Native{
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,IntPtr context,ushort contextSize,IntPtr security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint inputBytes,byte[]? output,uint outputBytes,out uint returned);
}



