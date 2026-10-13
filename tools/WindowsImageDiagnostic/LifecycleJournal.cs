using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

record LifecycleRow(uint Kind,uint Reason,uint Status,uint Flags,uint OriginalAccess,uint MappedAccess,uint QualificationVersion,uint CreateStatus,ulong Sequence,ulong Id,ulong? Pid,ulong? Created,ulong? FileId,ulong? Length,ulong Monotonic,ulong ObservedUtc,uint EmissionIrql);
record IdleExpiryCheck(Child Child,ulong CandidateId,long IdleStartQpc,long IdleEndQpc,long Frequency,StagingHealth Before,StagingHealth After,bool Removed,bool Passed);
record StopRaceCheck(Child Child,ulong CandidateId,bool StopBlockedWhileClaimed,StagingHealth WhilePaused,StagingHealth AfterStop,int ReadHResult,uint ReadReturned,int ReadByte,int PostStopReadHResult,int RestartHResult,bool Passed);
sealed class LifecycleJournal:IDisposable
{
 readonly SafeFileHandle port;readonly FileStream binary;readonly StreamWriter json;
 internal List<LifecycleRow> Rows {get;}=[];
 internal LifecycleJournal(SafeFileHandle port,string root){this.port=port;binary=new(Path.Combine(root,"lifecycle.bin"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);json=new(new FileStream(Path.Combine(root,"lifecycle.jsonl"),FileMode.CreateNew,FileAccess.Write,FileShare.Read));}
 static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
 static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
 internal void Drain(){
  while(true){var input=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(input,4);BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(4),15);var b=new byte[112];
   int hr=Native.FilterSendMessage(port,input,8,b,112,out var n);if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;
   Marshal.ThrowExceptionForHR(hr);if(n!=112||U32(b,0)!=1||U32(b,4)!=112)throw new IOException("Invalid lifecycle row");
   uint flags=U32(b,20);var r=new LifecycleRow(U32(b,8),U32(b,12),U32(b,16),flags,U32(b,24),U32(b,28),U32(b,32),U32(b,36),U64(b,40),U64(b,48),(flags&2)!=0?U64(b,56):null,(flags&2)!=0?U64(b,64):null,(flags&4)!=0?U64(b,72):null,(flags&16)!=0?U64(b,80):null,U64(b,88),U64(b,96),U32(b,104));
   Rows.Add(r);binary.Write(b);json.WriteLine(JsonSerializer.Serialize(r));
  }
  binary.Flush(true);json.Flush();
 }
 internal bool Validate(StagingHealth h,IEnumerable<StagedCopy> copies,IdleExpiryCheck? expiry,StopRaceCheck? stop){
  if(h.NoticeLost!=0||h.NoticeQueued!=0||(ulong)Rows.Count!=h.NoticeSequence||Rows.Where((r,i)=>r.Sequence!=(ulong)i+1).Any())return false;
  foreach(var g in Rows.Where(r=>r.Id!=0).GroupBy(r=>r.Id)){
   if(g.Count(r=>r.Kind==1)!=1||g.First().Kind!=1||g.Count(r=>r.Kind is >=5 and <=10)!=1||g.Last().Kind is not (>=5 and <=10))return false;
  }
  foreach(var copy in copies.Where(c=>c.Passed)){
   var rows=Rows.Where(r=>r.Id==copy.CandidateId).ToArray();
   if(!new uint[]{1,2,3,4,5}.All(k=>rows.Count(r=>r.Kind==k)==1)||rows.Last().Kind!=5)return false;
   if(rows.Where(r=>r.Pid.HasValue).Any(r=>r.Pid!=(ulong)copy.Child.ProcessId||r.Created!=(ulong)copy.Child.CreatedFileTime))return false;
  }
  return expiry?.Passed==true&&Rows.Any(r=>r.Id==expiry.CandidateId&&r.Kind==6&&r.Reason==1)&&stop?.Passed==true&&Rows.Any(r=>r.Id==stop.CandidateId&&r.Kind==9);
 }
 internal static IdleExpiryCheck Expire(SafeFileHandle port,Func<StagingHealth> health,Action drain,Action traceDrain,string image){
  using var p=Process.Start(new ProcessStartInfo(image,"/d /c exit 0"){UseShellExecute=false,CreateNoWindow=true})??throw new IOException("Expiry child launch failed");var handle=p.Handle;
  var child=new Child("idle-expiry",p.Id,p.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
  if(!p.WaitForExit(15000)||p.ExitCode!=0)throw new IOException("Expiry child failed");drain();
  var slot=Staging.Table(port).Single(s=>s.Pid==(ulong)child.ProcessId&&s.Created==(ulong)child.CreatedFileTime&&s.Ready==1&&s.Exited==1);
  var before=health();long start=Stopwatch.GetTimestamp();
  // No staging reads, queries or ACKs during expiry. Command 7 only drains
  // unrelated image trace rows; its native handler never calls StSweep.
  // This keeps the diagnostic ring bounded on a busy live host without
  // driving candidate expiration from a retrieval or staging-health query.
  while(Stopwatch.GetTimestamp()-start<33*Stopwatch.Frequency){Thread.Sleep(1000);traceDrain();}
  long end=Stopwatch.GetTimestamp();var after=health();
  bool removed=!Staging.Table(port).Any(s=>s.Id==slot.Id);drain();
  bool passed=removed&&after.IdleSweeps>before.IdleSweeps&&after.IdleExpired>before.IdleExpired&&end-start>=32*Stopwatch.Frequency;
 return new(child,slot.Id,start,end,Stopwatch.Frequency,before,after,removed,passed);
 }
 internal static StopRaceCheck StopRace(SafeFileHandle port,Action<uint> send,Func<StagingHealth> health,Action drain,string image){
  using var p=Process.Start(new ProcessStartInfo(image,"/d /c exit 0"){UseShellExecute=false,CreateNoWindow=true})??throw new IOException("STOP fixture launch failed");var handle=p.Handle;
  var child=new Child("publication-stop",p.Id,p.StartTime.ToUniversalTime().ToFileTimeUtc(),image);
  if(!p.WaitForExit(15000)||p.ExitCode!=0)throw new IOException("STOP child failed");drain();
  var slot=Staging.Table(port).Single(s=>s.Pid==(ulong)child.ProcessId&&s.Created==(ulong)child.CreatedFileTime&&s.Ready==1&&s.Exited==1);
  var request=new byte[40];BinaryPrimitives.WriteUInt32LittleEndian(request,4);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),10);
  BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(8),(ulong)child.ProcessId);BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(16),(ulong)child.CreatedFileTime);BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(24),slot.Id);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(36),1);
  var bytes=new byte[121];send(16);
  var reader=Task.Factory.StartNew(()=>{var hr=Native.FilterSendMessage(port,request,40,bytes,121,out var n);return (Hr:hr,Bytes:n);},CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
  Task? stopper=null;
  try{
   var deadline=Stopwatch.GetTimestamp()+2*Stopwatch.Frequency;StagingHealth paused;
   do{paused=health();if(paused.TestPauseEntered==1)break;if(reader.IsCompleted||Stopwatch.GetTimestamp()>deadline)throw new IOException("Publication was not paused");Thread.Sleep(5);}while(true);
   stopper=Task.Factory.StartNew(()=>send(9),CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
   bool blocked=!stopper.Wait(200);paused=health();send(17);
   if(!reader.Wait(10000)||!stopper.Wait(10000))throw new TimeoutException("STOP publication did not drain");
   var after=health();var replay=new byte[121];int replayHr=Native.FilterSendMessage(port,request,40,replay,121,out _);
   var restart=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(restart,4);BinaryPrimitives.WriteUInt32LittleEndian(restart.AsSpan(4),6);int restartHr=Native.FilterSendMessage(port,restart,8,null,0,out _);
   var reply=reader.Result;bool passed=blocked&&paused.TestPauseEntered==1&&paused.PublicationInFlight==1&&paused.StopCompleted==0&&after.StopCompleted==1&&after.PublicationInFlight==0&&after.TestPauseTimedOut==0&&reply.Hr==0&&reply.Bytes==121&&bytes[120]==0x4D&&U64(bytes,32)==slot.Id&&replayHr<0&&restartHr<0;
   drain();return new(child,slot.Id,blocked,paused,after,reply.Hr,reply.Bytes,bytes[120],replayHr,restartHr,passed);
  }finally{send(17);reader.Wait(10000);stopper?.Wait(10000);}
 }
 public void Dispose(){json.Dispose();binary.Dispose();}
}
