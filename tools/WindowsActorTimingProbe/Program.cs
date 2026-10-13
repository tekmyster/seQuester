using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client;
using RansomFree.Client.Forensics;

if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned SYSTEM guest/new output required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var reports=Path.Combine(root,"reports");Directory.CreateDirectory(reports);var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);
var actor=Path.Combine(Path.GetDirectoryName(root)!,"reader","actor","WindowsActorFixture.exe");var target=Path.Combine(root,"timing-read.bin");File.WriteAllBytes(target,new byte[8192]);
var sensor=Guid.NewGuid().ToString("N");var runs=new List<object>();var stages=new List<object>();var observations=0;bool passed=false;string? error=null;object? resources=null;
try
{
 Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
 using(port)
 {
  byte[] Get(uint command,int size){var b=new byte[size];var request=WindowsStagedActorProtocol.Message(command);Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,8,b,(uint)size,out var n));if(n!=size)throw new IOException("Health size");return b;}
  void Send(byte[] request){Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,(uint)request.Length,[],0,out var n));if(n!=0)throw new IOException("Unexpected reply");}
  void Drain(bool operations)
  {
   foreach(var (command,length,name) in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
   {
    using var file=new FileStream(Path.Combine(capture,name+".journal"),FileMode.Append,FileAccess.Write,FileShare.Read);
    for(var i=0;i<256;i++){var b=new byte[length];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,b,(uint)length,out var n);if(Empty(hr))break;Marshal.ThrowExceptionForHR(hr);if(n!=length)throw new IOException("Journal size");file.Write(b);}
    file.Flush(true);
   }
   if(!operations)return;
   for(var i=0;i<256;i++)
   {
    var raw=new byte[3800];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(2),8,raw,3800,out var n);if(Empty(hr))break;Marshal.ThrowExceptionForHR(hr);if(n!=3800)throw new IOException("Operation size");
    var e=WindowsKernelDecoder.Decode(raw,sensor,p=>p,false);using(var file=new FileStream(Path.Combine(capture,e.EventId+".record"),FileMode.CreateNew,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough)){file.Write(raw);file.Flush(true);}
    observations++;var ack=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(ack);
   }
  }
  if(WindowsStagedActorProtocol.U32(Get(12,224),8)!=0)throw new IOException("Staging must start disabled");
  foreach(var mode in new[]{"loaded-staging-disabled","staging-enabled-no-drain","staging-enabled-with-drain"})
  {
   if(mode=="staging-enabled-no-drain")
   {
    var device=new StringBuilder(32768);if(Native.QueryDosDevice(target[..2],device,device.Capacity)==0)throw new IOException("Device mapping");
    var scope=WindowsStagedActorProtocol.Message(5,1548);WindowsStagedActorProtocol.Put32(scope,8,1);Encoding.Unicode.GetBytes(device+target[2..]).CopyTo(scope,12);Send(scope);Get(6,0);
   }
   for(var iteration=0;iteration<3;iteration++)
   {
    var report=Path.Combine(reports,mode+"-"+iteration+".json");var start=new ProcessStartInfo(actor){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden};foreach(var a in new[]{"read",target,report,"--exit-immediately"})start.ArgumentList.Add(a);
    var clock=Stopwatch.StartNew();var mono=Stopwatch.GetTimestamp();var launchUtc=DateTimeOffset.UtcNow;
    using var child=Process.Start(start)??throw new IOException("Child launch");var launchMs=clock.Elapsed.TotalMilliseconds;var owned=child.Handle;var pid=child.Id;var created=child.StartTime.ToUniversalTime().ToFileTimeUtc();
    while(!child.WaitForExit(100)){if(mode=="staging-enabled-with-drain")Drain(false);if(clock.Elapsed>TimeSpan.FromSeconds(60)){child.Kill();throw new TimeoutException("Measurement limit; not an acceptance threshold");}}
    var exitMs=clock.Elapsed.TotalMilliseconds;if(child.ExitCode!=0)throw new IOException("Actor exit failed");using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
    if(t.GetProperty("ProcessId").GetInt32()!=pid||t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()!=created||t.GetProperty("PostOperationDelayMs").GetInt32()!=0||t.GetProperty("Outcome").GetString()!="Success")throw new IOException("Actor ground truth mismatch");
    var begin=t.GetProperty("StartedUtc").GetDateTimeOffset();var end=t.GetProperty("CompletedUtc").GetDateTimeOffset();
    var row=new{Mode=mode,Iteration=iteration,Pid=pid,Created=created,LaunchUtc=launchUtc,MonotonicStart=mono,MonotonicFrequency=Stopwatch.Frequency,ProcessStartCallMs=launchMs,ChildExitElapsedMs=exitMs,StartupMs=(begin-DateTimeOffset.FromFileTime(created)).TotalMilliseconds,OperationMs=(end-begin).TotalMilliseconds,ExitedWithinOriginal15SecondWait=(exitMs-launchMs)<=15000};runs.Add(row);
    File.AppendAllText(Path.Combine(root,"timings.jsonl"),JsonSerializer.Serialize(row)+"\n");
    // Always save/ack actual operations; this is not a preservation acceptance test.
    Drain(true);
   }
   stages.Add(new{Mode=mode,Staging=Convert.ToHexString(Get(12,224)),Admission=Convert.ToHexString(Get(24,48))});
  }
  Get(9,0);Drain(true);var s=Get(12,224);var b=Get(20,88);var h=Get(3,48);
  resources=new{Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(b),Operations=Convert.ToHexString(h)};
  if(WindowsStagedActorProtocol.U64(s,24)!=0||WindowsStagedActorProtocol.U32(s,12)!=0||WindowsStagedActorProtocol.U32(s,16)!=0||WindowsStagedActorProtocol.U64(s,96)!=0||WindowsStagedActorProtocol.U64(s,192)!=0||WindowsStagedActorProtocol.U64(b,56)!=0||WindowsStagedActorProtocol.U64(b,40)!=WindowsStagedActorProtocol.U64(b,48)||WindowsStagedActorProtocol.U64(b,72)!=WindowsStagedActorProtocol.U64(b,80)||WindowsStagedActorProtocol.U64(h,24)!=0||WindowsStagedActorProtocol.U32(h,40)!=0)throw new IOException("Resource/loss accounting failed; retain timing evidence");
  passed=true;
 }
}
catch(Exception ex){error=ex.ToString();}
var result=new{Schema="sequester.windows-actor-startup-diagnostic/v1",AccountingPassed=passed,AllChildrenObserved=runs.Count==9,Children=runs.Count,Matches=runs.Count,ByteCaptureImplemented=true,Runs=runs,Stages=stages,Resources=resources,Observations=observations,Error=error,ProductionReady=false,Scope="Diagnostic measurements only; fixed mode order and warm-cache effects do not establish causality or the 15-second acceptance gate"};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{passed,result.Children,error}));if(!passed)Environment.ExitCode=2;
static bool Empty(int hr)=>hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A);
static class Native
{
 [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
 [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]internal static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
