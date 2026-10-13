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
var parent=Path.GetDirectoryName(root)!;var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);
var target=Path.Combine(root,"delayed-impersonated-read.bin");File.WriteAllBytes(target,new byte[8192]);
var reports=Path.Combine(root,"reports");Directory.CreateDirectory(reports);
var sid=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var d=new DirectoryInfo(path);var a=d.GetAccessControl();a.AddAccessRule(new FileSystemAccessRule(sid,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));d.SetAccessControl(a);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var sensor=Guid.NewGuid().ToString("N");var checks=new List<string>();var health=new List<string>();var observations=new List<AgentEvent>();var completions=new List<AgentEvent>();
void Check(bool yes,string label){if(!yes)throw new IOException(label);checks.Add(label);}
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var expected=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actorPath)));
string? error=null;bool passed=false;object? resources=null;int pid=0;long created=0;int diagnosticRecords=0,backgroundOperations=0;
try
{
    Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
    using(port)
    {
        byte[] Send(byte[] request,int length){var output=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,(uint)request.Length,output,(uint)length,out var n));if(n!=length)throw new IOException("Native reply length differs");return output;}
        void Reject(byte[] request,int length,string label){Check(Native.FilterSendMessage(port,request,(uint)request.Length,new byte[length],(uint)length,out _) < 0,label);}
        byte[] Get(uint command,int length)=>Send(WindowsStagedActorProtocol.Message(command),length);
        void Drain()
        {
            foreach(var item in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
            {
                using var output=new FileStream(Path.Combine(capture,item.Item3+".journal"),FileMode.Append,FileAccess.Write,FileShare.Read);
                for(int i=0;i<1024;i++){var bytes=new byte[item.Item2];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(item.Item1),8,bytes,(uint)bytes.Length,out var n);if(hr<0){if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;Marshal.ThrowExceptionForHR(hr);}if(n!=bytes.Length)throw new IOException("Diagnostic record length differs");diagnosticRecords++;output.Write(bytes);}
            }
        }
        Get(6,0);var binding=Get(20,88);var provider=Convert.ToHexString(binding.AsSpan(8,16));
        var nativeDrive=new StringBuilder(32768);Check(Native.QueryDosDevice(target[..2],nativeDrive,nativeDrive.Capacity)>0,"native target drive resolved");
        var nativeTarget=nativeDrive+target[2..];var scope=WindowsStagedActorProtocol.Message(5,1548);WindowsStagedActorProtocol.Put32(scope,8,1);Encoding.Unicode.GetBytes(nativeTarget).CopyTo(scope,12);Send(scope,0);
        var report=Path.Combine(reports,"impersonated-read.json");var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};
        foreach(var arg in new[]{"impersonated-read",target,report,"--exit-immediately"})start.ArgumentList.Add(arg);start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";
        using(var child=Process.Start(start)!)
        {var owned=child.Handle;pid=child.Id;created=child.StartTime.ToUniversalTime().ToFileTimeUtc();var stderr=child.StandardError.ReadToEndAsync();Check(child.WaitForExit(15000)&&child.ExitCode==0,"zero-dwell impersonated actor exited successfully");if(child.ExitCode!=0)throw new IOException(await stderr);}
        using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
        Check(t.GetProperty("ProcessId").GetInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created&&t.GetProperty("PostOperationDelayMs").GetInt32()==0,"fixture identity and immediate exit established");
        // No actor-byte request is sent until well beyond the 30-second table TTL.
        var delay=Stopwatch.StartNew();while(delay.Elapsed<TimeSpan.FromSeconds(36)){Drain();await Task.Delay(250);}
        var intake=new WindowsStagedActorStore(capture,sensor);var collector=new ForensicCollector(sensor,capture);
        var inbox=Path.Combine(capture,"kernel-inbox");Directory.CreateDirectory(inbox);var rawRoot=Path.Combine(capture,"kernel-raw");Directory.CreateDirectory(rawRoot);
        for(int records=0;records<100;records++)
        {
            var raw=new byte[3800];var hr=Native.FilterSendMessage(port,WindowsStagedActorProtocol.Message(2),8,raw,3800,out var n);
            if(hr<0){if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;Marshal.ThrowExceptionForHR(hr);}
            Check(n==3800,"operation packet has v4 size");
            var e=WindowsKernelDecoder.Decode(raw,sensor,p=>p.StartsWith(nativeDrive.ToString()+"\\",StringComparison.OrdinalIgnoreCase)?target[..2]+p[nativeDrive.Length..]:p,false);
            if(e.ProcessId!=pid||e.Attribution!.WindowsKernel!.ProcessCreatedFileTime!=created)
            {
                // Other actors may inspect the test file. Retain their raw evidence
                // separately; they cannot satisfy this fixture's ground truth.
                File.WriteAllBytes(Path.Combine(rawRoot,e.EventId+".bin"),raw);
                File.AppendAllText(Path.Combine(capture,"background.jsonl"),JsonSerializer.Serialize(e)+"\n");backgroundOperations++;
                var backgroundAck=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(backgroundAck.AsSpan(8));Send(backgroundAck,0);Drain();continue;
            }
            Check(e.ProcessId==pid&&e.Attribution!.WindowsKernel!.ProcessCreatedFileTime==created,"queued operation remains bound to original process instance");
            var a=WindowsStagedActorProtocol.Companion(Send(WindowsStagedActorProtocol.CompanionRequest(e,provider),88),e,provider);
            Check(a.BindingKind=="bytes-pinned","queued operation retained its independent actor byte pin");
            Reject(WindowsStagedActorProtocol.CandidateRequest(a,13),144,"candidate table lookup expired before operation retrieval");
            var request=WindowsStagedActorProtocol.OperationRequest(a,13);
            foreach(var offset in new[]{0,8,24,32,40,48,68,72,80}){var wrong=(byte[])request.Clone();wrong[offset]^=0x40;Reject(wrong,144,"pinned lookup rejects changed key field "+offset);}
            var oversized=WindowsStagedActorProtocol.OperationRequest(a,10,0,65537);Reject(oversized,144+65537,"oversized pinned read rejected");
            using var lease=intake.Capture(e,provider,Send,health.Add);
            var observed=e with{Forensics=collector.Begin(e,lease)};var f=collector.Complete(e,lease,observed.Forensics!,new());var completionId=Guid.NewGuid().ToString("N");
            var completed=e with{EventId=completionId,Source="Forensic enrichment",Forensics=collector.LinkCompletion(f,completionId)};
            Check(f.IsValid()&&f.Preservation.HashMatched==true&&f.ActorExecutable.Sha256==expected,"expired-table operation preserves exact executable bytes");
            if(e.Attribution!.WindowsKernel!.Major==3)
            {
                var k=e.Attribution.WindowsKernel;
                Check(k.ThreadId==t.GetProperty("ThreadId").GetUInt32()&&TokenMatches(k.RequestorPrimary,t.GetProperty("Primary"))&&TokenMatches(k.ThreadEffective,t.GetProperty("Effective")),"delayed read preserves exact process owner and impersonated accessing-thread token");
            }
            var journal=Path.Combine(inbox,e.EventId+".record");using(var file=new FileStream(journal,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){file.Write(raw);file.Flush(true);}
            File.WriteAllBytes(Path.Combine(rawRoot,e.EventId+".bin"),raw);intake.AcknowledgeAfterJournal(e,journal,Send,health.Add);
            observations.Add(observed);completions.Add(completed);
            File.AppendAllText(Path.Combine(capture,"events.jsonl"),JsonSerializer.Serialize(observed)+"\n"+JsonSerializer.Serialize(completed)+"\n");
            var ack=WindowsStagedActorProtocol.Message(4,24);raw.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(ack,0);
            Reject(request,144,"acknowledged operation pin cannot be replayed against next queue head");Drain();
        }
        Check(observations.Any(e=>e.Attribution!.WindowsKernel!.Major==3),"required delayed impersonated read observed");
        Get(9,0);Drain();var s=Get(12,224);var b=Get(20,88);var h=Get(3,48);
        resources=new{Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(b),Operations=Convert.ToHexString(h)};
        Check(WindowsStagedActorProtocol.U64(s,24)==0&&WindowsStagedActorProtocol.U32(s,16)==0&&WindowsStagedActorProtocol.U32(s,12)==0&&WindowsStagedActorProtocol.U64(s,96)==0&&WindowsStagedActorProtocol.U64(s,192)==0,"native bytes, capacity and lifecycle journal balanced");
        Check(WindowsStagedActorProtocol.U64(b,40)==WindowsStagedActorProtocol.U64(b,48)&&WindowsStagedActorProtocol.U64(b,72)==WindowsStagedActorProtocol.U64(b,80)&&WindowsStagedActorProtocol.U64(h,24)==0&&WindowsStagedActorProtocol.U32(h,40)==0,"process references and operation pins released without operation loss");
        passed=true;
    }
}
catch(Exception ex){error=ex.ToString();}
var result=new{Schema="sequester.windows-pinned-actor-delay/v1",AccountingPassed=passed,AllChildrenObserved=passed,Children=observations.Any()?1:0,Matches=completions.Count,ByteCaptureImplemented=true,DelaySeconds=36,Sensor=sensor,Pid=pid,Created=created,ExpectedHash=expected,Observations=observations.Count,Completions=completions.Count,DiagnosticRecords=diagnosticRecords,BackgroundOperations=backgroundOperations,Checks=checks,Health=health,Resources=resources,Error=error,ProductionReady=false};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{passed,result.Observations,error}));if(!passed)Environment.ExitCode=2;
static bool TokenMatches(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static class Native
{
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]internal static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}
