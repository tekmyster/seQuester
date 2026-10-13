using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

if(WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned SYSTEM guest required");
if(args.Length==2&&args[0]=="--owned-parent")
{
    var marker=Path.GetFullPath(args[1]);if(File.Exists(marker)||File.Exists(marker+".release"))throw new IOException("Owned parent marker already exists");
    using var self=Process.GetCurrentProcess();
    using(var ready=new FileStream(marker+".partial",FileMode.CreateNew,FileAccess.Write,FileShare.None)){ready.Write(JsonSerializer.SerializeToUtf8Bytes(new{Pid=self.Id,Created=self.StartTime.ToUniversalTime().ToFileTimeUtc()}));ready.Flush(true);}File.Move(marker+".partial",marker,false);
    var wait=Stopwatch.StartNew();while(!File.Exists(marker+".release")){if(wait.ElapsedMilliseconds>90000)throw new TimeoutException("Owned parent release deadline exceeded");Thread.Sleep(100);}return;
}
if(args.Length!=1)throw new ArgumentException("New qualification output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var parent=Path.GetDirectoryName(root)!;var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);
var reports=Path.Combine(root,"reports");Directory.CreateDirectory(reports);var watched=Path.Combine(root,"designated-parent-read.bin");File.WriteAllBytes(watched,new byte[8192]);
var sid=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var directory=new DirectoryInfo(path);var acl=directory.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(sid,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));directory.SetAccessControl(acl);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var sensor=Guid.NewGuid().ToString("N");var checks=new List<string>();var collected=new ConcurrentDictionary<string,AgentEvent>();var health=new ConcurrentQueue<string>();var sync=new object();var spool=new EventSpool(capture,sensor);
void Check(bool value,string label){if(!value)throw new IOException(label);checks.Add(label);}
async Task Until(Func<bool> predicate,int seconds,string label){var clock=Stopwatch.StartNew();while(!predicate()){if(clock.Elapsed.TotalSeconds>seconds)throw new TimeoutException(label);await Task.Delay(100);}}
void Health(string message){health.Enqueue(message);lock(sync)File.AppendAllText(Path.Combine(capture,"health.jsonl"),JsonSerializer.Serialize(new{Utc=DateTimeOffset.UtcNow,Message=message})+"\n");}
void Persist(AgentEvent e)
{
    lock(sync)
    {
        if(e.Source=="Windows minifilter")
        {
            var raw=File.ReadAllBytes(Path.Combine(capture,"kernel-inbox",e.EventId+".record"));var folder=Path.Combine(capture,"kernel-raw");Directory.CreateDirectory(folder);var path=Path.Combine(folder,e.EventId+".bin");
            if(File.Exists(path)){if(!raw.AsSpan().SequenceEqual(File.ReadAllBytes(path)))throw new IOException("Raw archive differs");}else File.WriteAllBytes(path,raw);
        }
        spool.Enqueue(e);if(collected.TryAdd(e.EventId,e)){using var file=new FileStream(Path.Combine(capture,"events.jsonl"),FileMode.Append,FileAccess.Write,FileShare.Read);file.Write(JsonSerializer.SerializeToUtf8Bytes(e));file.WriteByte(10);file.Flush(true);}
    }
}
using var launcher=Process.GetCurrentProcess();var creatorPid=launcher.Id;var creatorCreated=launcher.StartTime.ToUniversalTime().ToFileTimeUtc();uint creatorTid=0,pid=0;long created=0;int parentPid=0;long parentCreated=0;
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var actorHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actorPath)));var original=SourceIdentityTruth.Capture(actorPath);
File.WriteAllText(Path.Combine(root,"source-identities.json"),JsonSerializer.Serialize(new{Schema="sequester.source-identity-ground-truth/v1",Actor=original,Probe=SourceIdentityTruth.Capture(Environment.ProcessPath!)}));
string? error=null;var passed=false;object? resources=null;string[] accepted=[];Process? parentProcess=null;Task<string>? parentError=null;
var parentMarker=Path.Combine(reports,"parent.json");
try
{
    await using(var pipeline=new ForensicPipeline(sensor,capture,Health))
    {
        void Publish(AgentEvent e,ActorLease? actor){var prepared=WindowsKernelSource.RestorePrepared(capture,e.EventId);if(prepared!=null){actor?.Dispose();Persist(prepared);return;}pipeline.Submit(e,new(),pending=>{WindowsKernelSource.SavePrepared(capture,pending);Persist(pending);},Persist,actor);}
        await using(var source=new WindowsKernelSource(sensor,capture,()=>[watched],e=>Publish(e,null),Health,Publish,captureStagedExecutables:true))
        {
            await Until(()=>File.Exists(Path.Combine(capture,"kernel-inbox","provider-checkpoint.json")),30,"Scope not ready");
            var parentStart=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};parentStart.ArgumentList.Add("--owned-parent");parentStart.ArgumentList.Add(parentMarker);
            parentProcess=Process.Start(parentStart)??throw new IOException("Owned parent failed to launch");var heldParent=parentProcess.Handle;parentPid=parentProcess.Id;parentCreated=parentProcess.StartTime.ToUniversalTime().ToFileTimeUtc();parentError=parentProcess.StandardError.ReadToEndAsync();
            await Until(()=>File.Exists(parentMarker)||parentProcess.HasExited,15,"Owned parent did not start");Check(!parentProcess.HasExited&&File.Exists(parentMarker),"independent parent is running");
            using var parentTruth=JsonDocument.Parse(File.ReadAllBytes(parentMarker));Check(parentTruth.RootElement.GetProperty("Pid").GetInt32()==parentPid&&parentTruth.RootElement.GetProperty("Created").GetInt64()==parentCreated,"designated parent reports its own independently matched PID/start");
            using var parentHandle=OwnedDesignatedActor.OpenParent(parentPid);Check(OwnedDesignatedActor.Times(parentHandle)==parentCreated&&parentPid!=creatorPid,"designated parent handle identifies a distinct retained process instance");
            var report=Path.Combine(reports,"impersonated-read.json");
            using(var actor=OwnedDesignatedActor.Start(actorPath,["impersonated-read",watched,report,"--exit-immediately"],parentHandle))
            {
                pid=actor.Pid;created=actor.Created;creatorTid=actor.CreatorTid;actor.Resume();Check(actor.Wait(15000)&&actor.ExitCode==0,"designated-parent actor completes within unchanged exit deadline");
                using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
                Check(t.GetProperty("ProcessId").GetUInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created&&t.GetProperty("PostOperationDelayMs").GetInt32()==0&&t.GetProperty("Outcome").GetString()=="Success","actor independently records its exact zero-dwell instance");
                await Until(()=>collected.Values.Any(e=>e.Source=="Forensic enrichment"&&e.ProcessId==pid&&e.Attribution?.WindowsKernel?.ProcessCreatedFileTime==created&&e.Attribution.WindowsKernel.Major==3),30,"Designated-parent read completion missing");
                var observations=collected.Values.Where(e=>e.Source=="Windows minifilter"&&e.ProcessId==pid&&e.Attribution?.WindowsKernel?.ProcessCreatedFileTime==created&&e.Attribution.WindowsKernel.Major==3).ToArray();
                foreach(var observed in observations)
                {
                    var k=observed.Attribution!.WindowsKernel!;var done=collected.Values.Single(e=>e.Source=="Forensic enrichment"&&e.Forensics?.RelatedEventId==observed.EventId);var f=done.Forensics!;var p=f.Process;var c=p.Creation;
                    Check(f.IsValid()&&WindowsKernelEvidence.Matches(done),"completed forensic event validates");
                    Check(k.ThreadId==t.GetProperty("ThreadId").GetUInt32()&&Token(k.RequestorPrimary,t.GetProperty("Primary"))&&Token(k.ThreadEffective,t.GetProperty("Effective")),"actual actor PID/start/thread owner and effective tokens match independently recorded values");
                    Check(c is {Status.State:"captured",CreatorStatus.State:"captured",FileOpenNameAvailable:true}&&c.CreatorPid==(ulong)creatorPid&&c.CreatorTid==creatorTid&&c.CreatorCreatedFileTime==creatorCreated,"creation callback identifies actual launcher and launch thread");
                    Check(c!.ReportedParentPid==(ulong)parentPid&&p.ParentPid==parentPid&&p.ParentStartKey==null&&p.ParentStartedUtc==null&&p.ParentInstanceId==null&&p.ParentExecutablePath==null&&c.ParentCreatedFileTime==null&&p.ParentStatus.State=="unavailable"&&p.ParentStatus.Reason=="creation-designated-parent-instance-unavailable","designated parent PID retained without fabricating its start/instance/path");
                    Check(p.CommandLine==t.GetProperty("CommandLine").GetString()&&p.CommandLineStatus.State=="captured"&&JsonSerializer.Serialize(observed.Forensics!.Process)==JsonSerializer.Serialize(p),"native actor command and process metadata survive immutable observation/completion");
                    Check(f.ActorExecutable.Sha256==actorHash&&f.Preservation.HashMatched==true&&f.ActorExecutable.File.StableId==original.StableId&&f.ActorExecutable.Acquisition?.Status.State=="captured","actor binary preservation and original identity survive designated parent relationship");
                }
                Check(observations.Length==1,"one controlled designated-parent read accepted");accepted=observations.Select(e=>e.EventId).ToArray();
                Check(!parentProcess.HasExited&&OwnedDesignatedActor.Times(parentHandle)==parentCreated,"designated parent remains independently held through evidence collection");
            }
            using(var release=new FileStream(parentMarker+".release",FileMode.CreateNew,FileAccess.Write,FileShare.Read)){release.WriteByte(1);release.Flush(true);}
            Check(parentProcess.WaitForExit(15000)&&parentProcess.ExitCode==0&&string.IsNullOrWhiteSpace(await parentError.WaitAsync(TimeSpan.FromSeconds(5))),"owned parent exits normally on release");
            await Until(()=>!Directory.EnumerateFiles(Path.Combine(capture,"kernel-inbox"),"*.record").Any()&&collected.Values.Count(e=>e.Source=="Windows minifilter")==collected.Values.Count(e=>e.Source=="Forensic enrichment"),20,"Intake did not drain");
        }
    }
    resources=NativeHealth.Read();Check(!health.Any(x=>x.StartsWith("Windows kernel diagnostic journal gap:",StringComparison.Ordinal)),"no native diagnostic gap reported");passed=true;
}
catch(Exception ex){error=ex.ToString();}
finally
{
    if(parentProcess!=null)
    {
        try{if(!parentProcess.HasExited){parentProcess.Kill();if(!parentProcess.WaitForExit(15000))throw new IOException("Owned parent cleanup deadline exceeded");}if(parentError!=null)File.WriteAllText(Path.Combine(reports,"parent.stderr.txt"),await parentError.WaitAsync(TimeSpan.FromSeconds(5)));}
        catch(Exception cleanup){passed=false;error+="; owned parent cleanup: "+cleanup;}
        finally{parentProcess.Dispose();}
    }
}
var result=new{Schema="sequester.windows-designated-parent-native/v1",RecordedUtc=DateTimeOffset.UtcNow,Sensor=sensor,Host=Environment.MachineName,AccountingPassed=passed,AllChildrenObserved=passed,Children=passed?1:0,Matches=accepted.Length,Pid=pid,Created=created,CreatorPid=creatorPid,CreatorTid=creatorTid,CreatorCreated=creatorCreated,DesignatedParentPid=parentPid,DesignatedParentCreated=parentCreated,ExpectedHash=actorHash,AcceptedEventIds=accepted,Checks=checks,NativeHealth=resources,Events=collected.Count,Completions=collected.Values.Count(e=>e.Source=="Forensic enrichment"),Preserved=collected.Values.Count(e=>e.Forensics?.Preservation.Status.State=="captured"),ByteCaptureImplemented=true,Error=error,ProductionReady=false,Scope="Real Windows designated-parent attribute, separately held creator/parent/actor truth; parent start intentionally unavailable in collected evidence. Server replay is separate."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{passed,error}));if(!passed)Environment.ExitCode=2;
static bool Token(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.ModifiedId==t.GetProperty("ModifiedId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static class NativeHealth
{
    internal static object Read()
    {
        Marshal.ThrowExceptionForHR(FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));using(port)
        {
            byte[] Get(uint command,int length){var b=new byte[length];Marshal.ThrowExceptionForHR(FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,b,(uint)length,out var n));if(n!=length)throw new IOException("Health reply size differs");return b;}
            var d=Get(8,72);var s=Get(12,224);var b=Get(20,88);var h=Get(3,48);var a=Get(24,48);var p=Get(28,48);
            uint N(byte[] value,int offset)=>WindowsStagedActorProtocol.U32(value,offset);ulong Q(byte[] value,int offset)=>WindowsStagedActorProtocol.U64(value,offset);
            if(Q(d,24)!=0||Q(d,32)!=0||Q(d,40)!=Q(d,48)||N(d,56)!=0||Q(s,24)!=0||N(s,12)!=0||N(s,16)!=0||Q(s,96)!=0||Q(s,192)!=0||N(s,212)!=1||Q(b,40)!=Q(b,48)||Q(b,72)!=Q(b,80)||Q(b,56)!=0||N(b,64)!=0||Q(h,24)!=0||N(h,40)!=0||N(a,16)!=0||N(a,20)!=0||Q(a,32)!=0||Q(a,40)!=0||N(p,12)!=0||Q(p,16)==0||Q(p,16)!=Q(p,24)||Q(p,32)!=0)throw new IOException("Native resource/loss accounting failed");
            return new{Diagnostic=Convert.ToHexString(d),Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(b),Operations=Convert.ToHexString(h),Admission=Convert.ToHexString(a),ProcessCreation=Convert.ToHexString(p)};
        }
    }
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]private static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]private static extern int FilterSendMessage(SafeFileHandle port,byte[] request,uint size,[Out]byte[] reply,uint capacity,out uint returned);
}
