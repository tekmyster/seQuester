using System.Buffers.Binary;
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

if(args.Length!=1||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new ArgumentException("Owned SYSTEM guest and new output directory required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output exists");Directory.CreateDirectory(root);
var parent=Path.GetDirectoryName(root)!;var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);
var watched=Path.Combine(root,"first-touch-after-expiry.bin");File.WriteAllBytes(watched,new byte[8192]);
var reports=Path.Combine(root,"reports");Directory.CreateDirectory(reports);
var sid=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var d=new DirectoryInfo(path);var a=d.GetAccessControl();a.AddAccessRule(new FileSystemAccessRule(sid,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));d.SetAccessControl(a);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(root,FileSystemRights.ReadAndExecute);Grant(reports,FileSystemRights.Modify);
var sensor=Guid.NewGuid().ToString("N");var checks=new List<string>();var health=new ConcurrentQueue<string>();var collected=new ConcurrentDictionary<string,AgentEvent>();var gate=new object();
var spool=new EventSpool(capture,sensor);
void Check(bool yes,string label){if(!yes)throw new IOException(label);checks.Add(label);}
void Health(string text){health.Enqueue(text);lock(gate)File.AppendAllText(Path.Combine(capture,"health.jsonl"),JsonSerializer.Serialize(new{Utc=DateTimeOffset.UtcNow,Message=text})+Environment.NewLine);}
async Task Until(Func<bool> predicate,TimeSpan timeout,string message){var watch=Stopwatch.StartNew();while(!predicate()){if(watch.Elapsed>timeout)throw new TimeoutException(message);await Task.Delay(100);}}
void Persist(AgentEvent e)
{
    lock(gate)
    {
        if(e.Source=="Windows minifilter")
        {
            var raw=File.ReadAllBytes(Path.Combine(capture,"kernel-inbox",e.EventId+".record"));var folder=Path.Combine(capture,"kernel-raw");Directory.CreateDirectory(folder);
            var file=Path.Combine(folder,e.EventId+".bin");if(File.Exists(file)){if(!File.ReadAllBytes(file).SequenceEqual(raw))throw new IOException("Raw archive differs");}else File.WriteAllBytes(file,raw);
        }
        spool.Enqueue(e);if(collected.TryAdd(e.EventId,e)){using var stream=new FileStream(Path.Combine(capture,"events.jsonl"),FileMode.Append,FileAccess.Write,FileShare.Read);stream.Write(JsonSerializer.SerializeToUtf8Bytes(e));stream.WriteByte(10);stream.Flush(true);}
    }
}
string? error=null;bool passed=false;object? resources=null;int pid=0;long created=0;string? processRecord=null;string[] accepted=[];
var phases=new List<object>();
void Phase(string name)=>phases.Add(new{Phase=name,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Frequency=Stopwatch.Frequency});
using var creator=Process.GetCurrentProcess();var creatorPid=creator.Id;var creatorCreated=creator.StartTime.ToUniversalTime().ToFileTimeUtc();uint creatorTid=0;
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var expected=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actorPath)));
var originalIdentity=SourceIdentityTruth.Capture(actorPath);
File.WriteAllText(Path.Combine(root,"source-identities.json"),JsonSerializer.Serialize(new{Schema="sequester.source-identity-ground-truth/v1",Actor=originalIdentity,Probe=SourceIdentityTruth.Capture(Environment.ProcessPath!)}));
try
{
    await using(var pipeline=new ForensicPipeline(sensor,capture,Health))
    {
        void Publish(AgentEvent e,ActorLease? actor)
        {
            var prepared=WindowsKernelSource.RestorePrepared(capture,e.EventId);if(prepared!=null){actor?.Dispose();Persist(prepared);return;}
            pipeline.Submit(e,new(),pending=>{WindowsKernelSource.SavePrepared(capture,pending);Persist(pending);},Persist,actor);
        }
        await using(var source=new WindowsKernelSource(sensor,capture,()=>[watched],e=>Publish(e,null),Health,Publish,captureStagedExecutables:true,captureProactiveExecutables:true))
        {
            await Until(()=>File.Exists(Path.Combine(capture,"kernel-inbox","provider-checkpoint.json")),TimeSpan.FromSeconds(30),"Scope not ready");
            var report=Path.Combine(reports,"impersonated-read.json");var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};
            foreach(var argument in new[]{"impersonated-read",watched,report,"--exit-immediately"})start.ArgumentList.Add(argument);
            start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";start.Environment["SQ_FIXTURE_PRE_OPERATION_DELAY_MS"]="34000";
            Phase("before-process-start");creatorTid=Native.GetCurrentThreadId();using var child=Process.Start(start)??throw new IOException("Actor launch failed");Phase("after-process-start");var handle=child.Handle;pid=child.Id;created=child.StartTime.ToUniversalTime().ToFileTimeUtc();var stderr=child.StandardError.ReadToEndAsync();
            try
            {
                Phase("before-ready-wait");await Until(()=>File.Exists(report+".ready.json")||child.HasExited,TimeSpan.FromSeconds(15),"Delayed actor did not start");Phase("after-ready-wait");
                Check(File.Exists(report+".ready.json"),"actor reached its managed ready marker within the startup deadline");
                await Until(()=>
                {
                    foreach(var file in Directory.EnumerateFiles(Path.Combine(capture,"kernel-actor-intake"),"*.process.json"))
                    {
                        using var json=JsonDocument.Parse(File.ReadAllBytes(file));var r=json.RootElement;var key=r.GetProperty("Ready");
                        if(key.GetProperty("Pid").GetInt32()==pid&&key.GetProperty("Created").GetInt64()==created&&r.GetProperty("State").GetString()=="captured"){processRecord=file;return true;}
                    }
                    return false;
                },TimeSpan.FromSeconds(25),"No proactive commit before first touch");
                Phase("proactive-commit-observed");
                Check(!collected.Values.Any(e=>e.Source=="Windows minifilter"&&e.ProcessId==pid),"actor snapshot committed before any observed honeypot operation by that process");
                Phase("before-exit-wait");Check(child.WaitForExit(45000)&&child.ExitCode==0,"delayed impersonated actor completes without post-operation dwell");Phase("after-exit-wait");
                Check(string.IsNullOrWhiteSpace(await stderr),"actor has no error output");
                await Until(()=>collected.Values.Any(e=>e.Source=="Forensic enrichment"&&e.ProcessId==pid&&e.Attribution!.WindowsKernel!.Major==3),TimeSpan.FromSeconds(30),"First delayed read completion missing");
                using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
                using var readyTime=JsonDocument.Parse(File.ReadAllBytes(report+".ready.json"));var timing=readyTime.RootElement;
                Check(t.GetProperty("PreOperationDelayMs").GetInt32()==34000&&t.GetProperty("PostOperationDelayMs").GetInt32()==0&&t.GetProperty("ProcessId").GetInt32()==pid&&t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()==created,"fixture ground truth establishes delay and exact process instance");
                using var receipt=JsonDocument.Parse(File.ReadAllBytes(processRecord!));var saved=receipt.RootElement;
                var observations=collected.Values.Where(e=>e.Source=="Windows minifilter"&&e.ProcessId==pid&&e.Attribution?.WindowsKernel?.ProcessCreatedFileTime==created&&e.Attribution.WindowsKernel.Major==3).ToArray();
                foreach(var observation in observations)
                {
                    var k=observation.Attribution!.WindowsKernel!;var completion=collected.Values.Single(e=>e.Source=="Forensic enrichment"&&e.Forensics?.RelatedEventId==observation.EventId);var f=completion.Forensics!;
                    Check(timing.GetProperty("Pid").GetInt32()==pid&&timing.GetProperty("Created").GetInt64()==created&&k.MonotonicFrequency==timing.GetProperty("Frequency").GetInt64()&&k.MonotonicTicks-timing.GetProperty("Monotonic").GetInt64()>=33*k.MonotonicFrequency,"monotonic first-touch delay exceeds the 30-second native byte TTL");
                    Check(TokenMatches(k.ThreadEffective,t.GetProperty("Effective"))&&TokenMatches(k.RequestorPrimary,t.GetProperty("Primary"))&&k.ThreadId==t.GetProperty("ThreadId").GetUInt32(),"first delayed read retains its actual impersonated thread and process owner tokens");
                    Check(f.IsValid()&&WindowsKernelEvidence.Matches(completion)&&f.ActorExecutable.Acquisition is {Status.State:"captured",BindingKind:"process-generation-only"} a&&a.SnapshotId==saved.GetProperty("SnapshotId").GetString()&&a.PersistedUtc==saved.GetProperty("RecordedUtc").GetDateTimeOffset()&&a.PersistedUtc<observation.ObservedUtc&&f.ActorExecutable.Sha256==expected&&f.Preservation.HashMatched==true,"first post-expiry read uses the prior verified process snapshot and preserves exact actor bytes");
                    Check(f.ActorExecutable.File.StableId==originalIdentity.StableId&&f.ActorExecutable.Acquisition!.SourceIdentityStatus.State=="captured"&&f.ActorExecutable.Acquisition.SnapshotFile!.StableId!=originalIdentity.StableId,"original source volume and file index match independent Win32 ground truth and differ from private copy identity");
                    Check(f.Process.CommandLine==t.GetProperty("CommandLine").GetString()&&f.Process.CommandLineStatus.State=="captured"&&f.Process.Creation is {Status.State:"captured",CreatorStatus.State:"captured",FileOpenNameAvailable:true} pm&&pm.CreatorPid==(ulong)creatorPid&&pm.CreatorTid==creatorTid&&pm.CreatorCreatedFileTime==creatorCreated&&f.Process.ParentPid==creatorPid&&f.Process.ParentStartKey==creatorCreated.ToString(),"delayed first touch retains exact native command and creator/parent instance from proactive acquisition");
                    var creation=saved.GetProperty("Creation");var raw=Convert.FromBase64String(creation.GetProperty("Raw").GetString()!);
                    Check(raw.Length==WindowsProcessCreationProtocol.ReplyBytes&&Convert.ToHexString(SHA256.HashData(raw))==creation.GetProperty("Sha256").GetString()&&f.Process.Creation!.RawSha256==creation.GetProperty("Sha256").GetString()&&WindowsStagedActorProtocol.U64(raw,64)==0&&WindowsStagedActorProtocol.U64(raw,72)==0,"proactive creation proof is event-independent, hash-verified and reused without rebinding");
                    Check(JsonSerializer.Serialize(observation.Forensics!.Process)==JsonSerializer.Serialize(f.Process),"observation and completion retain identical process-creation evidence");
                }
                Check(observations.Length==1,"one controlled delayed read matched");accepted=observations.Select(e=>e.EventId).ToArray();
                await Until(()=>!Directory.EnumerateFiles(Path.Combine(capture,"kernel-inbox"),"*.record").Any()&&collected.Values.Count(e=>e.Source=="Windows minifilter")==collected.Values.Count(e=>e.Source=="Forensic enrichment"),TimeSpan.FromSeconds(20),"Intake did not drain");
            }
            catch(Exception failure)
            {
                Phase("owned-actor-check-failed");
                OwnedChildDiagnostics.Save(child,pid,created,report,failure);
                throw;
            }
            finally
            {
                if(!child.HasExited){child.Kill();if(!child.WaitForExit(15000))throw new IOException("Owned proactive actor did not exit");}
                File.WriteAllText(report+".stderr.txt",await stderr);
                Phase("owned-actor-cleanup-complete");
            }
        }
    }
    resources=NativeHealth(capture,sensor,processRecord!,DateTimeOffset.UtcNow);
    if(health.Any(x=>x.StartsWith("Windows kernel diagnostic journal gap:",StringComparison.Ordinal)||x.StartsWith("Proactive actor ready-feed gap:",StringComparison.Ordinal)||x.StartsWith("Proactive actor ready-feed unavailable:",StringComparison.Ordinal)||x.StartsWith("Proactive actor acknowledgement retry unavailable:",StringComparison.Ordinal)))throw new IOException("Acquisition, acknowledgement or diagnostic gap reported");
    passed=true;
}
catch(Exception ex)
{
    error=ex.ToString();Phase("qualification-failed");
    try{File.WriteAllText(Path.Combine(capture,"native-failure-health.json"),JsonSerializer.Serialize(Native.FailureHealth()));}
    catch(Exception diagnostic){File.WriteAllText(Path.Combine(capture,"native-failure-health-error.txt"),diagnostic.ToString());}
}
File.WriteAllText(Path.Combine(root,"probe-phases.json"),JsonSerializer.Serialize(phases,new JsonSerializerOptions{WriteIndented=true}));
var result=new{Schema="sequester.windows-proactive-acquisition-native/v1",RecordedUtc=DateTimeOffset.UtcNow,Host=Environment.MachineName,Sensor=sensor,AccountingPassed=passed,AllChildrenObserved=passed,Children=passed?1:0,Matches=accepted.Length,Pid=pid,Created=created,CreatorPid=creatorPid,CreatorTid=creatorTid,CreatorCreated=creatorCreated,ExpectedHash=expected,ProcessRecord=processRecord,AcceptedEventIds=accepted,Checks=checks,NativeHealth=resources,Events=collected.Count,Completions=collected.Values.Count(e=>e.Source=="Forensic enrichment"),Preserved=collected.Values.Count(e=>e.Forensics?.Preservation.Status.State=="captured"),ByteCaptureImplemented=true,ProductionReady=false,Error=error,Scope="One actual first impersonated file read after 34-second delay, proactive immutable process snapshot, creation metadata, raw operation-time tokens and preservation. Full matrix/server delivery remain separate."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{result.AccountingPassed,result.Children,result.Error}));if(!passed)Environment.ExitCode=2;

static bool TokenMatches(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.ModifiedId==t.GetProperty("ModifiedId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static object NativeHealth(string capture,string sensor,string controlledRecord,DateTimeOffset sourceStoppedUtc)
{
    Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
    using(port)
    {
        byte[] Get(uint command,int size){var request=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(request,4);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),command);var b=new byte[size];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,8,b,(uint)size,out var n));if(n!=size)throw new IOException("Native health length mismatch");return b;}
        ulong Q(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));uint N(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
        var receipts=Directory.GetFiles(Path.Combine(capture,"kernel-actor-intake"),"*.ack");if(receipts.Length==0)throw new IOException("Proactive durable candidate acknowledgement receipt missing");
        var acknowledgementProof=ProactiveAckProof.Verify(capture,sensor,controlledRecord,sourceStoppedUtc);
        var replayed=0;var rejected=0;
        foreach(var receipt in receipts)
        {
            var request=File.ReadAllBytes(receipt);if(request.Length!=160)throw new IOException("Invalid saved durable receipt");
            for(var retry=0;retry<2;retry++){var reply=new byte[160];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,160,reply,160,out var n));if(n!=160||!reply.AsSpan().SequenceEqual(request))throw new IOException("Native durable ACK retry changed");replayed++;}
            foreach(var offset in new[]{8,24,32,40,48,68,72,80,112,128})
            {
                var invalid=(byte[])request.Clone();invalid[offset]^=0x40;var reply=new byte[160];
                if(Native.FilterSendMessage(port,invalid,160,reply,160,out _)>=0)throw new IOException("Native accepted contradictory durable ACK offset "+offset);rejected++;
            }
        }
        var d=Get(8,72);var s=Get(12,224);var p=Get(20,88);var h=Get(3,48);var admission=Get(24,48);var creation=Get(28,48);
        var ordinaryCommands=OrdinaryCommandsProof.Verify(port,p,Path.Combine(capture,"ordinary-commands.jsonl"));
        var result=new{Diagnostic=Convert.ToHexString(d),Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(p),Operations=Convert.ToHexString(h),Admission=Convert.ToHexString(admission),ProcessCreation=Convert.ToHexString(creation),DurableReceiptReplays=replayed,RejectedAcknowledgements=rejected,CommittedAckIntents=acknowledgementProof.Rows.Length,ConfirmedAckOutcomes=acknowledgementProof.Confirmed,PendingAckIntents=acknowledgementProof.Pending,NonConfirmedAckOutcomes=acknowledgementProof.NonConfirmed,AcknowledgementProof=acknowledgementProof,OrdinaryCommands=ordinaryCommands};
        File.WriteAllText(Path.Combine(capture,"native-final-health.json"),JsonSerializer.Serialize(result));
        if(N(creation,0)!=1||N(creation,4)!=48||N(creation,8)!=256||N(creation,12)!=0||Q(creation,16)==0||Q(creation,16)!=Q(creation,24)||Q(creation,32)!=0)throw new IOException("Proactive creation metadata allocation accounting failed");
        if(N(admission,0)!=1||N(admission,4)!=48||N(admission,8)!=32||N(admission,12)!=16||N(admission,16)!=0||N(admission,20)!=0||N(admission,24)>32||N(admission,28)>16||Q(admission,32)!=0||Q(admission,40)!=0)throw new IOException("Separate qualification/copy admission accounting failed");
        if(Q(d,24)!=0||Q(d,32)!=0||Q(d,40)!=Q(d,48)||N(d,56)!=0||Q(s,24)!=0||N(s,12)!=0||N(s,16)!=0||Q(s,32)>32UL*1024*1024||N(s,156)!=32||N(s,160)>32||Q(s,96)!=0||Q(s,192)!=0||N(s,212)!=1||Q(p,40)!=Q(p,48)||N(p,64)!=0||Q(p,56)!=0||Q(p,72)!=Q(p,80)||Q(h,24)!=0)throw new IOException("Native resource/loss accounting failed");
        return result;
    }
}
static class Native
{
    // Read only after the owned actor and source are disposed. This is failure
    // evidence, never a substitute for the success-path accounting/ACK gates.
    internal static object FailureHealth()
    {
        Marshal.ThrowExceptionForHR(FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));using(port)
        {
            string Get(uint command,int length){var b=new byte[length];Marshal.ThrowExceptionForHR(FilterSendMessage(port,WindowsStagedActorProtocol.Message(command),8,b,(uint)length,out var returned));if(returned!=length)throw new IOException("Failure health reply length differs");return Convert.ToHexString(b);}
            return new{QualificationPassed=false,ReadOnlyAfterFailure=true,Diagnostic=Get(8,72),Staging=Get(12,224),Binding=Get(20,88),Operations=Get(3,48),Admission=Get(24,48),ProcessCreation=Get(28,48)};
        }
    }
    [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
}
