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

if(args is ["--validate-ack-errors"])
{
    var mapped=0;
    foreach(var status in new[]{unchecked((int)0x80070490),unchecked((int)0x80070057),unchecked((int)0x80070017)})
    {
        try{Marshal.ThrowExceptionForHR(status);throw new Exception("Expected HRESULT did not throw");}
        catch(Exception ex)when(ExpectedAckRejection(ex)){mapped++;Console.WriteLine("PASS expected rejection 0x"+status.ToString("X8")+" maps to "+ex.GetType().Name);}
    }
    if(ExpectedAckRejection(Marshal.GetExceptionForHR(unchecked((int)0x80004005))!))throw new Exception("Unspecified transport failure counted as a rejected claim");
    Console.WriteLine("PASS "+mapped+" actual HRESULT mappings and rejected unrelated failure");return;
}
if(args.Length==3&&args[0]=="--long-lived")
{
    using var self=Process.GetCurrentProcess();var created=self.StartTime.ToUniversalTime().ToFileTimeUtc();
    void Phase(string phase,string? error=null)=>File.AppendAllText(args[2]+".timeline.jsonl",JsonSerializer.Serialize(new{Phase=phase,Pid=self.Id,Created=created,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Frequency=Stopwatch.Frequency,Error=error})+Environment.NewLine);
    try
    {
        Phase("first-read-start");File.ReadAllBytes(args[1]);Phase("first-read-complete");
        File.WriteAllText(args[2],JsonSerializer.Serialize(new{ProcessId=self.Id,Created=created,CommandLine=Native.CommandLine(),ManagedCommandLine=Environment.CommandLine,ReadyUtc=DateTimeOffset.UtcNow}));
        Phase("sleep-start");Thread.Sleep(34000);Phase("sleep-end");
        Phase("second-read-start");File.ReadAllBytes(args[1]);Phase("second-read-complete");return;
    }
    catch(Exception ex){Phase("failed",ex.ToString());throw;}
}
if(args.Length!=1)throw new ArgumentException("New output directory required");
if(WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")throw new InvalidOperationException("Owned guest SYSTEM task required");
var root=Path.GetFullPath(args[0]);if(Directory.Exists(root))throw new IOException("Output already exists");Directory.CreateDirectory(root);
var parent=Path.GetDirectoryName(root)!;var localService=new SecurityIdentifier("S-1-5-19");
void Grant(string path,FileSystemRights rights){var info=new DirectoryInfo(path);var acl=info.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(localService,rights,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));info.SetAccessControl(acl);}
Grant(parent,FileSystemRights.ReadAndExecute);Grant(root,FileSystemRights.ReadAndExecute);
var watched=Path.Combine(root,"scope");var reports=Path.Combine(root,"reports");Directory.CreateDirectory(watched);Directory.CreateDirectory(reports);Grant(reports,FileSystemRights.Modify);
string[] operations=["read","impersonated-read","open-impersonated-read-reverted","open-primary-read-impersonated","denied-read","denied-write","denied-append","denied-delete","denied-rename","denied-acl","write","append","copy","rename","delete","async-read","async-write","mmap-read","mmap-write","acl"];
var paths=operations.Append("long-lived").Select(op=>Path.Combine(watched,op+".bin")).ToArray();
foreach(var path in paths)
{
    File.WriteAllBytes(path,new byte[8192]);
    if(Path.GetFileName(path).StartsWith("denied-")){var info=new FileInfo(path);var acl=info.GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(localService,FileSystemRights.ReadData|FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.Delete|FileSystemRights.ChangePermissions,AccessControlType.Deny));info.SetAccessControl(acl);}
}
var actorPath=Path.Combine(parent,"reader","actor","WindowsActorFixture.exe");var actorHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(actorPath)));
var originalIdentity=SourceIdentityTruth.Capture(actorPath);var probeIdentity=SourceIdentityTruth.Capture(Environment.ProcessPath!);
File.WriteAllText(Path.Combine(root,"source-identities.json"),JsonSerializer.Serialize(new{Schema="sequester.source-identity-ground-truth/v1",Actor=originalIdentity,Probe=probeIdentity}));
var capture=Path.Combine(root,"capture");Directory.CreateDirectory(capture);var sensor=Guid.NewGuid().ToString("N");
var spool=new EventSpool(capture,sensor);var collected=new ConcurrentDictionary<string,AgentEvent>();var health=new ConcurrentQueue<string>();var gate=new object();var cases=new List<object>();
void Persist(AgentEvent e)
{
    lock(gate)
    {
        if(e.Source=="Windows minifilter")
        {
            var raw=File.ReadAllBytes(Path.Combine(capture,"kernel-inbox",e.EventId+".record"));var rawRoot=Path.Combine(capture,"kernel-raw");Directory.CreateDirectory(rawRoot);
            var path=Path.Combine(rawRoot,e.EventId+".bin");if(File.Exists(path)){if(!File.ReadAllBytes(path).AsSpan().SequenceEqual(raw))throw new IOException("Raw native archive changed");}else File.WriteAllBytes(path,raw);
        }
        spool.Enqueue(e);if(collected.TryAdd(e.EventId,e)){using var file=new FileStream(Path.Combine(capture,"events.jsonl"),FileMode.Append,FileAccess.Write,FileShare.Read);file.Write(JsonSerializer.SerializeToUtf8Bytes(e));file.WriteByte(10);file.Flush(true);}
    }
}
void Health(string text){health.Enqueue(text);lock(gate)File.AppendAllText(Path.Combine(capture,"health.jsonl"),JsonSerializer.Serialize(new{Utc=DateTimeOffset.UtcNow,Message=text})+Environment.NewLine);}
async Task Until(Func<bool> ready,TimeSpan timeout,string reason){var sw=Stopwatch.StartNew();while(!ready()){if(sw.Elapsed>timeout)throw new TimeoutException(reason);await Task.Delay(100);}}
using var creatorProcess=Process.GetCurrentProcess();var creatorPid=creatorProcess.Id;var creatorCreated=creatorProcess.StartTime.ToUniversalTime().ToFileTimeUtc();
string? error=null;bool passed=false;object? nativeHealth=null;
var reconnectChecks=new List<object>();
CheckTransport("health-only-before-start",false);
try
{
    await using(var pipeline=new ForensicPipeline(sensor,capture,Health))
    {
        void Publish(AgentEvent e,ActorLease? early)
        {
            var prepared=WindowsKernelSource.RestorePrepared(capture,e.EventId);
            if(prepared!=null){early?.Dispose();Persist(prepared);return;}
            pipeline.Submit(e,new(),pending=>{WindowsKernelSource.SavePrepared(capture,pending);Persist(pending);},Persist,early);
        }
        WindowsKernelSource NewSource()=>new(sensor,capture,()=>paths,e=>Publish(e,null),Health,Publish,captureStagedExecutables:true);
        var source=NewSource();
        try
        {
            source.DiagnosticAfterIntake=CheckAcknowledgementsWhileRetained;
            await Until(()=>File.Exists(Path.Combine(capture,"kernel-inbox","provider-checkpoint.json")),TimeSpan.FromSeconds(30),"Native scope not ready");
            foreach(var operation in operations)
            {
                if(operation=="read"){await source.DisposeAsync();CheckTransport("active-epoch-disconnected",true);}
                var path=Path.Combine(watched,operation+".bin");var report=Path.Combine(reports,operation+".json");
                var start=new ProcessStartInfo(actorPath){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden,RedirectStandardError=true};
                foreach(var arg in new[]{operation,path,report,"--exit-immediately"})start.ArgumentList.Add(arg);start.Environment["SQ_FIXTURE_LOCAL_SERVICE"]="1";
                var creatorTid=Native.GetCurrentThreadId();
                using var child=Process.Start(start)??throw new IOException("Fixture launch failed");var ownedHandle=child.Handle;var pid=child.Id;var created=child.StartTime.ToUniversalTime().ToFileTimeUtc();var stderr=child.StandardError.ReadToEndAsync();
                try
                {
                    if(!child.WaitForExit(15000))throw new TimeoutException("Fixture exceeded unchanged 15-second exit deadline: "+operation);
                    if(child.ExitCode!=0)throw new IOException("Fixture failed "+operation+": "+await stderr);
                }
                catch(Exception failure){OwnedChildDiagnostics.Save(child,pid,created,report,failure);throw;}
                finally
                {
                    // Read stderr only after this exact owned child has exited;
                    // a missed gate must not wait forever on its open pipe.
                    if(!child.HasExited){child.Kill();if(!child.WaitForExit(15000))throw new IOException("Owned matrix actor did not exit after failed deadline");}
                    File.WriteAllText(report+".stderr.txt",await stderr);
                }
                if(operation=="read"){
                    // This zero-dwell actor ran with no consumer. Its raw queue
                    // record and pinned executable must survive the reconnect.
                    CheckTransport("unacknowledged-operation-disconnected",true,true);
                    source=NewSource();source.DiagnosticAfterIntake=CheckAcknowledgementsWhileRetained;
                }
                using var truth=JsonDocument.Parse(File.ReadAllBytes(report));var t=truth.RootElement;
                if(t.GetProperty("ProcessId").GetInt32()!=pid||t.GetProperty("ProcessCreatedUtcFileTime").GetInt64()!=created||t.GetProperty("PostOperationDelayMs").GetInt32()!=0)throw new IOException("Ground-truth process identity differs");
                AgentEvent[] Relevant()=>collected.Values.Where(e=>e.Source=="Windows minifilter"&&e.ProcessId==pid&&e.Attribution?.WindowsKernel?.ProcessCreatedFileTime==created&&RelevantMajor(e.Attribution.WindowsKernel,operation)&&(!operation.StartsWith("denied-")||e.Attribution.OsStatus=="0xC0000022")).ToArray();
                var deliveryWait=Stopwatch.StartNew();
                await Until(()=>Relevant().Any(e=>collected.Values.Any(c=>c.Source=="Forensic enrichment"&&c.Forensics?.RelatedEventId==e.EventId)),TimeSpan.FromSeconds(45),"Required completed observation missing: "+operation);
                var matching=Relevant();var accepted=new List<string>();
                foreach(var observation in matching)
                {
                    var k=observation.Attribution!.WindowsKernel!;var primary=t.GetProperty("Primary");var effective=t.GetProperty("Effective");
                    if(k.Version!=5||k.ThreadOwnerPrimary==null||!TokenMatches(k.ThreadOwnerPrimary,primary)||k.ThreadProcessCreatedFileTime!=created||
                        !TokenMatches(k.RequestorPrimary,primary)||!TokenMatches(k.ThreadEffective,effective)||k.ThreadId!=t.GetProperty("ThreadId").GetUInt32())continue;
                    if(operation.StartsWith("denied-")&&observation.Attribution.OsStatus!="0xC0000022")continue;
                    var completion=collected.Values.SingleOrDefault(c=>c.Source=="Forensic enrichment"&&c.Forensics?.RelatedEventId==observation.EventId);
                    if(completion?.Forensics is not {} f)continue;
                    if(!f.IsValid()||!WindowsKernelEvidence.Matches(completion)||f.ActorExecutable.Acquisition?.Status.State!="captured"||f.Preservation.HashMatched!=true||f.ActorExecutable.Sha256!=actorHash||f.Process.Owner.Sid!=primary.GetProperty("UserSid").GetString()||f.Process.EffectiveThreadContext?.Sid!=effective.GetProperty("UserSid").GetString()||f.Process.ThreadOwner?.Sid!=primary.GetProperty("UserSid").GetString()||f.Process.ThreadOwnerCreatedFileTime!=created)throw new IOException("Attribution or executable preservation differs: "+operation);
                    if(f.ActorExecutable.File.StableId!=originalIdentity.StableId||f.ActorExecutable.Acquisition.SourceIdentityStatus.State!="captured"||f.ActorExecutable.Acquisition.SnapshotFile!.StableId==originalIdentity.StableId)throw new IOException("Original source identity differs from independent Win32 query: "+operation);
                    if(f.Process.CommandLine!=t.GetProperty("CommandLine").GetString()||f.Process.CommandLineStatus.State!="captured"||f.Process.Creation is not {Status.State:"captured",CreatorStatus.State:"captured",FileOpenNameAvailable:true} creation||creation.CreatorPid!=(ulong)creatorPid||creation.CreatorTid!=creatorTid||creation.CreatorCreatedFileTime!=creatorCreated||f.Process.ParentPid!=creatorPid||f.Process.ParentStartKey!=creatorCreated.ToString())throw new IOException("Process-creation evidence differs from independent actor/creator truth: "+operation);
                    accepted.Add(observation.EventId);
                }
                if(accepted.Count==0)throw new IOException("No exact accessing-thread/process token match: "+operation);
                var openingEvents=new List<string>();
                if(t.GetProperty("OpenContext") is {ValueKind:JsonValueKind.Object} opening)
                {
                    AgentEvent[] Opens()=>collected.Values.Where(e=>e.Source=="Windows minifilter"&&e.ProcessId==pid&&e.Attribution?.WindowsKernel is {Major:0} k&&k.ProcessCreatedFileTime==created&&k.ThreadId==opening.GetProperty("ThreadId").GetUInt32()&&TokenMatches(k.CreateAuthorization,opening.GetProperty("Effective"))&&TokenMatches(k.ThreadEffective,opening.GetProperty("Effective"))&&TokenMatches(k.RequestorPrimary,opening.GetProperty("Primary"))).ToArray();
                    await Until(()=>Opens().Any(e=>collected.Values.Any(c=>c.Source=="Forensic enrichment"&&c.Forensics?.RelatedEventId==e.EventId&&c.Forensics.Preservation.HashMatched==true)),TimeSpan.FromSeconds(15),"Earlier CREATE token/preservation missing: "+operation);
                    openingEvents.AddRange(Opens().Select(e=>e.EventId));
                    if(opening.GetProperty("Effective").GetProperty("UserSid").GetString()==t.GetProperty("Effective").GetProperty("UserSid").GetString())throw new IOException("Open/read test did not change effective principal");
                }
                cases.Add(new{Operation=operation,Pid=pid,Created=created,ExitUtc=child.ExitTime.ToUniversalTime(),ExpectedHash=actorHash,CreatorPid=creatorPid,CreatorTid=creatorTid,CreatorCreated=creatorCreated,AcceptedEventIds=accepted,EarlierCreateEventIds=openingEvents,PostOperationDelayMs=0,CompletionWaitMs=deliveryWait.ElapsedMilliseconds});
            }
            var longPath=Path.Combine(watched,"long-lived.bin");var marker=Path.Combine(reports,"long-lived.json");
            var longStart=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,CreateNoWindow=true,WindowStyle=ProcessWindowStyle.Hidden};foreach(var arg in new[]{"--long-lived",longPath,marker})longStart.ArgumentList.Add(arg);
            var longCreatorTid=Native.GetCurrentThreadId();
            using(var child=Process.Start(longStart)!)
            {
                var owned=child.Handle;var pid=child.Id;var created=child.StartTime.ToUniversalTime().ToFileTimeUtc();
                var longWait=Stopwatch.StartNew();bool? exitedInDeadline=null;int? childExitCode=null;
                try
                {
                await Until(()=>File.Exists(marker),TimeSpan.FromSeconds(15),"Long-lived actor did not start");
                longWait.Restart();exitedInDeadline=child.WaitForExit(45000);if(exitedInDeadline==true)childExitCode=child.ExitCode;
                if(exitedInDeadline!=true||childExitCode!=0)throw new IOException("Long-lived actor failed: exitedInDeadline="+exitedInDeadline+", exitCode="+(childExitCode?.ToString()??"unavailable")+", waitMs="+longWait.ElapsedMilliseconds);
                // Delivery includes queued acquisition and enrichment. Keep the
                // 34-second expiry and owned actor's exit deadline unchanged;
                // allow the same 45-second delivery budget as the short-lived
                // matrix on the contended host, and retain actual latency.
                await Until(()=>collected.Values.Count(e=>e.Source=="Forensic enrichment"&&e.ProcessId==pid&&e.Forensics!.Process.StartKey==created.ToString()&&e.Attribution!.WindowsKernel!.Major==3)>=2,TimeSpan.FromSeconds(45),"Post-expiry read missing");
                var reads=collected.Values.Where(e=>e.Source=="Forensic enrichment"&&e.ProcessId==pid&&e.Attribution!.WindowsKernel!.ProcessCreatedFileTime==created&&e.Attribution.WindowsKernel.Major==3).OrderBy(e=>e.Attribution!.WindowsKernel!.Sequence).ToArray();
                var expected=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Environment.ProcessPath!)));
                if(reads.Any(e=>e.Forensics!.ActorExecutable.File.StableId!=probeIdentity.StableId||e.Forensics.ActorExecutable.Acquisition!.SourceIdentityStatus.State!="captured"))throw new IOException("Long-lived original source identity differs from independent Win32 query");
                if(reads.Length!=2||reads.Any(e=>e.Forensics!.Preservation.HashMatched!=true||e.Forensics.ActorExecutable.Sha256!=expected)||reads[0].Forensics!.ActorExecutable.Acquisition!.SnapshotId!=reads[1].Forensics!.ActorExecutable.Acquisition!.SnapshotId||reads[1].Forensics!.ActorExecutable.Acquisition!.BindingKind!="process-generation-only")throw new IOException("Long-lived actor lost exact bytes after native expiry");
                using var longTruth=JsonDocument.Parse(File.ReadAllBytes(marker));
                if(reads.Any(e=>e.Forensics!.Process.CommandLine!=longTruth.RootElement.GetProperty("CommandLine").GetString()||e.Forensics.Process.Creation is not {Status.State:"captured"} pm||pm.CreatorPid!=(ulong)creatorPid||pm.CreatorTid!=longCreatorTid||pm.CreatorCreatedFileTime!=creatorCreated))throw new IOException("Post-expiry creation metadata differs from original command/creator");
                cases.Add(new{Operation="long-lived-after-byte-expiry",Pid=pid,Created=created,ExpectedHash=expected,CreatorPid=creatorPid,CreatorTid=longCreatorTid,CreatorCreated=creatorCreated,AcceptedEventIds=reads.Select(e=>e.Forensics!.RelatedEventId).ToArray(),DelayMs=34000});
                }
                finally
                {
                    File.WriteAllText(Path.Combine(reports,"long-lived-parent.json"),JsonSerializer.Serialize(new{Pid=pid,Created=created,Utc=DateTimeOffset.UtcNow,Monotonic=Stopwatch.GetTimestamp(),Frequency=Stopwatch.Frequency,ExitedInDeadline=exitedInDeadline,ExitCode=childExitCode,WaitMs=longWait.ElapsedMilliseconds,HasExited=child.HasExited,OwnedHandleRetained=owned!=IntPtr.Zero}));
                    // Only this exact spawned child is terminated after a failed
                    // test. Keep the native result negative; never relax its deadline.
                    if(!child.HasExited){child.Kill();if(!child.WaitForExit(15000))throw new IOException("Owned long-lived actor did not exit after test failure; native cleanup must wait");}
                }
            }
            await Until(()=>!Directory.EnumerateFiles(Path.Combine(capture,"kernel-inbox"),"*.record").Any()&&collected.Values.Count(e=>e.Source=="Windows minifilter")==collected.Values.Count(e=>e.Source=="Forensic enrichment"),TimeSpan.FromSeconds(20),"Durable intake did not drain");
        }
        finally{await source.DisposeAsync();}
    }
    nativeHealth=NativeHealth(capture);
    if(health.Any(x=>x.StartsWith("Windows kernel diagnostic journal gap:",StringComparison.Ordinal)))throw new IOException("Supplementary diagnostic journal gap reported; raw observations retained");
    passed=true;
}
catch(Exception ex){error=ex.ToString();var saved=Path.Combine(capture,"native-final-health.json");if(nativeHealth==null&&File.Exists(saved))nativeHealth=JsonSerializer.Deserialize<JsonElement>(File.ReadAllBytes(saved));}
var result=new{Schema="sequester.windows-actor-intake-native/v1",RecordedUtc=DateTimeOffset.UtcNow,Host=Environment.MachineName,Sensor=sensor,AccountingPassed=passed,AllChildrenObserved=cases.Count==21,Children=cases.Count,Matches=cases.Count,ByteCaptureImplemented=true,Cases=cases,ReconnectChecks=reconnectChecks,NativeHealth=nativeHealth,Events=collected.Count,Completions=collected.Values.Count(e=>e.Source=="Forensic enrichment"),Preserved=collected.Values.Count(e=>e.Source=="Forensic enrichment"&&e.Forensics?.Preservation.Status.State=="captured"),Error=error,ProductionReady=false,Scope="Actual minifilter through sensor durable intake, enrichment and preservation; zero-dwell 20-case matrix plus post-expiry live process. Server transfer is a separate replay gate."};
File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true}));Console.WriteLine(JsonSerializer.Serialize(new{result.AccountingPassed,result.AllChildrenObserved,result.Children,result.Events,result.Error}));if(!passed||cases.Count!=21)Environment.ExitCode=2;

static bool RelevantMajor(WindowsKernelEvidence k,string operation)=>operation.StartsWith("denied-")?k.Major==0:operation switch{"read" or "impersonated-read" or "open-impersonated-read-reverted" or "open-primary-read-impersonated" or "async-read" or "copy"=>k.Major==3,"write" or "append" or "async-write"=>k.Major==4,"rename"=>k.Major==6&&k.OperationClass is 10 or 65,"delete"=>k.Major==6&&k.OperationClass is 13 or 64,"acl"=>k.Major==21,"mmap-read" or "mmap-write"=>k.Major==255,_=>false};
void CheckAcknowledgementsWhileRetained(Func<byte[],int,byte[]> send)
{
    foreach(var path in Directory.EnumerateFiles(Path.Combine(capture,"kernel-actor-intake"),"*.ack"))
    {
        if(File.Exists(path+".qualified.json"))continue;
        var started=DateTimeOffset.UtcNow;var claim=File.ReadAllBytes(path);var replays=0;var rejected=0;var statuses=new Dictionary<int,string>();
        try
        {
            if(claim.Length!=160)throw new IOException("Invalid saved durable receipt");
            for(var i=0;i<2;i++){if(!send(claim,160).AsSpan().SequenceEqual(claim))throw new IOException("Native durable ACK retry changed");replays++;}
            foreach(var offset in new[]{8,24,32,40,48,68,72,80,112,128})
            {
                var invalid=(byte[])claim.Clone();invalid[offset]^=0x40;
                try{send(invalid,160);throw new IOException("Native accepted contradictory durable ACK offset "+offset);}
                catch(Exception ex)when(ExpectedAckRejection(ex)){rejected++;statuses[offset]="0x"+ex.HResult.ToString("X8");}
            }
            var proof=JsonSerializer.SerializeToUtf8Bytes(new{Schema="sequester.native-ack-retention-check/v1",ClaimSha256=Convert.ToHexString(SHA256.HashData(claim)),StartedUtc=started,CompletedUtc=DateTimeOffset.UtcNow,Replays=replays,Rejected=rejected,RejectionStatuses=statuses});
            using var file=new FileStream(path+".qualified.json",FileMode.CreateNew,FileAccess.Write,FileShare.Read);file.Write(proof);file.Flush(true);
        }
        catch(Exception ex)
        {
            var failure=path+".qualification-failed.json";
            if(!File.Exists(failure))File.WriteAllText(failure,JsonSerializer.Serialize(new{StartedUtc=started,CompletedUtc=DateTimeOffset.UtcNow,Replays=replays,Rejected=rejected,Error=ex.ToString()}));throw;
        }
    }
}
void CheckTransport(string phase,bool active,bool pending=false)
{
    Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
    using(port)
    {
        byte[] Get(uint command,int length){var request=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(request,4);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),command);var reply=new byte[length];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,8,reply,(uint)length,out var n));if(n!=length)throw new IOException("Reconnect health size differs");return reply;}
        var binding=Get(20,88);var staging=Get(12,224);var operations=Get(3,48);
        uint N(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
        if(N(binding,68)!=0||N(staging,212)!=0||N(staging,8)!=(active?1u:0u)||pending&&N(operations,40)==0)throw new IOException("Transport disconnect retired epoch or lost pending operation: "+phase);
        reconnectChecks.Add(new{Phase=phase,Binding=Convert.ToHexString(binding),Staging=Convert.ToHexString(staging),Operations=Convert.ToHexString(operations),PendingRequired=pending});
    }
}
static bool ExpectedAckRejection(Exception ex)=>ex is COMException or ArgumentException&&ex.HResult is unchecked((int)0x80070490) or unchecked((int)0x80070057) or unchecked((int)0x80070017);
static bool TokenMatches(WindowsTokenSnapshot k,JsonElement t)=>k.Captured==31&&k.QueryStatus.All(x=>x=="0x00000000")&&k.Sid==t.GetProperty("UserSid").GetString()&&k.TokenId==t.GetProperty("TokenId").GetString()&&k.AuthenticationId==t.GetProperty("AuthenticationId").GetString()&&k.ModifiedId==t.GetProperty("ModifiedId").GetString()&&k.Type==t.GetProperty("TokenType").GetUInt32()&&k.ImpersonationLevel==(t.GetProperty("ImpersonationLevel").ValueKind==JsonValueKind.Null?null:t.GetProperty("ImpersonationLevel").GetUInt32())&&k.SessionId==t.GetProperty("SessionId").GetUInt32()&&k.IntegrityRid==t.GetProperty("IntegrityRid").GetUInt32()&&k.Elevated==t.GetProperty("Elevated").GetBoolean();
static object NativeHealth(string capture)
{
    Marshal.ThrowExceptionForHR(Native.FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,0,0,0,out var port));
    using(port)
    {
        byte[] Get(uint command,int size){var request=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(request,4);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),command);var b=new byte[size];Marshal.ThrowExceptionForHR(Native.FilterSendMessage(port,request,8,b,(uint)size,out var n));if(n!=size)throw new IOException("Native health length mismatch");return b;}
        ulong Q(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));uint N(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
        // The test owns explicit terminal STOP. Port disconnect is transport only.
        Get(9,0);
        foreach(var (command,length) in new[]{(7u,88),(15u,112)}){
            using var rows=new FileStream(Path.Combine(capture,"terminal-"+command+".journal"),FileMode.CreateNew,FileAccess.Write);
            while(true){var request=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(request,4);BinaryPrimitives.WriteUInt32LittleEndian(request.AsSpan(4),command);var reply=new byte[length];var hr=Native.FilterSendMessage(port,request,8,reply,(uint)length,out var n);if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A))break;Marshal.ThrowExceptionForHR(hr);if(n!=length)throw new IOException("Terminal journal size differs");rows.Write(reply);}
            rows.Flush(true);
        }
        var d=Get(8,72);var s=Get(12,224);var p=Get(20,88);var h=Get(3,48);var admission=Get(24,48);var creation=Get(28,48);
        File.WriteAllText(Path.Combine(capture,"native-final-health.json"),JsonSerializer.Serialize(new{Diagnostic=Convert.ToHexString(d),Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(p),Operations=Convert.ToHexString(h),Admission=Convert.ToHexString(admission),ProcessCreation=Convert.ToHexString(creation),AcknowledgementsValidated=false}));
        var receipts=Directory.GetFiles(Path.Combine(capture,"kernel-actor-intake"),"*.ack");if(receipts.Length!=21)throw new IOException("Durable candidate acknowledgement receipt missing");
        var replayed=0;var rejected=0;
        foreach(var receipt in receipts)
        {
            var request=File.ReadAllBytes(receipt);if(request.Length!=160)throw new IOException("Invalid saved durable receipt");
            if(File.Exists(receipt+".qualification-failed.json"))throw new IOException("In-window native ACK qualification failed");
            using var saved=JsonDocument.Parse(File.ReadAllBytes(receipt+".qualified.json"));var check=saved.RootElement;
            if(check.GetProperty("Schema").GetString()!="sequester.native-ack-retention-check/v1"||check.GetProperty("ClaimSha256").GetString()!=Convert.ToHexString(SHA256.HashData(request))||check.GetProperty("Replays").GetInt32()!=2||check.GetProperty("Rejected").GetInt32()!=10||check.GetProperty("CompletedUtc").GetDateTimeOffset()<check.GetProperty("StartedUtc").GetDateTimeOffset())throw new IOException("In-window native ACK qualification proof differs");
            replayed+=2;rejected+=10;
        }
        var result=new{Diagnostic=Convert.ToHexString(d),Staging=Convert.ToHexString(s),Binding=Convert.ToHexString(p),Operations=Convert.ToHexString(h),Admission=Convert.ToHexString(admission),ProcessCreation=Convert.ToHexString(creation),DurableReceiptReplays=replayed,RejectedAcknowledgements=rejected,AcknowledgementsValidatedWhileRetained=true};
        File.WriteAllText(Path.Combine(capture,"native-final-health.json"),JsonSerializer.Serialize(result));
        if(N(creation,0)!=1||N(creation,4)!=48||N(creation,8)!=256||N(creation,12)!=0||Q(creation,16)!=Q(creation,24)||Q(creation,16)==0||Q(creation,32)!=0)throw new IOException("Process metadata lifetime/capacity accounting failed");
        if(N(admission,0)!=1||N(admission,4)!=48||N(admission,8)!=32||N(admission,12)!=16||N(admission,16)!=0||N(admission,20)!=0||N(admission,24)>32||N(admission,28)>16||Q(admission,32)!=0||Q(admission,40)!=0)throw new IOException("Separate qualification/copy admission accounting failed");
        if(Q(d,24)!=0||Q(d,32)!=0||Q(d,40)!=Q(d,48)||N(d,56)!=0||Q(s,24)!=0||N(s,12)!=0||N(s,16)!=0||Q(s,32)>32UL*1024*1024||N(s,156)!=32||N(s,160)>32||Q(s,96)!=0||Q(s,192)!=0||N(s,212)!=1||Q(p,40)!=Q(p,48)||N(p,64)!=0||Q(p,56)!=0||Q(p,72)!=Q(p,80)||Q(h,24)!=0)throw new IOException("Native resource/loss accounting failed");
        return result;
    }
}
static class Native
{
    [DllImport("kernel32.dll",ExactSpelling=true)]private static extern nint GetCommandLineW();
    internal static string CommandLine()=>Marshal.PtrToStringUni(GetCommandLineW())??throw new IOException("Native process command line unavailable");
    [DllImport("kernel32.dll")]internal static extern uint GetCurrentThreadId();
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]internal static extern int FilterConnectCommunicationPort(string name,uint options,nint context,ushort size,nint security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]internal static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[] output,uint outputSize,out uint returned);
}
