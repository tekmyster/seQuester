using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using RansomFree.Server;

// Private qualification only. No replay input or synthetic acquisition transport
// is accepted. Both production source classes run against the actual drivers.
if(args.Length is not (2 or 4)||!OperatingSystem.IsWindows()||Environment.MachineName!="SQ-KERNEL-W10"||WindowsIdentity.GetCurrent().User?.Value!="S-1-5-18")
    throw new InvalidOperationException("Requires the owned Windows 10 qualification guest running as SYSTEM");
var reportingWaitSeconds=60;
if(args.Length==4&&(args[2]!="--reporting-wait-seconds"||!int.TryParse(args[3],out reportingWaitSeconds)||reportingWaitSeconds is <60 or >900))
    throw new ArgumentException("Private reporting wait must be 60–900 seconds; the original 60-second gate remains the default.");
var producer=Path.GetFullPath(args[0]);var root=Path.GetFullPath(args[1]);
if(!root.StartsWith(@"C:\Windows\Temp\sq-syscall-",StringComparison.OrdinalIgnoreCase)||Directory.Exists(root)||!File.Exists(producer))
    throw new InvalidOperationException("Requires a new private qualification directory and an existing producer");
Directory.CreateDirectory(root);
using var powerLease = new QualificationPowerLease();
var count=0;void Check(bool ok,string reason){if(!ok)throw new InvalidDataException(reason);count++;}
var json=new JsonSerializerOptions{WriteIndented=true};
var health=new ConcurrentQueue<string>();var received=new ConcurrentDictionary<string,AgentEvent>(StringComparer.Ordinal);
var publicationTimes=new ConcurrentDictionary<string,DateTimeOffset>(StringComparer.Ordinal);
var healthGate=new object();
void Health(string message){var line=DateTimeOffset.UtcNow.ToString("o")+" "+message;health.Enqueue(line);lock(healthGate)File.AppendAllText(Path.Combine(root,"health-live.txt"),line+Environment.NewLine);}
var serverDirectory=Path.Combine(root,"isolated-server");var server=new Store(serverDirectory);
var code=server.CreateCode();var enrollment=server.Enroll(new(code.Code,"SQ-KERNEL-W10-live-syscall","private-native-qualification"))!;
var sensor=enrollment.EndpointId;var directory=Path.Combine(root,"sensor");var owned=Path.Combine(root,"owned-files");
using var spool=new EventSpool(directory,sensor,retainJournalLifetime:true);
await using var pipeline=new ForensicPipeline(sensor,directory,Health);
var watched=Enumerable.Range(0,9).Select(i=>Path.Combine(owned,$"case-{i}.txt")).ToArray();
void Publish(AgentEvent value){spool.Enqueue(value);publicationTimes[value.EventId]=DateTimeOffset.UtcNow;received[value.EventId]=value;}
var kernel=new WindowsKernelSource(sensor,directory,()=>watched,_=>{},Health,
    (_,lease)=>lease?.Dispose(),captureStagedExecutables:true,captureProactiveExecutables:true);
WindowsSyscallSource? syscall=null;Process? actor=null;Task<string>? stdout=null,stderr=null;
using var progressStop=new ManualResetEventSlim();Thread? progressThread=null;
var producerHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(producer)));
FileIdentityEvidence sourceIdentity;using(var executable=File.OpenRead(producer))sourceIdentity=NativeFileIdentity.Read(executable);
var sourceIndex=BinaryPrimitives.ReadUInt64LittleEndian(Convert.FromHexString(sourceIdentity.StableId!.Split(':')[2]).AsSpan(0,8)).ToString("X16");
try
{
    syscall=new(sensor,directory,kernel,pipeline,()=>new(),Publish,Health);
    // A dedicated observer keeps diagnostics available if blocked native I/O
    // consumes thread-pool workers or prevents source disposal from finishing.
    progressThread=new Thread(()=>{
        while(!progressStop.Wait(TimeSpan.FromSeconds(5))){
            try{File.AppendAllText(Path.Combine(root,"live-progress.jsonl"),JsonSerializer.Serialize(new{Utc=DateTimeOffset.UtcNow,Source=syscall.CaptureDiagnostics(),Spool=spool.CaptureWriteDiagnostics(),Events=received.Count,ActorExited=actor?.HasExited})+Environment.NewLine);}
            catch(Exception ex){try{File.AppendAllText(Path.Combine(root,"progress-errors.txt"),ex.GetType().Name+Environment.NewLine);}catch(IOException){}}
        }
    }){IsBackground=true,Name="private-syscall-progress"};progressThread.Start();
    async Task Wait(Func<bool> ready,TimeSpan limit,string failure)
    {
        var elapsed=Stopwatch.StartNew();
        while(!ready()){if(elapsed.Elapsed>=limit)throw new TimeoutException(failure);await Task.Delay(100);}
    }
    await Wait(()=>health.Any(s=>s.Contains("Windows kernel source connected"))&&health.Any(s=>s.Contains("Windows syscall intake connected")),TimeSpan.FromSeconds(60),"Both live sensor sources did not connect");
    var start=new ProcessStartInfo(producer){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};start.ArgumentList.Add(owned);
    actor=Process.Start(start)!;stdout=actor.StandardOutput.ReadToEndAsync();stderr=actor.StandardError.ReadToEndAsync();
    // No termination or later process inspection is used to fill evidence gaps.
    await Wait(()=>actor.HasExited,TimeSpan.FromMinutes(11),"Owned producer did not finish naturally; keep the administrative session and guest");
    File.WriteAllText(Path.Combine(root,"producer.jsonl"),await stdout);File.WriteAllText(Path.Combine(root,"producer.stderr.txt"),await stderr);
    Check(actor.ExitCode==0,"Independent native producer failed");
    var reportingWait=Stopwatch.StartNew();
    await Wait(()=>received.Values.Count(e=>e.Source=="Windows syscall")==9&&received.Values.Count(e=>e.Source=="Forensic enrichment")==9,TimeSpan.FromSeconds(reportingWaitSeconds),"Managed intake did not publish all nine original/completion pairs");
    var reportingDrainMilliseconds=reportingWait.ElapsedMilliseconds;
    var events=received.Values.Where(e=>e.Source=="Windows syscall").OrderBy(e=>e.Attribution!.WindowsSyscall!.Native.Sequence).ToArray();
    var truth=File.ReadAllBytes(Path.Combine(owned,"expected-operations.bin"));Check(truth.Length==9*336,"Independent truth file incomplete");
    var receiver=new EvidenceReceiver(server,serverDirectory);long prior=0;
    for(var i=0;i<9;i++)
    {
        var expected=truth.AsSpan(i*336,336).ToArray();var value=events[i];var n=value.Attribution!.WindowsSyscall!.Native;var f=value.Forensics!;
        uint U(int o)=>BinaryPrimitives.ReadUInt32LittleEndian(expected.AsSpan(o,4));
        ulong L(int o)=>BinaryPrimitives.ReadUInt64LittleEndian(expected.AsSpan(o,8));
        Check(U(0)==1&&U(4)==336&&U(44)==0,"Independent truth header differs");
        Check(n.ProcessId==U(16)&&n.ThreadId==U(20)&&(ulong)n.ProcessCreatedFileTime==L(8)&&value.ProcessId==actor.Id,"Exact native process/thread lifetime differs");
        Check(n.Operation==U(24)&&n.InformationClass==U(28)&&n.ThreadImpersonating==(U(32)==2)&&n.ReturnStatus=="0x"+U(36).ToString("X8"),"Actual operation/status/impersonation differs from independent truth");
        Check(TokenMatches(n.ProcessOwner,expected,48)&&TokenMatches(n.ThreadEffective,expected,192),"Full native accessing-token evidence differs from independent GetTokenInformation truth");
        Check(n.Sequence>prior&&n.ReturnMonotonic>=n.EntryMonotonic&&n.Outcome==(i<8?"failed":"success"),"Native ordering or failed-operation result differs");prior=n.Sequence;
        Check(value.Attribution.WindowsSyscall.LostRecords==0&&value.Path.EndsWith($"\\case-{i}.txt",StringComparison.OrdinalIgnoreCase),"Native target identity or loss counter differs");
        Check(WindowsSyscallObservation.Matches(value)&&f.IsValid(),"Reported forensic/native evidence linkage invalid");
        Check(f.ActorExecutable.Acquisition is {Version:2,Status.State:"captured"} acquisition&&acquisition.ProcessId==actor.Id&&acquisition.ProcessCreatedFileTime==n.ProcessCreatedFileTime&&acquisition.SyscallRecordSha256==n.RawRecordSha256,"Real proactive acquisition did not bind this exact process instance");
        Check(f.ActorExecutable.Sha256==producerHash&&f.Preservation is {Status.State:"captured",HashMatched:true},"Actual actor bytes were not hashed and preserved exactly");
        Check(string.Equals(value.Process,producer,StringComparison.OrdinalIgnoreCase)&&f.Process.ExecutablePath==value.Process,"Reported process path differs from the actual producer image");
        Check(f.Process.ParentPid==Environment.ProcessId&&f.Process.ParentStartKey!=null&&f.Process.CommandLineStatus.State=="captured"&&f.Process.CommandLine?.Contains(owned,StringComparison.Ordinal)==true,"Actual parent process and creation command line were not collected");
        Check(f.ActorExecutable.Acquisition!.SourceFileIndex==sourceIndex&&f.ActorExecutable.File.Size==sourceIdentity.Size&&f.ActorExecutable.Acquisition.SourceIdentityStatus.State=="captured","Source executable identity differs from the independently opened producer");
        Check(f.ActorExecutable.Signature.Valid!=true,"Unsigned test executable incorrectly reported as validly signed");
        Check(f.Process.Owner.Sid==n.ProcessOwner.Sid&&f.Process.EffectiveThreadContext?.Sid==n.ThreadEffective.Sid&&f.Process.Impersonating==n.ThreadImpersonating,"Reported owner/effective security identities differ");
        Check(f.Observation.HashPolicy=="not-hashed-by-forensic-collector","Target-file default hashing policy changed");
        var completion=received.Values.Single(e=>e.Source=="Forensic enrichment"&&e.Forensics?.RelatedEventId==value.EventId);
        var accepted=server.Ingest(sensor,new([value,completion]))!;Check(accepted.Accepted==2,"Isolated server failed to persist both linked events");
        var preserved=completion.Forensics!.Preservation;
        var manifest=File.ReadAllBytes(Path.Combine(directory,preserved.ManifestRelativePath!));
        var upload=await receiver.Start(sensor,new(completion.EventId,Convert.ToBase64String(manifest)));
        using(var image=File.OpenRead(Path.Combine(directory,preserved.ArtifactRelativePath!))){var buffer=new byte[65536];long offset=0;int length;
            while((length=await image.ReadAsync(buffer))>0){await receiver.Chunk(sensor,upload.EvidenceId,offset,buffer.AsSpan(0,length).ToArray());offset+=length;}}
        await receiver.Finish(sensor,upload.EvidenceId);
        using(var artifact=receiver.Download(sensor,upload.EvidenceId,false))Check(Convert.ToHexString(SHA256.HashData(artifact))==producerHash,"Central preserved executable bytes differ from actual producer");
    }
    Check(spool.Count==18,"Both sensor publications were not durably spooled");
    File.WriteAllText(Path.Combine(root,"events.json"),JsonSerializer.Serialize(events,json));
    File.WriteAllText(Path.Combine(root,"publication-times.json"),JsonSerializer.Serialize(publicationTimes,json));
    File.WriteAllText(Path.Combine(root,"acceptance.json"),JsonSerializer.Serialize(new{Passed=true,Checks=count,NativeCases=9,ReportingWaitSeconds=reportingWaitSeconds,ReportingDrainMilliseconds=reportingDrainMilliseconds,LiveManagedReceiver=true,LiveProactiveAcquisition=true,IsolatedCentralReceiver=true,HttpDeliveryQualified=false,ProductionDeployed=false,Scope="owned-thread-registered-handles",ProducerSha256=producerHash,Sensor=sensor},json));
    Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=count,NativeCases=9,Artifacts=root}));
}
catch(Exception ex)
{
    File.WriteAllText(Path.Combine(root,"publication-times.json"),JsonSerializer.Serialize(publicationTimes,json));
    File.WriteAllText(Path.Combine(root,"failure.json"),JsonSerializer.Serialize(new{Passed=false,Error=ex.ToString(),ReportingWaitSeconds=reportingWaitSeconds,ActorExited=actor?.HasExited,Events=received.Values},json));throw;
}
finally
{
    // Stop intake before retiring the independently owned acquisition receiver.
    try{if(syscall!=null)await syscall.DisposeAsync();await kernel.DisposeAsync();}
    finally{progressStop.Set();progressThread?.Join(TimeSpan.FromSeconds(10));File.WriteAllLines(Path.Combine(root,"health.txt"),health);actor?.Dispose();}
}

static bool TokenMatches(WindowsTokenSnapshot token,byte[] truth,int o)
{
    uint U(int p)=>BinaryPrimitives.ReadUInt32LittleEndian(truth.AsSpan(o+p,4));
    string L(int p)=>BinaryPrimitives.ReadUInt64LittleEndian(truth.AsSpan(o+p,8)).ToString("X16");
    var sidLength=U(24);if(sidLength is <8 or >68)return false;
    var sid=new SecurityIdentifier(truth.AsSpan(o+72,(int)sidLength).ToArray(),0).Value;
    return token.Captured==31&&U(0)==31&&token.Sid==sid&&token.TokenId==L(48)&&token.AuthenticationId==L(56)&&token.ModifiedId==L(64)&&
        token.SessionId==U(28)&&token.IntegrityRid==U(32)&&token.Elevated==(U(36)!=0)&&token.Type==U(40)&&
        token.ImpersonationLevel==(U(40)==2?U(44):null)&&token.QueryStatus.All(s=>s=="0x00000000");
}
