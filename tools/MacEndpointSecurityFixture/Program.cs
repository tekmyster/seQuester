using RansomFree.LinuxAgent;
using RansomFree.LinuxAgent.EndpointSecurity;

var root=Path.Combine(Path.GetTempPath(),"mac-es-fixture-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
int checks=0;
void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS "+name);}
ManagedEvent Sample()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"fixture-not-native",ObservedOperation.Write,"/canary","/renamed",new("0102",42,1,"/bin/fixture","signing","team",501,502,503,7),[1,2,3]);
var sample=Sample();
foreach(var op in Enum.GetValues<ObservedOperation>())
{
    var mapped=EvidenceMapper.Map(sample with{Operation=op},"fixture");
    Check(op==ObservedOperation.Unknown?mapped==null:mapped!=null,"operation "+op);
    if(mapped!=null)Check(!mapped.Operation.Contains("copy",StringComparison.OrdinalIgnoreCase)&&!mapped.Operation.Contains("encrypt",StringComparison.OrdinalIgnoreCase),"observed facts "+op);
}
var m=EvidenceMapper.Map(sample,"fixture")!;
Check(m.EventId==sample.EventId&&m.Attribution.ParentProcessId==1&&m.Attribution.LoginUserId==503&&m.Attribution.SessionId==7&&m.Attribution.IsValid(),"identity and additive contract");
Check(EvidenceMapper.Map(sample with{Actor=new()},"fixture")!.Attribution.Level=="Detection only","empty actor does not imply attribution");
Check(EvidenceMapper.Map(sample with{Actor=null},"fixture")!.Attribution.Level=="Detection only","unknown actor explicit");
Check(EvidenceMapper.Map(sample with{SourcePath="/"+new string('x',1024)},"fixture")==null,"long wire path retained raw only");
Check(EvidenceMapper.Map(sample with{PathTruncated=true},"fixture")==null,"truncated path not mapped");
Check(!EvidenceMapper.Valid(sample with{SourcePath="/bad\0path"})&&!EvidenceMapper.Valid(sample with{RawEvidence=null!})&&!EvidenceMapper.Valid(null),"malformed null input");
Check(!EvidenceMapper.Valid(sample with{Actor=new(Pid:-1)})&&!EvidenceMapper.Valid(sample with{EventId="bad"})&&!EvidenceMapper.Valid(sample with{RawEvidence=new byte[65537]}),"identity and bounded input");
Check(EvidenceMapper.Map(sample with{SourcePath="/日本語 é"},"fixture")!.Path=="/日本語 é","unicode exact path");
foreach(var state in Enum.GetValues<SensorState>())
{
    var s=new SensorStatus(state,FallbackRunning:true);
    Check(!s.RequestedCoverageAvailable&&!s.Display.Contains("Full attribution")&&s.Display.Contains("no actor/open/read"),"degraded status "+state);
}
var directory=Path.Combine(root,"evidence");Directory.CreateDirectory(directory);
var disk=new FileEvidenceStore(directory,1);var evidenceId=disk.Save(sample);
Check(disk.Save(sample)==evidenceId&&Directory.GetFiles(directory).Length==1,"durable dedup evidence");
Check(File.ReadAllText(Directory.GetFiles(directory)[0]).Contains("team"),"raw signing and target lineage retained");
try{disk.Save(Sample());throw new Exception("quota should fail");}catch(IOException){checks++;Console.WriteLine("PASS quota preserves evidence");}
var provider=new FixtureProvider();var store=new BlockingStore();var delivered=new List<MappedEvidence>();
using(var sensor=new EndpointSecuritySensor(provider,store,delivered.Add,1))
{
    sensor.Start();provider.Emit!(sample);Check(store.Entered.Wait(5000),"worker entered evidence sink");
    var old=provider.Emit;provider.Emit(sample);provider.Emit(sample);provider.Emit(null);provider.Loss!(3);
    sample.RawEvidence[0]=99;store.Release.Set();sensor.Stop();
    Check(sensor.Metrics.QueueLost==1&&sensor.Metrics.ProviderLost==3&&sensor.Metrics.Rejected==1,"bounded queue and loss counters");
    Check(store.FirstByte==1&&delivered.Count==2,"callback owns raw bytes before return");
    Check(sensor.Status.State==SensorState.Stopped&&provider.Stops>=2,"stop drains and unsubscribes");
    sensor.Start();old!(Sample());sensor.Stop();Check(sensor.Metrics.Rejected==2,"late callback rejected after restart");
}
var failing=new FixtureProvider();using(var sensor=new EndpointSecuritySensor(failing,new ThrowingStore(),_=>throw new Exception()))
{sensor.Start();failing.Emit!(Sample());sensor.Stop();Check(sensor.Metrics.DeliveryFailed==1&&sensor.Metrics.Archived==0,"failed archive suppresses publication");}
var recover=new ConfigurableProvider();using(var sensor=new EndpointSecuritySensor(recover,new MemoryStore(),_=>{}))
{
    foreach(var state in new[]{SensorState.UnsupportedApi,SensorState.MissingEntitlement,SensorState.MissingFullDiskAccess,SensorState.AuthorizationDenied,SensorState.InsufficientPrivilege,SensorState.SubscriptionFailed})
    {recover.Result=new(state);sensor.Start();Check(sensor.Status.State==state&&!sensor.Status.RequestedCoverageAvailable,"provider startup result "+state);}
    recover.Result=new(SensorState.Running,true);recover.SynchronousLoss=true;sensor.Start();
    Check(sensor.Status.State==SensorState.ProviderLoss&&!sensor.Status.RequestedCoverageAvailable,"synchronous loss survives Start result");
    recover.SynchronousLoss=false;sensor.Start();Check(sensor.Status.RequestedCoverageAvailable&&sensor.Metrics.ProviderLost==1,"simulated verified-provider recovery retains historical loss (fixture only)");
    recover.Throws=true;sensor.Start();Check(sensor.Status.State==SensorState.Failed,"provider start exception cleaned up");
}
var publishFail=new FixtureProvider();using(var sensor=new EndpointSecuritySensor(publishFail,new MemoryStore(),_=>throw new IOException("fixture")))
{sensor.Start();publishFail.Emit!(Sample());sensor.Stop();Check(sensor.Metrics.Archived==1&&sensor.Metrics.DeliveryFailed==1,"publish failure retains archive and counts failure");}
var fallbackDir=Path.Combine(root,"fallback");Directory.CreateDirectory(fallbackDir);
var path=Path.Combine(fallbackDir,"canary");var seen=new System.Collections.Concurrent.ConcurrentQueue<Observation>();
using(var monitor=new LinuxMonitors("endpoint-security",seen.Enqueue))
{
    monitor.Update([new(path,true)]);
    try{monitor.RequireRequestedCoverage();throw new Exception("ES must stay pending");}catch(InvalidOperationException){checks++;Console.WriteLine("PASS unavailable ES policy guard");}
    File.WriteAllText(path,"fixture");Check(SpinWait.SpinUntil(()=>seen.Count>0,5000),"fallback continues after coverage rejection (Windows watcher fixture only)");
    Check(monitor.Mode.Contains("no actor/open/read")&&seen.All(x=>x.Pid==null&&x.Attribution==null),"fallback never supplies actor");
}
using(var monitor=new LinuxMonitors("fsevents",_=>{})){monitor.Update([new(path,true)]);monitor.RequireRequestedCoverage();checks++;Console.WriteLine("PASS explicit fallback policy accepted");}
Console.WriteLine($"PASS {checks} checks; managed Windows fixtures only. Native ABI/runtime acceptance OPEN. Evidence: {root}");

sealed class FixtureProvider:IEndpointSecurityProvider
{
    public Action<ManagedEvent?>? Emit;public Action<long>? Loss;public int Stops;
    public SensorStatus Start(Action<ManagedEvent?> onEvent,Action<long> onLoss){Emit=onEvent;Loss=onLoss;return new(SensorState.Running);}
    public void Stop(){Stops++;}public void Dispose(){}
}
sealed class BlockingStore:IEvidenceStore
{
    public ManualResetEventSlim Entered=new(false),Release=new(false);public byte FirstByte;
    public string Save(ManagedEvent e){Entered.Set();if(!Release.Wait(5000))throw new TimeoutException();if(FirstByte==0)FirstByte=e.RawEvidence[0];return "fixture";}
}
sealed class ConfigurableProvider:IEndpointSecurityProvider
{
    public SensorStatus Result=new(SensorState.SubscriptionFailed);public bool SynchronousLoss,Throws;
    public SensorStatus Start(Action<ManagedEvent?> onEvent,Action<long> onLoss){if(Throws)throw new IOException("fixture");if(SynchronousLoss)onLoss(1);return Result;}
    public void Stop(){}public void Dispose(){}
}
sealed class MemoryStore:IEvidenceStore{public string Save(ManagedEvent e)=>"fixture";}
sealed class ThrowingStore:IEvidenceStore{public string Save(ManagedEvent e)=>throw new IOException("fixture");}
namespace RansomFree.LinuxAgent
{
    internal sealed record Canary(string Path,bool Active);
    internal static class Platform{public static string DataPath=>Path.GetTempPath();}
    internal static class Paths{public static string NoLinks(string path)=>path;}
}


