using System.Diagnostics;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativeHealthReadinessChecks
{
    internal static void Run()
    {
        var checks=new List<string>();void Check(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
        var nativeError=new System.ComponentModel.Win32Exception(13,"must-not-log-secret");
        nativeError.Data["LinuxNativeHealthSide"]="CLIENT";nativeError.Data["LinuxNativeHealthPhase"]="PIDFD_OPEN";
        nativeError.Data["LinuxNativeHealthElapsedMs"]=123L;
        var diagnostic=LinuxNativeHealthSocket.FailureDiagnostic(nativeError);
        using(var evidence=JsonDocument.Parse(diagnostic))
        {
            var value=evidence.RootElement;
            Check(value.GetProperty("NativeCode").GetInt32()==13&&value.GetProperty("Phase").GetString()=="PIDFD_OPEN"&&
                value.GetProperty("ElapsedMs").GetInt64()==123,"health diagnostics retain raw OS code, actual stage and elapsed time");
            Check(!diagnostic.Contains("must-not-log-secret",StringComparison.Ordinal),"health diagnostics exclude arbitrary exception messages");
        }
        using(var evidence=JsonDocument.Parse(LinuxNativeHealthSocket.FailureDiagnostic(new OperationCanceledException())))
            Check(evidence.RootElement.GetProperty("NativeCode").ValueKind==JsonValueKind.Null&&evidence.RootElement.GetProperty("Phase").ValueKind==JsonValueKind.Null,
                "unavailable health error code and stage remain explicit nulls");
        const string sensor="11111111111111111111111111111111";
        var ticks=Stopwatch.GetTimestamp();var utc=DateTimeOffset.UtcNow;var sample=new LinuxKernelSourceHealthEvidence(1,0,0,utc,utc,utc,utc,ticks,ticks+1,ticks+2,ticks+3,ticks+4,Stopwatch.Frequency);
        var source=new LinuxControlledSourceRuntime.ServiceHealth(Guid.NewGuid().ToString("N"),sensor,"ACTIVE",Guid.NewGuid().ToString("N"),Guid.NewGuid().ToString("N"),"123",new string('A',64),new string('B',64),utc.AddMinutes(1),sample,"LINUX_SOURCE_HEALTH_SAMPLED");
        string Inspect(LinuxControlledSourceRuntime.ServiceHealth? value,long begin=0)=>LinuxNativeHealthSocket.Readiness(value,sensor,begin==0?ticks:begin,ticks+5,utc);
        Check(Inspect(source)=="LINUX_NATIVE_SERVICE_READY_AT_SAMPLE","bounded actual-shape active sample accepted for exact sensor");
        foreach(var bad in new[]{source with{SensorId=Guid.NewGuid().ToString("N")},source with{RuntimeId="pid-123"},source with{Phase="COMPLETED"},source with{Reason="cached"},source with{Sample=null},source with{Session=null},source with{CollectorInstance="0"},source with{ProviderEpoch="0"},source with{TargetSetSha256="unknown"},source with{PolicyDigest="missing"},source with{PolicyExpiresUtc=utc},source with{Sample=sample with{LostAtSample=1}},source with{Sample=sample with{ChildExitNotObservedAtCheck=false}},source with{Sample=sample with{Generation=0}},source with{Sample=sample with{MonotonicFrequency=0}},source with{Sample=sample with{SealedTicks=ticks+6}}})
            Check(Inspect(bad)!="LINUX_NATIVE_SERVICE_READY_AT_SAMPLE","invalid source evidence unavailable: "+checks.Count);
        Check(Inspect(null)=="LINUX_NATIVE_SERVICE_STARTING_OR_UNAVAILABLE","missing source is explicit starting or unavailable");
        Check(Inspect(source,ticks+1)!="LINUX_NATIVE_SERVICE_READY_AT_SAMPLE","sample from before the live request is rejected");
        var response=new LinuxNativeHealthSocket.Reply(1,sensor,"https://qualification.invalid/",Guid.NewGuid().ToString("N"),123,"456",Guid.NewGuid().ToString("D"),Guid.NewGuid().ToString("N"),1,ticks+5,Stopwatch.Frequency,utc,source);
        var observation=new LinuxNativeHealthSocket.Observation(response,ticks+6,"LINUX_NATIVE_SERVICE_READY_AT_SAMPLE");var tracker=new LinuxNativeHealthTracker();
        Check(tracker.Accept(observation,ticks+6),"first authenticated observation establishes volatile floor");
        Check(!tracker.Accept(observation,ticks+7)&&tracker.Current==null,"duplicate cannot renew readiness and invalidates current state");
        var next=observation with{Reply=response with{Sequence=2,RecordedMonotonic=ticks+8},ReceivedMonotonic=ticks+9};
        Check(tracker.Accept(next,ticks+9),"new sequence and monotonic observation advances");
        Check(!tracker.Accept(observation with{ReceivedMonotonic=ticks+10},ticks+10),"regressing sequence rejected even with new delivery timestamp");
        var changed=next with{Reply=next.Reply with{Pid=124,StartTicks="789",InstanceId=Guid.NewGuid().ToString("N"),Sequence=1,RecordedMonotonic=ticks+11},ReceivedMonotonic=ticks+12};
        Check(tracker.Accept(changed,ticks+12),"new live process and instance may reset its own sequence");
        Check(!tracker.Accept(next,ticks+13),"late old-process completion cannot overwrite newer accepted instance");
        var stopped=changed with{Reply=changed.Reply with{Sequence=2,RecordedMonotonic=ticks+14,Source=source with{Phase="COMPLETED",Sample=null}},ReceivedMonotonic=ticks+15,Reason="LINUX_NATIVE_SERVICE_SOURCE_UNAVAILABLE"};
        Check(tracker.Accept(stopped,ticks+15)&&!tracker.ReadyAtRecentSample,"fresh unavailable report advances floor but cannot advertise readiness");
        tracker.Invalidate();Check(tracker.Current==null,"transport failure clears cached readiness");
        Check(!observation.IsFresh(ticks+5)&&!observation.IsFresh(ticks+7+11*Stopwatch.Frequency),"clock regression and age cannot renew a response");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Readiness validation and volatile ordering only; socket authentication/native source composition not exercised here"}));
    }
}
