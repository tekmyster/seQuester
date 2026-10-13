using System.ComponentModel;
using System.Text.Json;
using RansomFree.Client.Forensics;

internal static class SourceHealthSampleChecks
{
    internal static async Task Run()
    {
        var checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        var normal=new LinuxSourceWorkBarrier();var calls=0;
        var accepted=LinuxSourceHealthSampler.Capture(normal,1,0,()=>{calls++;return 0;},()=>false);
        Check(accepted.Evidence is not null&&calls==1&&accepted.Reason=="LINUX_SOURCE_HEALTH_SAMPLED","actual callable sample read once for active generation");
        var sample=accepted.Evidence!;
        Check(sample.ActiveBeforeTicks<=sample.SampleStartedTicks&&sample.SampleStartedTicks<=sample.SampleReturnedTicks&&sample.SampleReturnedTicks<=sample.ChildCheckedTicks&&sample.ChildCheckedTicks<=sample.SealedTicks&&sample.MonotonicFrequency>0,"separate map, child and seal observations retain monotonic ordering");
        Check(sample.Semantics=="ZERO_LOSS_AT_SAMPLE_WITH_ACTIVE_GENERATION_BRACKET"&&sample.LostAtReady==0&&sample.LostAtSample==0&&sample.ChildExitNotObservedAtCheck,"health receipt states sampled facts without continuous-liveness promise");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(sample);normal.RequestStop("AFTER_SEAL",DateTimeOffset.UtcNow);
        Check(bytes.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(sample)),"later clean stop preserves exact historical receipt");
        Check(LinuxSourceHealthSampler.Capture(normal,1,0,()=>throw new Exception("must not read"),()=>false).Reason=="LINUX_SOURCE_NOT_ACTIVE","stopped source does not read map or create new receipt");
        Check(LinuxSourceHealthSampler.Capture(new(),1,1,()=>throw new Exception("must not read"),()=>false).Reason=="LINUX_SOURCE_INITIAL_LOSS","nonzero ready baseline cannot be relabeled healthy");
        Check(LinuxSourceHealthSampler.Capture(new(),2,0,()=>throw new Exception("must not read"),()=>false).Reason=="LINUX_SOURCE_NOT_ACTIVE","actor source generation mismatch prevents sampling");
        Check(LinuxSourceHealthSampler.Capture(new(),1,0,()=>7,()=>false).Reason=="LINUX_SOURCE_LOSS_OBSERVED","loss preceding sample prevents receipt");
        var failed=LinuxSourceHealthSampler.Capture(new(),1,0,()=>throw new Win32Exception(5),()=>false);
        Check(failed.Evidence==null&&failed.Reason=="LINUX_SOURCE_LOSS_SAMPLE_FAILED"&&failed.ErrorDomain=="posix"&&failed.ErrorCode=="5","native map error remains explicit and cannot create receipt");
        Check(LinuxSourceHealthSampler.Capture(new(),1,0,()=>0,()=>true).Reason=="LINUX_SOURCE_CHILD_UNAVAILABLE","observed child exit/framing failure prevents receipt");
        Check(LinuxSourceHealthSampler.Capture(new(),1,0,()=>0,()=>throw new IOException()).Reason=="LINUX_SOURCE_CHILD_CHECK_FAILED","unavailable child check is not invented as alive");
        foreach(var fault in new[]{false,true})
        {
            var barrier=new LinuxSourceWorkBarrier();using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            var blocked=Task.Run(()=>LinuxSourceHealthSampler.Capture(barrier,1,0,()=>{entered.Set();release.Wait();return 0;},()=>false));
            if(!entered.Wait(TimeSpan.FromSeconds(10)))throw new Exception("Map reader did not enter");
            // This transition must progress while map I/O is blocked. Run it
            // as a task with a bounded wait so a regression cannot hang QA.
            var transition=Task.Run(()=>fault?barrier.Fault("DURING_SAMPLE",DateTimeOffset.UtcNow):barrier.RequestStop("DURING_SAMPLE",DateTimeOffset.UtcNow));
            try{await transition.WaitAsync(TimeSpan.FromSeconds(10));}finally{release.Set();}
            var result=await blocked;
            Check(result.Evidence==null&&result.Reason=="LINUX_SOURCE_CHANGED_DURING_SAMPLE",(fault?"fault":"stop")+" during blocked map read progresses and rejects sealing");
        }
        var afterSample=new LinuxSourceWorkBarrier();ulong counter=0;
        var historic=LinuxSourceHealthSampler.Capture(afterSample,1,0,()=>counter,()=>{counter=1;return false;});
        Check(historic.Evidence?.LostAtSample==0&&counter==1,"loss after map sample is not misreported as loss-free through seal");
        Check(LinuxSourceHealthSampler.Capture(afterSample,1,0,()=>counter,()=>false).Reason=="LINUX_SOURCE_LOSS_OBSERVED","next decision observes loss and cannot reuse previous zero sample");
        var stopInChildCheck=new LinuxSourceWorkBarrier();
        Check(LinuxSourceHealthSampler.Capture(stopInChildCheck,1,0,()=>0,()=>{stopInChildCheck.RequestStop("CHILD_MONITOR_STOP",DateTimeOffset.UtcNow);return false;}).Evidence==null,"terminal change in child check cannot evade final active-generation check");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Bounded sampled-health component with real blocked tasks and deterministic race order; no native map, live-source ownership, policy authority or production deployment."}));
    }
}
