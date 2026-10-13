using System.Diagnostics;
using System.Globalization;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// A bounded historical observation only. The runtime must separately establish
// actual child/map ownership, exact source/activation linkage and actor facts.
// A zero counter is true at the sample, not through the later seal or fsync.
internal static class LinuxSourceHealthSampler
{
    internal sealed record Result(LinuxKernelSourceHealthEvidence? Evidence,string Reason,string? ErrorDomain=null,string? ErrorCode=null);
    internal static Result Capture(LinuxSourceWorkBarrier barrier,long expectedGeneration,ulong lostAtReady,
        Func<ulong> sampleOwnedMap,Func<bool> ownedChildUnavailable)
    {
        if(lostAtReady!=0)return new(null,"LINUX_SOURCE_INITIAL_LOSS");
        var before=barrier.Current;var beforeTicks=Stopwatch.GetTimestamp();
        if(before.State!="Active"||before.Generation!=expectedGeneration||before.FirstInterruption!=null)
            return new(null,"LINUX_SOURCE_NOT_ACTIVE");
        var startedUtc=DateTimeOffset.UtcNow;var startedTicks=Stopwatch.GetTimestamp();
        ulong lost;
        try{lost=sampleOwnedMap();}
        catch(Exception ex)when(ex is not OutOfMemoryException){return Failed("LINUX_SOURCE_LOSS_SAMPLE_FAILED",ex);}
        var returnedTicks=Stopwatch.GetTimestamp();var returnedUtc=DateTimeOffset.UtcNow;
        if(lost!=0)return new(null,"LINUX_SOURCE_LOSS_OBSERVED");
        // A separate sampled fact. No claim that child state and BPF map state
        // were observed atomically, or that either stays unchanged afterward.
        bool unavailable;
        try{unavailable=ownedChildUnavailable();}
        catch(Exception ex)when(ex is not OutOfMemoryException){return Failed("LINUX_SOURCE_CHILD_CHECK_FAILED",ex);}
        var childTicks=Stopwatch.GetTimestamp();var childUtc=DateTimeOffset.UtcNow;
        if(unavailable)return new(null,"LINUX_SOURCE_CHILD_UNAVAILABLE");
        if(barrier.TrySealActiveObservation(before)==null)return new(null,"LINUX_SOURCE_CHANGED_DURING_SAMPLE");
        var sealedTicks=Stopwatch.GetTimestamp();var sealedUtc=DateTimeOffset.UtcNow;
        return new(new(before.Generation,lostAtReady,lost,startedUtc,returnedUtc,childUtc,sealedUtc,
            beforeTicks,startedTicks,returnedTicks,childTicks,sealedTicks,Stopwatch.Frequency),"LINUX_SOURCE_HEALTH_SAMPLED");
    }
    private static Result Failed(string reason,Exception ex)=>ex is System.ComponentModel.Win32Exception native?
        new(null,reason,"posix",native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)):
        new(null,reason,"dotnet",ex.HResult.ToString(CultureInfo.InvariantCulture));
}
