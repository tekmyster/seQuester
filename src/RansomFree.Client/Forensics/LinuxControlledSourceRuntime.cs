using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Explicit qualification entry point. This is not installed or auto-started by
// the audit sensor. One object owns the actual child, map and controller for
// its entire lifetime; journal rows never recreate those capabilities.
internal sealed class LinuxControlledSourceRuntime
{
    internal sealed record Qualification(LinuxOwnedLoaderProcess.Launch Launch,string Kernel,string BtfSha256,
        string LoaderSha256,string ObjectSha256,string Directory,int RawSlots=256)
    {
        // Independently prepared identities, never inferred from loader output.
        public ImmutableArray<LinuxControlledTargetSet.Identity> ExpectedTargets {get;init;}=[];
        public long RawBankQuotaBytes {get;init;}=LinuxNativeRawStorageCapacity.DefaultBytes;
    }
    internal sealed record Outcome(string State,string? Session,string Startup,string Close,int RawRecords,
        int? PendingDelivery,bool? CanonicalBacklogPresent,LinuxSourceWorkBarrier.Interruption? Stop,string[] Errors,LinuxOwnedLoaderProcess.Diagnostics? Child,
        string RawRecoveryState,int? UnindexedRawRecords)
    {
        public NativeClosureEvidence? NativeClosure {get;init;}
        public StartupTiming[] StartupTimings {get;init;}=[];
    }
    // Diagnostic observations only. Recording does no filesystem I/O and
    // grants no source, policy, process or native-operation authority.
    internal readonly record struct StartupTiming(int Version,int Sequence,string Point,
        DateTimeOffset RecordedUtc,long RecordedMonotonic,long MonotonicFrequency);
    private readonly object startupTimingGate=new();
    private readonly StartupTiming[] startupTimings=new StartupTiming[64];
    private int startupTimingCount;
    private void RecordStartup(string point)
    {
        lock(startupTimingGate)
        {
            if(startupTimingCount==startupTimings.Length)return;
            startupTimings[startupTimingCount]=new(1,startupTimingCount+1,point,
                DateTimeOffset.UtcNow,Stopwatch.GetTimestamp(),Stopwatch.Frequency);
            startupTimingCount++;
        }
    }
    private StartupTiming[] StartupTimeline()
    {lock(startupTimingGate)return startupTimings[..startupTimingCount];}
    internal sealed record NativeClosureEvidence(int Version,string RuntimeId,string? Session,DateTimeOffset RecordedUtc,long RecordedMonotonic,
        long MonotonicFrequency,string Controller,bool IssuedWorkDrained,bool ChildAndPipesReturned,bool MapHandlesClosed,bool ChildHandlesClosed)
    {public bool NoRunEntered {get;init;}}
    private readonly string runtimeId=Guid.NewGuid().ToString("N");
    internal string RuntimeId=>runtimeId;
    internal string EvidenceDirectory=>config.Directory;
    private readonly LinuxActorLeaseDevice.OpenAttempt controllerOpen=new();
    private NativeClosureEvidence? nativeClosure;
    private bool nativeWorkDrained,nativeAcquisitionUnresolved;
    // A module owner must inspect this registered runtime itself, never accept
    // a deserialized receipt or arbitrary Task as native lifetime authority.
    internal NativeClosureEvidence? NativeClosure=>Volatile.Read(ref nativeClosure);
    internal sealed record StartupCheckpoint(string Point,LinuxControlledLoaderProtocol.Ready Ready,
        string ReadyFrameSha256,string? Session,string Phase,bool ControllerOpened,bool ActivationWriteAttempted);
    internal sealed record MatchSourceResult(LinuxKernelSourceMatchEvidence? Evidence,string Reason,string? ErrorDomain=null,string? ErrorCode=null);
    internal sealed record ServiceHealth(string RuntimeId,string SensorId,string Phase,string? Session,string? CollectorInstance,string? ProviderEpoch,
        string? TargetSetSha256,string? PolicyDigest,DateTimeOffset? PolicyExpiresUtc,LinuxKernelSourceHealthEvidence? Sample,string Reason)
    {public uint ControlVersion {get;init;}}
    private readonly Qualification config;
    private readonly LinuxForensicJournal journal;
    private readonly ForensicPipeline pipeline;
    private readonly EventSpool spool;
    private readonly string sensor;
    private readonly ForensicPolicy policy;
    private readonly Action<string> report;
    private readonly TrustPolicyCache? trustCache;
    private readonly string? trustGroup;
    private readonly LinuxNativeSourcePolicy? signedPolicy;
    private readonly Action? requireAdmissionCurrent;
    private readonly TaskCompletionSource<Outcome> completion=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int begun;
    private bool journalAdmitted;
    // Instance-scoped qualification instrumentation. No environment switch or
    // persisted configuration can enable this callback in an installed sensor.
    private readonly Func<StartupCheckpoint,LinuxOwnedLoaderProcess,Task>? qualificationCheckpoint;
    private readonly LinuxSourceWorkBarrier barrier=new();
    private readonly Channel<byte> wake=Channel.CreateBounded<byte>(new BoundedChannelOptions(1){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly Channel<byte> retry=Channel.CreateBounded<byte>(new BoundedChannelOptions(1){SingleReader=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly ConcurrentQueue<string> errors=new();
    private readonly TaskCompletionSource stop=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource activated=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource started=new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource samplerStop=new();
    private LinuxOwnedLoaderProcess? loader;
    private LinuxBpfLostMap? map;
    private LinuxControlledMapSet? mapSet;
    private LinuxActorLeaseDevice? controller;
    private LinuxRawIngressReserve? bank;
    private LinuxControlledIngress? ingress;
    private LinuxSerialNativeWorker? native;
    private string? session;
    private string startup="NONE",close="NOT_ATTEMPTED";
    private string phase="STARTING";
    private Task? rawPump,sampler,dispatcher;
    private int rawDone,retryWork;
    private bool linked;
    private readonly Dictionary<string,LinuxForensicJournal.NativePinClaim> unscheduled=new(StringComparer.Ordinal);
    private LinuxForensicJournal.OwnerMethodReturn? opened,closed;
    private LinuxOwnedLoaderProcess.PipeWrite? write;
    private LinuxForensicJournal.SourceBoundary? closeIntent;
    private LinuxForensicJournal.SourceBoundary? startupFault;
    private DateTimeOffset? noControllerCompleted;
    private DateTimeOffset? rawSealedUtc;
    private string rawRecoveryState="NOT_RECONCILED";
    internal Task Started=>started.Task;
    internal Task<Outcome> Completion=>completion.Task;
    internal string Phase=>Volatile.Read(ref phase);
    internal string? Session=>Volatile.Read(ref session);
    private LinuxControlledSourceRuntime(Qualification config,LinuxForensicJournal journal,ForensicPipeline pipeline,EventSpool spool,string sensor,ForensicPolicy policy,Action<string> report,
        Func<StartupCheckpoint,LinuxOwnedLoaderProcess,Task>? qualificationCheckpoint,TrustPolicyCache? trustCache,string? trustGroup,LinuxNativeSourcePolicy? signedPolicy,Action? requireAdmissionCurrent)
    {
        this.config=config;this.journal=journal;this.pipeline=pipeline;this.spool=spool;this.sensor=sensor;this.policy=policy;this.report=report;
        this.qualificationCheckpoint=qualificationCheckpoint;this.trustCache=trustCache;this.trustGroup=trustGroup;
        this.signedPolicy=signedPolicy;
        this.requireAdmissionCurrent=requireAdmissionCurrent;
    }
    internal static LinuxControlledSourceRuntime StartForQualification(Qualification config,LinuxForensicJournal journal,
        ForensicPipeline pipeline,EventSpool spool,string sensor,ForensicPolicy policy,Action<string> report,
        Func<StartupCheckpoint,LinuxOwnedLoaderProcess,Task>? qualificationCheckpoint=null,TrustPolicyCache? trustCache=null,string? trustGroup=null,LinuxNativeSourcePolicy? signedPolicy=null)
    {
        var value=CreatePrepared(config,journal,pipeline,spool,sensor,policy,report,qualificationCheckpoint,trustCache,trustGroup,signedPolicy,null);
        value.BeginRegistered();return value;
    }
    // Creation only validates arguments and stores references. The module owner
    // must retain this exact instance before BeginRegistered can perform I/O.
    internal static LinuxControlledSourceRuntime CreateForRegisteredOwner(Qualification config,LinuxForensicJournal journal,
        ForensicPipeline pipeline,EventSpool spool,string sensor,ForensicPolicy policy,Action<string> report,
        LinuxNativeSourcePolicy signedPolicy,Action requireAdmissionCurrent)
    {
        ArgumentNullException.ThrowIfNull(signedPolicy);ArgumentNullException.ThrowIfNull(requireAdmissionCurrent);
        return CreatePrepared(config,journal,pipeline,spool,sensor,policy,report,null,null,null,signedPolicy,requireAdmissionCurrent);
    }
    private static LinuxControlledSourceRuntime CreatePrepared(Qualification config,LinuxForensicJournal journal,
        ForensicPipeline pipeline,EventSpool spool,string sensor,ForensicPolicy policy,Action<string> report,
        Func<StartupCheckpoint,LinuxOwnedLoaderProcess,Task>? qualificationCheckpoint,TrustPolicyCache? trustCache,string? trustGroup,LinuxNativeSourcePolicy? signedPolicy,Action? requireAdmissionCurrent)
    {
        if(!OperatingSystem.IsLinux()||System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture!=System.Runtime.InteropServices.Architecture.X64)
            throw new PlatformNotSupportedException("Controlled runtime requires qualified Linux x64");
        if(!Guid.TryParseExact(sensor,"N",out _)||!policy.IsValid()||!Path.IsPathFullyQualified(config.Directory)||Directory.Exists(config.Directory)||config.RawSlots is <5 or >4096)
            throw new ArgumentException("Fresh bounded qualification directory, sensor and policy required");
        _=ValidatePreparedTargets(config);
        if(signedPolicy!=null&&(trustCache!=null||trustGroup!=null||signedPolicy.UnavailableReason!=null))throw new ArgumentException("One current signed policy source required");
        signedPolicy?.RequireSource(sensor,policy);
        return new(config,journal,pipeline,spool,sensor,policy,report,qualificationCheckpoint,trustCache,trustGroup,signedPolicy,requireAdmissionCurrent);
    }
    internal void BeginRegistered()=>BeginRegisteredCore(null);
    internal void BeginRegisteredForQualification(Action beforeSubmission)=>BeginRegisteredCore(beforeSubmission??throw new ArgumentNullException(nameof(beforeSubmission)));
    private void BeginRegisteredCore(Action? beforeSubmission)
    {
        if(Interlocked.CompareExchange(ref begun,1,0)!=0)throw new InvalidOperationException("Registered runtime starts once");
        try
        {
            beforeSubmission?.Invoke();
            _=Task.Run(async()=>{try{completion.TrySetResult(await Run().ConfigureAwait(false));}catch(Exception error){started.TrySetException(error);completion.TrySetException(error);}});
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {
            // Only a synchronous failure before task submission is accepted
            // here. Failures inside Run remain faulted/unresolved above.
            phase="NOT_STARTED_NO_NATIVE_EFFECTS";startup="TASK_SUBMISSION_FAILED";
            var closure=new NativeClosureEvidence(1,runtimeId,null,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp(),Stopwatch.Frequency,
                "NOT_ENTERED",true,true,true,true){NoRunEntered=true};
            Volatile.Write(ref nativeClosure,closure);started.TrySetException(error);
            completion.TrySetResult(new(phase,null,startup,"NOT_OPENED",0,null,null,null,["TASK_SUBMISSION_FAILED:"+error.GetType().Name],null,"NOT_ENTERED",null){NativeClosure=closure});
        }
    }
    internal static LinuxControlledTargetSet? ValidatePreparedTargets(Qualification config)
    {
        _=LinuxOwnedLoaderProcess.BuildArguments(config.Launch);
        if(config.Launch.ControlVersion==1)
        {
            if(!config.ExpectedTargets.IsDefaultOrEmpty)throw new ArgumentException("Legacy launch cannot assert controlled-v2 target identities");
            return null;
        }
        if(config.ExpectedTargets.IsDefaultOrEmpty||config.ExpectedTargets.Length!=config.Launch.Targets.Length)throw new ArgumentException("Independently prepared identities required for every controlled-v2 target");
        return LinuxControlledTargetSet.Prepare(config.ExpectedTargets);
    }
    private void Wake()=>wake.Writer.TryWrite(1);
    // Neither method performs disk I/O, signals a numeric PID, or cancels an
    // actual method. Receipt retries are separate from native scheduling.
    internal void RequestStop(string reason="CONTROLLED_SOURCE_STOP_REQUESTED")
    {signedPolicy?.Invalidate();barrier.RequestStop(reason,DateTimeOffset.UtcNow);stop.TrySetResult();Wake();}
    internal void RetryReceipts(){Interlocked.Exchange(ref retryWork,1);retry.Writer.TryWrite(1);Wake();}
    // Used only by the actual companion owner. This never evaluates an event
    // or grants a whitelist decision; it reports a bounded historical sample.
    internal ServiceHealth ObserveServiceHealth()
    {
        ServiceHealth Unavailable(string reason)=>new(runtimeId,sensor,Phase,Session,null,null,null,null,null,null,reason);
        if(Phase!="ACTIVE"||signedPolicy==null)return Unavailable("LINUX_SOURCE_NOT_ACTIVE");
        var held=barrier.TryIssueObservation();if(held==null)return Unavailable("LINUX_SOURCE_HEALTH_SAMPLE_NOT_ADMITTED");
        var began=Stopwatch.GetTimestamp();var phase="PACKAGE_AND_TARGET_ADMISSION";
        var timings=new List<object>(8);var phaseBegan=began;
        void Next(string next)
        {
            var now=Stopwatch.GetTimestamp();timings.Add(new{Phase=phase,ElapsedMs=(long)((decimal)(now-phaseBegan)*1000/Stopwatch.Frequency)});
            phase=next;phaseBegan=now;
        }
        try
        {
            requireAdmissionCurrent?.Invoke();Next("POLICY_SAMPLE");var policySample=signedPolicy.Observe();
            if(policySample==null)return Unavailable(signedPolicy.UnavailableReason??"LINUX_NATIVE_POLICY_UNAVAILABLE");
            if(session==null||bank==null||loader==null||map==null||mapSet==null||controller==null||ingress?.Activated!=true||close!="NOT_ATTEMPTED")
                return Unavailable("LINUX_SOURCE_OWNER_MISMATCH");
            Next("JOURNAL_CONTROL");var journalHealth=journal.ReadSourceHealthControl(session);var control=journalHealth.Control;
            if(control?.Activated==null||control.Completion!=null||!journalHealth.ActivationWriteConfirmed||!mapSet.MatchesReadyFrame(control.Ready))
                return Unavailable("LINUX_SOURCE_CONTROL_MISMATCH");
            Next("READY_FRAME");var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
            if(ready.ControlVersion is not (2 or 3 or 4)||ready.Maps[3]!=map.Identity.Id||ready.Epoch.ToString(CultureInfo.InvariantCulture)!=bank.ProviderEpoch||ready.Targets?.Digest!=mapSet.Verified.TargetSetSha256)
                return Unavailable("LINUX_SOURCE_MAP_MISMATCH");
            Next("MAP_AND_CHILD_SAMPLE");var sampled=LinuxSourceHealthSampler.Capture(barrier,held.Issued.Generation,ready.Lost,map.Sample,
                ()=>Phase!="ACTIVE"||loader.HasExited||loader.FramingFault.IsCompleted||loader.Snapshot().StartupFailure!=null);
            if(sampled.Evidence==null)
            {
                if(sampled.Reason is "LINUX_SOURCE_LOSS_SAMPLE_FAILED" or "LINUX_SOURCE_LOSS_OBSERVED" or "LINUX_SOURCE_CHILD_UNAVAILABLE" or "LINUX_SOURCE_CHILD_CHECK_FAILED")Fault(sampled.Reason);
                return Unavailable(sampled.Reason);
            }
            Next("POLICY_RECHECK");if(!signedPolicy.StillCurrent(policySample))return Unavailable("LINUX_NATIVE_POLICY_CHANGED_DURING_SAMPLE");
            return new(runtimeId,sensor,Phase,session,bank.CollectorInstance,bank.ProviderEpoch,mapSet.Verified.TargetSetSha256,
                policySample.Snapshot.Trust.Digest,policySample.Snapshot.ExpiresUtc,sampled.Evidence,"LINUX_SOURCE_HEALTH_SAMPLED"){ControlVersion=ready.ControlVersion};
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {Fault("LINUX_SERVICE_HEALTH_SAMPLE_FAILED",error);return Unavailable("LINUX_SERVICE_HEALTH_SAMPLE_FAILED");}
        finally
        {
            try
            {
                Next("RETURNED");var elapsed=(long)((decimal)(Stopwatch.GetTimestamp()-began)*1000/Stopwatch.Frequency);
                if(elapsed>=1000)Notify(System.Text.Json.JsonSerializer.Serialize(new{Component="linux-native-health-source-sample",ElapsedMs=elapsed,Phases=timings}));
            }
            finally{barrier.Return(held);Wake();}
        }
    }
    private EventTrust? PrepareTrust(AgentEvent input,ActorLease actor)
    {
        if(signedPolicy==null)return TrustEventEvaluation.EvaluateLinuxKernel(trustCache!,sensor,trustGroup,input,actor,()=>ObserveMatchSource(input,actor).Evidence,DateTimeOffset.UtcNow);
        if(signedPolicy.Observe()==null){Fault(signedPolicy.UnavailableReason??"LINUX_NATIVE_POLICY_UNAVAILABLE");return null;}
        // Keep source/map/controller ownership through policy evaluation and
        // sampling. The inner observation reuses this exact hold.
        var hold=barrier.TryIssue(input.EventId);if(hold==null)return null;
        try
        {
            return signedPolicy.EvaluateCurrent(sample=>TrustEventEvaluation.EvaluateLinuxKernel((context,now)=>LinuxNativeSourcePolicy.Evaluate(sample,context,now),sensor,sample.Snapshot.Trust.GroupId,input,actor,
                ()=>ObserveMatchSource(input,actor,hold).Evidence,DateTimeOffset.UtcNow));
        }
        finally{barrier.Return(hold);Wake();}
    }
    // Sampled source facts are bound to the prepared decision by PrepareTrust.
    // Installed sensors do not call this qualified runtime yet.
    internal MatchSourceResult ObserveMatchSource(AgentEvent original,ActorLease actor)
        =>ObserveMatchSource(original,actor,null);
    private sealed record MatchSourceFacts(string SourceSessionId,string CollectorInstance,string ProviderEpoch,string ForensicPolicySha256,long SourceGeneration);
    private MatchSourceResult ObserveMatchSource(AgentEvent original,ActorLease actor,LinuxSourceWorkBarrier.Work? retainedHold)
    {
        if(Phase!="ACTIVE")return new(null,"LINUX_SOURCE_NOT_ACTIVE");
        var acquired=actor.AcquiredLinuxMatchEvidence(original);
        var native=original.Attribution?.LinuxKernel?.NativeSchemaVersion is 7 or 8;
        var actorEvent=actor.LinuxTrustEntry??original;
        MatchSourceFacts? facts=null;
        if(native&&actor.AcquiredLinuxNativeHash(actorEvent)!=null&&(actor.LinuxTrustEntry==null||LinuxNativeHashBinding.ActorHash(original,actorEvent)!=null)&&actor.LinuxNativeWork is {} work)facts=new(work.SourceSessionId,work.CollectorInstance,work.ProviderEpoch,work.PolicySha256,work.IssuedGeneration);
        else if(!native&&acquired.Evidence is {} legacy)facts=new(legacy.SourceSessionId,legacy.CollectorInstance,legacy.ProviderEpoch,legacy.ForensicPolicySha256,legacy.SourceGeneration);
        if(facts==null)return new(null,native?"LINUX_NATIVE_HASH_DESCRIPTOR_UNAVAILABLE":acquired.Reason);
        if(original.Forensics?.SensorId!=sensor||session!=facts.SourceSessionId||bank?.CollectorInstance!=facts.CollectorInstance||bank.ProviderEpoch!=facts.ProviderEpoch||
            loader==null||map==null||mapSet==null||controller==null||ingress?.Activated!=true||close!="NOT_ATTEMPTED")
            return new(null,"LINUX_SOURCE_OWNER_MISMATCH");
        // Reuse the owned drain barrier so teardown cannot dispose the actual
        // retained map/controller while this out-of-lock sample is running.
        // This is coordination only, never authorization for a native method.
        var hold=retainedHold??barrier.TryIssue(original.EventId);
        if(hold==null)return new(null,"LINUX_SOURCE_SAMPLE_NOT_ADMITTED");
        try
        {
            var source=journal.ReadSource(session);var control=journal.ReadSourceControl(session);
            if(source.State!="OPEN"||source.CollectorInstance!=facts.CollectorInstance||source.ProviderEpoch!=facts.ProviderEpoch||
                journal.ReadSourcePolicy(session)?.Sha256!=facts.ForensicPolicySha256||control?.Activated==null||control.Completion!=null||
                !journal.SourceActivationWriteConfirmed(session)||journal.ReadNativeWorkEvidence(actorEvent.EventId)!=actor.LinuxNativeWork)
                return new(null,"LINUX_SOURCE_CONTROL_MISMATCH");
            var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
            // ReadSourceControl already parses/binds the ACK version, epoch,
            // nonce, attached programs and zero activation loss to this ready
            // and session. Match all exact admitted ready bytes as well.
            if(!mapSet.MatchesReadyFrame(control.Ready)||ready.ControlVersion!=(native?4:2)||ready.Epoch.ToString(CultureInfo.InvariantCulture)!=facts.ProviderEpoch||ready.Maps[3]!=map.Identity.Id||
                ready.Targets?.Digest!=mapSet.Verified.TargetSetSha256)
                return new(null,"LINUX_SOURCE_MAP_MISMATCH");
            var result=LinuxSourceHealthSampler.Capture(barrier,facts.SourceGeneration,ready.Lost,map.Sample,
                ()=>Phase!="ACTIVE"||loader.HasExited||loader.FramingFault.IsCompleted||loader.Snapshot().StartupFailure!=null);
            if(result.Evidence==null)
            {
                if(result.Reason is "LINUX_SOURCE_LOSS_SAMPLE_FAILED" or "LINUX_SOURCE_LOSS_OBSERVED" or "LINUX_SOURCE_CHILD_UNAVAILABLE" or "LINUX_SOURCE_CHILD_CHECK_FAILED")Fault(result.Reason);
                return new(null,result.Reason,result.ErrorDomain,result.ErrorCode);
            }
            return new(new(session,facts.ProviderEpoch,facts.CollectorInstance,Convert.ToBase64String(control.Ready),
                Convert.ToHexString(SHA256.HashData(control.Ready)),Convert.ToBase64String(control.Activated),
                Convert.ToHexString(SHA256.HashData(control.Activated)),mapSet.Verified.TargetSetSha256,result.Evidence),result.Reason);
        }
        catch(Exception ex)when(ex is not OutOfMemoryException)
        {return new(null,"LINUX_SOURCE_OBSERVATION_FAILED",ex is System.ComponentModel.Win32Exception?"posix":"dotnet",
            (ex is System.ComponentModel.Win32Exception nativeError?nativeError.NativeErrorCode:ex.HResult).ToString(CultureInfo.InvariantCulture));}
        finally{if(retainedHold==null){barrier.Return(hold);Wake();}}
    }
    // Nonblocking latch/signal: never await/enter StopAndDrain here. Callers
    // may themselves hold a barrier entry that teardown must later drain.
    private void Fault(string reason,Exception? exception=null,string? sampledLost=null)
    {
        if(barrier.Current.State=="Closed")return;
        signedPolicy?.Invalidate();
        var current=Volatile.Read(ref ingress);
        var error=exception==null?null:exception.GetType().Name+":"+(exception is System.ComponentModel.Win32Exception n?n.NativeErrorCode:exception is Microsoft.Data.Sqlite.SqliteException sql?sql.SqliteExtendedErrorCode:exception.HResult).ToString(CultureInfo.InvariantCulture);
        if(current!=null)current.LatchFault(reason,error,sampledLost);else barrier.Fault(reason,DateTimeOffset.UtcNow);
        if(error!=null&&errors.Count<32)errors.Enqueue(reason+":"+error);
        stop.TrySetResult();Wake();
    }
    private void Notify(string message)
    {try{report(message);}catch(Exception e){if(errors.Count<32)errors.Enqueue("REPORT_FAILED:"+e.GetType().Name);}}
    private static string Digest(string path)
    {EvidenceDurability.NoLinks(path);using var file=File.OpenRead(path);return Convert.ToHexString(SHA256.HashData(file));}
    private void ValidatePackage()
    {
        if(File.ReadAllText("/proc/sys/kernel/osrelease").Trim()!=config.Kernel||!Digest("/sys/kernel/btf/vmlinux").Equals(config.BtfSha256,StringComparison.OrdinalIgnoreCase)||
            !Digest(config.Launch.Loader).Equals(config.LoaderSha256,StringComparison.OrdinalIgnoreCase)||!Digest(config.Launch.ObjectFile).Equals(config.ObjectSha256,StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Qualification kernel/BTF/loader/object differs from pinned artifacts");
        EvidenceStore.EnsurePrivate(config.Directory);EvidenceDurability.DirectoryCommitted(config.Directory);
    }
    private void RequireLiveStartup()
    {
        requireAdmissionCurrent?.Invoke();
        if(signedPolicy?.UnavailableReason is {} reason){Fault(reason);throw new LinuxNativePolicyUnavailableException(reason);}
        if(barrier.Current.State!="Active"||loader==null||loader.HasExited||loader.FramingFault.IsCompleted||loader.Snapshot().StartupFailure!=null)
            throw new InvalidOperationException("Owned loader or source barrier is no longer available for activation");
    }
    private Task QualifyStartup(string point,LinuxControlledLoaderProtocol.Ready ready,byte[] readyBytes)
        =>qualificationCheckpoint==null?Task.CompletedTask:qualificationCheckpoint(new(point,ready,
            Convert.ToHexString(SHA256.HashData(readyBytes)),session,Phase,controller!=null,loader!.ActivationAttempted),loader!);
    private static LinuxForensicJournal.OwnerMethodReturn MethodReturn(string id,string method,DateTimeOffset utc,long tick,Exception? error)
        =>new(1,Guid.NewGuid().ToString("N"),id,method,utc,DateTimeOffset.UtcNow,tick,Stopwatch.GetTimestamp(),Stopwatch.Frequency,error==null?"returned":"threw",
            error?.GetType().FullName,error==null?null:error is System.ComponentModel.Win32Exception?"posix":"dotnet",
            error==null?null:(error is System.ComponentModel.Win32Exception n?n.NativeErrorCode:error.HResult).ToString(CultureInfo.InvariantCulture));
    private async Task<Outcome> Run()
    {
        try
        {
            RecordStartup("STARTUP_ENTERED");
            journal.AdmitOwnedRuntime();journalAdmitted=true;pipeline.CapacityReturned+=Wake;
            RecordStartup("JOURNAL_ADMITTED");
            requireAdmissionCurrent?.Invoke();
            ValidatePackage();
            RecordStartup("PACKAGE_VALIDATED");
            if(stop.Task.IsCompleted)throw new InvalidOperationException("Registered source was stopped before native startup");
            if(signedPolicy?.UnavailableReason!=null)throw new InvalidDataException("Native signed policy unavailable before loader launch");
            using var prepared=LinuxRawIngressReserve.Prepare(Path.Combine(config.Directory,"raw"),sensor,Guid.NewGuid().ToString("N"),config.RawSlots,
                quotaDirectory:Path.GetDirectoryName(config.Directory)!,quotaBytes:LinuxNativeRawStorageCapacity.RequireQuota(config.RawBankQuotaBytes));
            RecordStartup("RAW_STORAGE_PREPARED");
            EvidenceDurability.SaveNew(Path.Combine(config.Directory,"raw-preparation.json"),JsonSerializer.SerializeToUtf8Bytes(new{
                Version=1,AttemptId=prepared.Collector,SensorId=sensor,ProviderEpoch=(string?)null,SourceSession=(string?)null,
                prepared.Identity,prepared.Slots,prepared.PhysicalAllocationEstablished,prepared.StartedUtc,prepared.CompletedUtc,
                prepared.StartedMonotonic,prepared.CompletedMonotonic,MonotonicFrequency=Stopwatch.Frequency,
                Scope="Held raw storage prepared before loader launch; no native epoch, links, source activation or file-operation authority"}));
            requireAdmissionCurrent?.Invoke();
            if(stop.Task.IsCompleted)throw new InvalidOperationException("Registered source stopped during raw preparation");
            if(signedPolicy?.UnavailableReason is {} preparationReason)throw new LinuxNativePolicyUnavailableException(preparationReason);
            loader=LinuxOwnedLoaderProcess.Start(config.Launch,_=>Fault("LOADER_FRAMING_FAILED"));
            RecordStartup("LOADER_STARTED");
            using var readiness=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var frameWait=loader.ReadFrameAsync(readiness.Token).AsTask();
            if(await Task.WhenAny(frameWait,stop.Task).ConfigureAwait(false)==stop.Task)readiness.Cancel();
            var readyBytes=await frameWait.ConfigureAwait(false)??throw new EndOfStreamException("Owned ready frame missing");
            RecordStartup("READY_FRAME_RECEIVED");
            EvidenceDurability.SaveNew(Path.Combine(config.Directory,"ready-frame.bin"),readyBytes);
            RecordStartup("READY_FRAME_SAVED");
            var ready=LinuxControlledLoaderProtocol.ParseReady(readyBytes);RequireLiveStartup();
            if(ready.ControlVersion!=config.Launch.ControlVersion)throw new InvalidDataException("Owned loader control version differs from explicit qualification launch");
            if(ready.ControlVersion is 2 or 3 or 4)
            {
                // Qualified entry point only. Exact independently prepared
                // identities must match both native ready and the frozen map.
                mapSet=LinuxControlledMapSet.Open(ready,ValidatePreparedTargets(config)!);RequireLiveStartup();
                RecordStartup("MAP_SET_VALIDATED");
                EvidenceDurability.SaveNew(Path.Combine(config.Directory,"source-map-proof.json"),JsonSerializer.SerializeToUtf8Bytes(new{
                    Version=1,ReadyFrameSha256=Convert.ToHexString(SHA256.HashData(readyBytes)),Proof=mapSet.Verified,
                    Scope="Independent read-only map identity/config/loss/target validation; freeze established by qualified pinned loader"}));
                RecordStartup("MAP_PROOF_SAVED");
                RequireLiveStartup();
                await QualifyStartup("MAP_PROOF_SAVED",ready,readyBytes).ConfigureAwait(false);RequireLiveStartup();
            }
            map=LinuxBpfLostMap.Open(ready.Maps[3],ready.Lost,ready.ControlVersion is 3 or 4);RequireLiveStartup();
            RecordStartup("LOST_MAP_OPENED");
            await QualifyStartup("LOST_MAP_OPENED",ready,readyBytes).ConfigureAwait(false);RequireLiveStartup();
            bank=new(prepared,ready.Epoch.ToString(CultureInfo.InvariantCulture),rotating:config.Launch.ControlVersion==4,
                quotaDirectory:Path.GetDirectoryName(config.Directory)!,quotaBytes:config.RawBankQuotaBytes);
            RecordStartup("RAW_BANK_BOUND");
            var source=journal.PrepareControlledSource(bank,policy,ready.Lost.ToString(CultureInfo.InvariantCulture),DateTimeOffset.UtcNow,LinuxNativeRawStorageCapacity.RequireQuota(config.RawBankQuotaBytes));session=source.Id;
            RecordStartup("SOURCE_PREPARED");
            journal.RecordSourceOwnerOpenAttempt(session,DateTimeOffset.UtcNow);RequireLiveStartup();
            RecordStartup("CONTROLLER_OPEN_INTENT_RECORDED");
            var openUtc=DateTimeOffset.UtcNow;var openTick=Stopwatch.GetTimestamp();
            try{controller=new LinuxActorLeaseDevice(controllerOpen);opened=MethodReturn(session,"OPEN",openUtc,openTick,null);}
            catch(Exception e){opened=MethodReturn(session,"OPEN",openUtc,openTick,e);throw;}
            RecordStartup("CONTROLLER_OPENED");
            if(ready.ControlVersion is 3 or 4)controller.RegisterAtomicSource(ready.Epoch);
            journal.RecordOwnerMethodReturn(session,opened);journal.CommitSourceControlLink(session,readyBytes,DateTimeOffset.UtcNow);linked=true;
            RecordStartup("SOURCE_CONTROL_LINKED");
            ingress=new(journal,bank,barrier,session);native=new(journal,barrier,controller,session);
            rawPump=Task.Run(Pump);
            // Admission performs durable synchronous I/O before START. Keep its
            // single owner off the shared pool, where raw ingress/enrichment
            // can delay it beyond an already retained executable's deadline.
            dispatcher=Task.Factory.StartNew(Dispatch,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
            sampler=Task.Run(()=>SampleLoss(ready.Lost));
            RecordStartup("WORKERS_SCHEDULED");
            RequireLiveStartup();ulong? sample=null;Exception? sampleError=null;
            try{sample=map.Sample();}catch(Exception e)when(e is not OutOfMemoryException){sampleError=e;}
            var command=LinuxControlledLoaderProtocol.ActivationFrame(ready,session);
            journal.CommitSourceActivationSample(session,new(2,Guid.NewGuid().ToString("N"),session,bank.ProviderEpoch,map.Identity,
                Convert.ToHexString(SHA256.HashData(readyBytes)),Convert.ToHexString(SHA256.HashData(command)),command.Length,sample?.ToString(CultureInfo.InvariantCulture),
                sampleError==null?null:sampleError.GetType().Name+":"+(sampleError is System.ComponentModel.Win32Exception mapError?mapError.NativeErrorCode:sampleError.HResult).ToString(CultureInfo.InvariantCulture),
                DateTimeOffset.UtcNow,Stopwatch.GetTimestamp(),Stopwatch.Frequency));
            RecordStartup("ACTIVATION_SAMPLE_COMMITTED");
            if(sampleError!=null)throw new IOException("Prewrite loss sample unavailable",sampleError);
            RequireLiveStartup();
            await QualifyStartup("LINKED_PREWRITE",ready,readyBytes).ConfigureAwait(false);RequireLiveStartup();
            journal.MarkSourceControlWriteStarted(session,DateTimeOffset.UtcNow);RequireLiveStartup();
            RecordStartup("ACTIVATION_INTENT_COMMITTED");
            phase="AWAITING_ACK";write=loader.ActivateOnce(ready,session);
            RecordStartup("ACTIVATION_WRITE_RETURNED");
            journal.RecordSourceActivationWrite(session,write);Wake();
            RecordStartup("ACTIVATION_RETURN_COMMITTED");
            if(!journal.SourceActivationWriteConfirmed(session))throw new IOException("Actual activation write or EOF failed");
            using var ackDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            RecordStartup("ACK_WAIT_ENTERED");
            await Task.WhenAny(activated.Task,stop.Task).WaitAsync(ackDeadline.Token).ConfigureAwait(false);
            RequireLiveStartup();if(!activated.Task.IsCompletedSuccessfully)throw new IOException("Source stopped before activation acknowledgement");
            phase="ACTIVE";RecordStartup("STARTUP_READY");started.TrySetResult();Wake();await stop.Task.ConfigureAwait(false);
        }
        catch(Exception e)when(e is not OutOfMemoryException)
        {
            RecordStartup("STARTUP_FAILED");
            // Constructors aggregate a failed cleanup when an actual descriptor
            // close is uncertain. A missing returned object is not absence.
            if(e is AggregateException)nativeAcquisitionUnresolved=true;
            // Do not perform another possibly failing DB read in the unwind
            // path. Linking is confirmed only after its actual call returns.
            startup=controller==null?"FAILED_NO_CONTROLLER":!linked?"FAILED_CONTROLLER_OPENED_UNLINKED":"FAILED_AFTER_LINK";
            // Policy expiry is already recorded at its actual boundary. Keep
            // the startup stage visible, but do not manufacture a second I/O
            // failure that prevents recovery after verified native closure.
            if(e is not LinuxNativePolicyUnavailableException {Reason:"LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED"})
                Fault("OWNED_SOURCE_STARTUP_FAILED",e);
            started.TrySetException(e);
        }
        phase=barrier.Current.State=="Faulted"?"DISABLED_DRAINING":"STOPPING_DRAINING";
        if(!started.Task.IsCompleted)started.TrySetException(new IOException("Source stopped before activation"));
        try
        {
            await StopAndDrain().ConfigureAwait(false);
        }
        catch(Exception e)when(e is not OutOfMemoryException)
        {Fault("OWNED_SOURCE_DRAIN_FAILED",e);Notify("Owned source remains unresolved: "+e.GetType().Name);}
        int? pending=null,unindexed=null;bool? backlog=null;
        try{pending=session==null?0:journal.Pending().Length;backlog=session!=null&&bank!=null&&journal.ReadDeferredCanonical(session,bank).Length!=0;unindexed=session!=null&&bank!=null?journal.CountUnindexedRaw(session,bank):0;}
        catch(Exception e){errors.Enqueue("PENDING_INVENTORY_UNAVAILABLE:"+e.GetType().Name);}
        var diagnostic=loader?.Snapshot();var records=bank?.Entries.Length??0;
        var mapClosed=map==null;var mapSetClosed=mapSet==null;var childClosed=loader==null;
        if(controller==null||close=="CLOSE_RETURNED_OK"||close=="CLOSE_RETURNED_ERROR")
        {
            try{map?.Dispose();mapClosed=true;}catch(Exception e){errors.Enqueue("MAP_CLOSE_FAILED:"+e.GetType().Name);}
            try{mapSet?.Dispose();mapSetClosed=true;}catch(Exception e){errors.Enqueue("MAP_SET_CLOSE_FAILED:"+e.GetType().Name);}
            try
            {
                if(loader?.Completion.IsCompletedSuccessfully==true)loader.Dispose();diagnostic=loader?.Snapshot();
                childClosed=loader==null||diagnostic is {State:"DISPOSED",InputClose:{Result:0,Error:0,ManagedFailure:null}}&&
                    (diagnostic.PidfdClose==null||diagnostic.PidfdClose is {Result:0,Error:0,ManagedFailure:null});
            }
            catch(Exception e){errors.Enqueue("CHILD_DISPOSAL_FAILED:"+e.GetType().Name);}
            try{bank?.Dispose();}catch(Exception e){errors.Enqueue("RAW_BANK_CLOSE_FAILED:"+e.GetType().Name);}
        }
        if(nativeWorkDrained&&!nativeAcquisitionUnresolved&&mapClosed&&mapSetClosed&&childClosed&&
            (loader==null||loader.Completion.IsCompletedSuccessfully)&&
            (controller==null?controllerOpen.NoDescriptorRemains:close=="CLOSE_RETURNED_OK"))
            Volatile.Write(ref nativeClosure,new(1,runtimeId,session,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp(),Stopwatch.Frequency,
                controller==null?(controllerOpen.Entered?"OPEN_FAILED_NO_DESCRIPTOR_REMAINS":"NOT_OPENED"):"CLOSE_RETURNED_OK",true,true,true,true));
        pipeline.CapacityReturned-=Wake;
        var ownerReleased=!journalAdmitted;
        if(journalAdmitted&&(session==null||controller==null&&noControllerCompleted!=null||close=="CLOSE_RETURNED_OK"))
            try{journal.ReleaseOwnedRuntime(session);ownerReleased=true;}catch(Exception e){errors.Enqueue("OWNER_RELEASE_UNRESOLVED:"+e.GetType().Name);}
        phase=!ownerReleased?"RECONCILIATION_REQUIRED":session!=null&&(rawRecoveryState!="COMPLETE"||pending!=0||backlog!=false||unindexed!=0)?"RECOVERY_PENDING":"COMPLETED";
        var outcome=new Outcome(phase,session,startup,close,records,pending,backlog,barrier.Current.FirstInterruption,errors.ToArray(),diagnostic,rawRecoveryState,unindexed){NativeClosure=nativeClosure,StartupTimings=StartupTimeline()};
        try{if(Directory.Exists(config.Directory))EvidenceDurability.SaveNew(Path.Combine(config.Directory,"outcome.json"),JsonSerializer.SerializeToUtf8Bytes(outcome));}
        catch(Exception e){Notify("Runtime outcome file unavailable: "+e.GetType().Name);}
        return outcome;
    }
    private async Task Pump()
    {
        try
        {
            while(await loader!.ReadFrameAsync().ConfigureAwait(false) is {} raw)
            {
                try
                {
                    _ =ingress!.Receive(raw,DateTimeOffset.UtcNow);
                    if(ingress.Activated&&!activated.Task.IsCompleted)
                    {RecordStartup("ACK_INGRESS_COMMITTED");activated.TrySetResult();}
                    Wake();
                }
                catch(Exception e)when(e is not OutOfMemoryException){Fault("RAW_INGRESS_FAILED",e);}
            }
        }
        catch(Exception e)when(e is not OutOfMemoryException){Fault("LOADER_STREAM_FAILED",e);}
        finally{Interlocked.Exchange(ref rawDone,1);Fault("LOADER_STREAM_ENDED");Wake();}
    }
    private async Task SampleLoss(ulong baseline)
    {
        try
        {
            while(!samplerStop.IsCancellationRequested)
            {
                requireAdmissionCurrent?.Invoke();
                if(loader!.HasExited){Fault("LOADER_EXITED");return;}
                if(signedPolicy?.UnavailableReason is {} reason){Fault(reason);return;}
                var sample=map!.SampleDetailed();if(sample.Total!=baseline)
                {
                    // Keep the observed breakdown with the source's terminal
                    // evidence. Do not infer a category from the aggregate.
                    errors.Enqueue("LOADER_HEALTH_COUNTERS:"+string.Join(",",sample.Values.Select(x=>x.ToString(CultureInfo.InvariantCulture))));
                    Fault("LOADER_LOSS_CHANGED",sampledLost:sample.Total.ToString(CultureInfo.InvariantCulture));return;
                }
                await Task.Delay(100,samplerStop.Token).ConfigureAwait(false);
            }
        }
        catch(OperationCanceledException)when(samplerStop.IsCancellationRequested){}
        catch(Exception e)when(e is not OutOfMemoryException){Fault("LOADER_LOSS_SAMPLE_FAILED",e);}
    }
    private void Dispatch()
    {
        if(Thread.CurrentThread.IsThreadPoolThread)throw new InvalidOperationException("Native admission requires its dedicated dispatcher");
        Notify("NATIVE_DISPATCH_DEDICATED_THREAD");
        var running=new Dictionary<string,Task<LinuxSerialNativeWorker.ReturnReceipt?>>(StringComparer.Ordinal);
        var prepared=new Dictionary<string,Task>(StringComparer.Ordinal);var failed=new HashSet<string>(StringComparer.Ordinal);
        Task? managedDrain=null;Wake();
        try
        {
            while(true)
            {
                wake.Reader.ReadAsync().AsTask().GetAwaiter().GetResult();while(wake.Reader.TryRead(out _)){}
                if(Interlocked.Exchange(ref retryWork,0)!=0)
                {
                    try{AbortUnscheduled();native!.RetryUncommittedReturnsAsync().GetAwaiter().GetResult();ingress!.PersistFaultOnce();}
                    catch(Exception e)when(e is not OutOfMemoryException){Fault("NATIVE_RECEIPT_RETRY_FAILED",e);}
                }
                foreach(var item in running.Where(x=>x.Value.IsCompleted).ToArray())
                {
                    try{item.Value.GetAwaiter().GetResult();}catch(Exception e)when(e is not OutOfMemoryException){Fault("NATIVE_WORK_FAILED",e);}
                    running.Remove(item.Key);
                }
                foreach(var item in prepared.Where(x=>x.Value.IsCompleted).ToArray())
                {
                    prepared.Remove(item.Key);
                    if(!journal.Read(item.Key).Done){failed.Add(item.Key);Fault("PREPARED_DELIVERY_FAILED");}
                }
                if(barrier.Current.State!="Active")
                {
                    stop.TrySetResult();
                    // No native admission is in progress once this serial
                    // dispatcher reaches the seal. Receipt retries remain live.
                    managedDrain??=native!.FinishScheduling();
                    try{ingress!.LatchFault(barrier.Current.Reason??"SOURCE_STOPPED");ingress.PersistFaultOnce();}
                    catch(Exception e)when(e is not OutOfMemoryException){Fault("SOURCE_FAULT_RECEIPT_FAILED",e);}
                }
                else if(ingress!.Activated&&journal.SourceActivationWriteConfirmed(session!))
                {
                    foreach(var entry in journal.ReadDeferredCanonical(session!,bank!))
                    {
                        // The four permits bound native work, not forensic delivery.
                        // A completed copy must release its slot even when hashing,
                        // preservation or export has queued managed completions.
                        // Counting all journal work here delayed START behind that
                        // backlog and let already retained executables expire.
                        if(running.Count>=4||journal.Pending().Length>=journal.PendingWorkLimit)break;
                        RequireLiveStartup();var index=journal.IndexRawIngress(session!,bank!,entry);
                        if(index.Status is not ("RAW_VALID" or "DUPLICATE")||index.CanonicalEventId==null)continue;
                        var token=barrier.TryIssue(index.CanonicalEventId);if(token==null)break;
                        LinuxForensicJournal.NativePinClaim? claim=null;
                        try
                        {
                            claim=journal.CommitNativePin(session!,bank!,entry,barrier,token);
                            // Register the completion owner before starting any
                            // actual native work. A rejected slot cannot leave
                            // an already running call outside this dictionary.
                            var tracked=new TaskCompletionSource<LinuxSerialNativeWorker.ReturnReceipt?>(TaskCreationOptions.RunContinuationsAsynchronously);
                            running.Add(token.EventId,tracked.Task);
                            _=RunTracked(claim,tracked);
                        }
                        catch
                        {
                            if(claim==null)barrier.Return(token);
                            else if(!claim.Started&&!claim.Returned){unscheduled.Add(token.EventId,claim);AbortUnscheduled();}
                            throw;
                        }
                    }
                }
                foreach(var id in journal.Pending())
                {
                    if(running.ContainsKey(id)||prepared.ContainsKey(id)||failed.Contains(id))continue;
                    var pin=journal.ReadNativePin(id);
                    if(pin?.State is "PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED"||native!.PendingPreNativeFailures.Any(x=>x.Claim.Intent.EventId==id)||native.UncommittedReturns.Any(x=>x.Claim.Intent.EventId==id))continue;
                    // Return enrichment must observe the entry's committed actor
                    // outcome, rather than winning a race with entry preservation.
                    // This delays delivery only; native acquisition remains separate.
                    if(!journal.IoEntryCompletionAvailable(id))continue;
                    var returned=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    if(pipeline.TrySubmitPrepared(journal,id,spool,returned:()=>{returned.TrySetResult();Wake();},prepareTrust:trustCache==null&&signedPolicy==null?null:PrepareTrust))prepared.Add(id,returned.Task);
                }
                // Unscheduled durable delivery is recoverable separately and
                // must not hold an otherwise drained controller open for a
                // permit owned by unrelated producers.
                if(managedDrain?.IsCompletedSuccessfully==true&&unscheduled.Count==0&&Volatile.Read(ref rawDone)!=0&&running.Count==0&&prepared.Count==0)return;
            }
        }
        catch(Exception e)when(e is not OutOfMemoryException)
        {
            Fault("SOURCE_DISPATCH_FAILED",e);
            Task.WhenAll(running.Values.Select(async task=>{try{await task.ConfigureAwait(false);}catch{}})).GetAwaiter().GetResult();
            Task.WhenAll(prepared.Values.Select(async task=>{try{await task.ConfigureAwait(false);}catch(Exception failure){Fault("PREPARED_CALLBACK_FAILED",failure);}})).GetAwaiter().GetResult();
            // Teardown separately waits the barrier and retained receipt-only
            // work. A failed dispatcher must not manufacture their completion.
        }
    }
    private async Task RunTracked(LinuxForensicJournal.NativePinClaim claim,TaskCompletionSource<LinuxSerialNativeWorker.ReturnReceipt?> tracked)
    {
        Task<LinuxSerialNativeWorker.ReturnReceipt?> task;
        try{task=native!.RunAsync(claim);}
        catch(Exception e)
        {
            // Synchronous admission rejection means the worker never owned
            // this claim. This prefix runs on the serial dispatcher, before
            // the first await; its abort remains retryable by that owner.
            unscheduled.Add(claim.Intent.EventId,claim);
            try{AbortUnscheduled();}catch(Exception abort){Fault("UNSCHEDULED_ABORT_UNCOMMITTED",abort);}
            tracked.TrySetException(e);Wake();return;
        }
        try{tracked.TrySetResult(await task.ConfigureAwait(false));}
        catch(Exception e){tracked.TrySetException(e);}
        finally{Wake();}
    }
    private void AbortUnscheduled()
    {
        foreach(var claim in unscheduled.Values.ToArray())
        {
            journal.AbortNativePinBeforeStart(claim);unscheduled.Remove(claim.Intent.EventId);
        }
    }
    private async Task PersistReturned(Action save,string reason)
    {
        while(true)
        {
            try{save();return;}
            catch(Exception e)when(e is not OutOfMemoryException)
            {
                Fault(reason,e);Notify(reason+": retained original receipt; native call will not be repeated");
                await retry.Reader.ReadAsync().ConfigureAwait(false);
            }
        }
    }
    private async Task StopAndDrain()
    {
        var barrierDrain=barrier.BeginClose("CONTROLLED_SOURCE_CLOSE",DateTimeOffset.UtcNow);
        if(loader!=null)
        {
            try{loader.RequestStop();}catch(Exception e)when(e is not OutOfMemoryException){Fault("LOADER_STOP_SIGNAL_FAILED",e);}
            if(rawPump!=null)await rawPump.ConfigureAwait(false);
            else
            {
                // Startup never activated a source. Consume the bounded owned
                // queue so the child and both pipe drains can actually finish.
                try{while(await loader.ReadFrameAsync().ConfigureAwait(false)!=null){}}
                catch(Exception e)when(e is not OutOfMemoryException){Fault("STARTUP_STREAM_FAILED",e);}
                Interlocked.Exchange(ref rawDone,1);
            }
            await loader.Completion.ConfigureAwait(false);samplerStop.Cancel();if(sampler!=null)await sampler.ConfigureAwait(false);Wake();
        }
        if(dispatcher!=null)
            try{await dispatcher.ConfigureAwait(false);}catch(Exception e)when(e is not OutOfMemoryException){Fault("DISPATCH_DRAIN_FAILED",e);}
        if(native!=null)
        {
            var drain=native.FinishScheduling();
            while(!drain.IsCompleted||unscheduled.Count!=0)
            {
                await retry.Reader.ReadAsync().ConfigureAwait(false);
                try{AbortUnscheduled();await native.RetryUncommittedReturnsAsync().ConfigureAwait(false);}catch(Exception e)when(e is not OutOfMemoryException){Fault("NATIVE_DRAIN_RECEIPT_FAILED",e);}
            }
            await drain.ConfigureAwait(false);
        }
        await barrierDrain.ConfigureAwait(false);
        nativeWorkDrained=true;
        if(session!=null)
        {
            await PersistReturned(()=>
            {
                try
                {
                    if(ingress!=null){ingress.LatchFault(barrier.Current.FirstInterruption!.Reason);ingress.PersistFaultOnce();}
                    else
                    {
                        var first=barrier.Current.FirstInterruption!;
                        startupFault??=new(first.Reason,first.RecordedUtc,null,journal.ReadSource(session).LatestLost,null,null,null,[],UnresolvedStatus:"unavailable");
                        journal.TransitionSource(session,"CONTINUITY_FAULTED",startupFault,deduplicate:true);
                    }
                }
                catch
                {
                    bank?.RecordBoundary(barrier.Current.FirstInterruption!.Reason,barrier.Current,null,"SOURCE_FIRST_FAULT_UNCOMMITTED");throw;
                }
            },"SOURCE_FIRST_FAULT_UNCOMMITTED").ConfigureAwait(false);
        }
        if(session!=null&&opened!=null)await PersistReturned(()=>journal.RecordOwnerMethodReturn(session,opened),"OPEN_RETURN_UNCOMMITTED").ConfigureAwait(false);
        if(session!=null&&write!=null)await PersistReturned(()=>journal.RecordSourceActivationWrite(session,write),"ACTIVATION_RETURN_UNCOMMITTED").ConfigureAwait(false);
        // Input has drained and all dispatcher/native workers have returned.
        // Seal before actual close to remove the normal close-to-seal crash
        // window. A storage failure is retried after close, never used to keep
        // the native controller open for optional evidence I/O.
        if(bank!=null)
        {
            rawSealedUtc??=DateTimeOffset.UtcNow;
            try
            {
                if(loader?.FramingFault.IsCompletedSuccessfully==true&&bank.CanAppend)
                {
                    var frame=loader.FramingFault.Result;
                    bank.RecordBoundary("LOADER_FRAMING_FAILED",barrier.Current,frame.BufferedPrefix.Length,Convert.ToHexString(SHA256.HashData(frame.BufferedPrefix.Span)));
                }
                bank.SealInput(rawSealedUtc.Value);
            }
            catch(Exception e)when(e is not OutOfMemoryException){Fault("RAW_INPUT_SEAL_UNCOMMITTED",e);Notify("Raw input seal retained for retry after native close: "+e.GetType().Name);}
        }
        if(controller==null)
        {
            if(session!=null)
            {
                noControllerCompleted??=DateTimeOffset.UtcNow;
                await PersistReturned(()=>journal.RecordSourceNoController(session,opened,noControllerCompleted.Value),"NO_CONTROLLER_TERMINAL_UNCOMMITTED").ConfigureAwait(false);
            }
            await RecoverRawAfterClose().ConfigureAwait(false);await PersistFramingEvidence().ConfigureAwait(false);return;
        }
        close="CLOSE_UNKNOWN_OPEN";
        await PersistReturned(()=>
        {
            // A transient read failure while preparing the intent must retain
            // the live teardown owner and its retry path, just like a failed
            // write. No controller call has occurred at this stage.
            closeIntent??=new("OWNED_CONTROLLER_CLOSE",DateTimeOffset.UtcNow,null,journal.ReadSource(session!).LatestLost,null,"not-resampled-after-loader-exit",null,[],UnresolvedStatus:"unavailable");
            journal.TransitionSource(session!,"CLOSE_UNKNOWN_OPEN",closeIntent,deduplicate:true);
        },"CLOSE_INTENT_UNCOMMITTED").ConfigureAwait(false);
        var utc=DateTimeOffset.UtcNow;var tick=Stopwatch.GetTimestamp();
        try{controller.Dispose();closed=MethodReturn(session!,"CLOSE",utc,tick,null);}
        catch(Exception e)when(e is not OutOfMemoryException){closed=MethodReturn(session!,"CLOSE",utc,tick,e);close="CLOSE_RETURNED_ERROR";Fault("CONTROLLER_CLOSE_FAILED",e);}
        if(closed.Outcome=="returned")close="CLOSE_RETURN_UNCOMMITTED";
        await PersistReturned(()=>journal.RecordOwnerMethodReturn(session!,closed),"CLOSE_RETURN_UNCOMMITTED").ConfigureAwait(false);
        if(closed.Outcome=="returned")
        {
            await PersistReturned(()=>journal.RecordSourceCloseReturned(session!,closed.ReturnedUtc),"CLOSED_STATE_UNCOMMITTED").ConfigureAwait(false);
            barrier.RecordCloseReturned();close="CLOSE_RETURNED_OK";
        }
        if(close=="CLOSE_RETURNED_OK")await RecoverRawAfterClose().ConfigureAwait(false);
        await PersistFramingEvidence().ConfigureAwait(false);
    }
    private async Task RecoverRawAfterClose()
    {
        if(session==null||bank==null){rawRecoveryState="NOT_APPLICABLE";return;}
        phase="RECOVERING_STOPPED_INPUT";rawRecoveryState="UNRESOLVED";
        rawSealedUtc??=DateTimeOffset.UtcNow;
        await PersistReturned(()=>bank.SealInput(rawSealedUtc.Value),"RAW_INPUT_SEAL_UNCOMMITTED").ConfigureAwait(false);
        await PersistReturned(()=>journal.RecoverStoppedRaw(session,bank),"RAW_REINDEX_UNCOMMITTED").ConfigureAwait(false);
        rawRecoveryState="INDEXED_DELIVERY_PENDING";
        if(await journal.DeliverStoppedRaw(session,bank,pipeline,spool).ConfigureAwait(false))rawRecoveryState="COMPLETE";
    }
    private async Task PersistFramingEvidence()
    {
        if(loader?.FramingFault.IsCompletedSuccessfully!=true)return;
        // Native work and the one actual controller close have already
        // returned. Retrying this optional archive keeps only bounded bytes
        // and evidence ownership alive, never an open controller capability.
        phase="RECONCILING_FRAMING_EVIDENCE";var frame=loader.FramingFault.Result;
        await PersistReturned(()=>
        {
            var path=Path.Combine(config.Directory,"framing-prefix.bin");
            if(!File.Exists(path))EvidenceDurability.SaveNew(path,frame.BufferedPrefix.Span);
            else if(!File.ReadAllBytes(path).AsSpan().SequenceEqual(frame.BufferedPrefix.Span))throw new InvalidDataException("Original framing prefix changed");
            // The raw input is sealed independently. Its emergency boundary
            // was attempted before sealing; optional prefix retries cannot
            // mutate that input or repeat controller work.
        },"FRAMING_EVIDENCE_UNCOMMITTED").ConfigureAwait(false);
    }
}
