using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Owns the admitted module and its single registered source runtime. Installed
// activation remains opt-in; qualification callbacks are never configuration.
// Loaded/unknown owners retain their admission holds and their live registry
// reference; neither GC nor Dispose is a module unload/recovery mechanism.
internal sealed class LinuxNativeModuleOwner:IDisposable
{
    private const string ModuleName="sq_actor_lease";
    // R18 uses the R16 source with qualification fault controls compiled out.
    // Its exact module passed the controlled native gate on the pinned kernel/BTF;
    // a manifest-selected name/hash alone is not that proof.
    internal const string QualifiedModuleSha256="A2D56043FE0F598B002070539880C905AE8394D10D4E5D3048DB1AF35618B24E";
    [DllImport("libc",EntryPoint="syscall",SetLastError=true)]private static extern long LoadModule(long number,SafeFileHandle file,string parameters,int flags);
    [DllImport("libc",EntryPoint="syscall",SetLastError=true)]private static extern long UnloadModule(long number,string name,int flags);
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    private static readonly ConcurrentDictionary<string,LinuxNativeModuleOwner> live=new();
    private readonly object gate=new();
    private readonly LinuxNativePackageAdmission package;
    private readonly LinuxNativeTargetAdmission targets;
    private readonly LinuxNativeAdmissionHold packageHold,targetHold;
    private readonly LinuxProtectedDirectory journal;
    private readonly string directory;
    private readonly Action<string>? qualificationCheckpoint;
    private string state="Prepared";
    private int sequence;
    private string? previousHash;
    private (string Name,byte[] Bytes)? pending;
    private Action? pendingCommitted;
    private bool disposed,releasing;
    private bool targetReleased,packageReleased,journalReleased;
    private LinuxControlledSourceRuntime? source;
    private bool sourceBeginAttempted,sourceClosureRecorded;
    internal LinuxControlledSourceRuntime? RegisteredSource {get{lock(gate)return source;}}
    internal string OwnerId {get;}=Guid.NewGuid().ToString("N");
    internal string State {get{lock(gate)return state;}}
    internal string EvidenceDirectory=>directory;
    internal sealed record Call(DateTimeOffset AttemptedUtc,DateTimeOffset ReturnedUtc,long AttemptedMonotonic,long ReturnedMonotonic,long MonotonicFrequency,long Result,int Error);
    internal Call? LoadReturn {get;private set;}
    internal Call? UnloadReturn {get;private set;}
    private LinuxNativeModuleOwner(LinuxNativePackageAdmission package,LinuxNativeTargetAdmission targets,
        LinuxNativeAdmissionHold packageHold,LinuxNativeAdmissionHold targetHold,LinuxProtectedDirectory journal,string directory,Action<string>? qualificationCheckpoint)
    {this.package=package;this.targets=targets;this.packageHold=packageHold;this.targetHold=targetHold;this.journal=journal;this.directory=directory;this.qualificationCheckpoint=qualificationCheckpoint;}
    internal static LinuxNativeModuleOwner Prepare(LinuxNativePackageAdmission package,LinuxNativeTargetAdmission targets)
        =>PrepareCore(package,targets,null);
    // No persisted setting or installed request can select these callbacks.
    internal static LinuxNativeModuleOwner PrepareForQualification(LinuxNativePackageAdmission package,LinuxNativeTargetAdmission targets,Action<string> checkpoint)
        =>PrepareCore(package,targets,checkpoint??throw new ArgumentNullException(nameof(checkpoint)));
    private static LinuxNativeModuleOwner PrepareCore(LinuxNativePackageAdmission package,LinuxNativeTargetAdmission targets,Action<string>? checkpoint)
    {
        if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64||UserId()!=0)
            throw new PlatformNotSupportedException("Owned module operations require qualified root Linux x64");
        package.RequireCurrent();targets.RequireCurrent();var definition=package.Definition;
        if(definition.Manifest.ModuleName!=ModuleName)
            throw new InvalidDataException("Only the exact qualified artifact bound to the kernel module name can be loaded");
        LinuxNativeInstallation.RequireModule(definition.Manifest);
        targets.Prepared.RequireSame(LinuxControlledTargetSet.Prepare(definition.Manifest.Targets.Select(t=>new LinuxControlledTargetSet.Identity(t.Device,t.Inode))));
        if(!definition.Manifest.Targets.Select(t=>t.Path).Order(StringComparer.Ordinal).SequenceEqual(targets.Proofs.Select(t=>t.Path).Order(StringComparer.Ordinal)))
            throw new InvalidDataException("Held target paths differ from the admitted root installation");
        using var parent=LinuxProtectedDirectory.OpenRoot(definition.Configuration.PrivateDirectory);parent.RequirePrivate();parent.RequireQualifiedLocalExt4();
        var packageHold=package.HoldNativeLifetime();LinuxNativeAdmissionHold? targetHold=null;LinuxProtectedDirectory? journal=null;
        try
        {
            targetHold=targets.HoldNativeLifetime();var name="module-"+Guid.NewGuid().ToString("N");var directory=Path.Combine(definition.Configuration.PrivateDirectory,name);
            journal=parent.CreatePrivateChild(name);journal.RequirePrivate();journal.RequireQualifiedLocalExt4();
            var owner=new LinuxNativeModuleOwner(package,targets,packageHold,targetHold,journal,directory,checkpoint);
            if(!live.TryAdd(owner.OwnerId,owner))throw new InvalidOperationException("Duplicate volatile module owner");
            return owner;
        }
        catch(Exception original)
        {
            var failures=new List<Exception>{original};
            foreach(var resource in new IDisposable?[]{journal,targetHold,packageHold})
                try{resource?.Dispose();}catch(Exception cleanup){failures.Add(cleanup);}
            if(failures.Count>1)throw new AggregateException("Module preparation and admission cleanup failed",failures);throw;
        }
    }
    // File.GetAttributes reports access/I/O errors rather than treating them as
    // absence like File.Exists/Directory.Exists. The two paths are fixed OS
    // locations, never request-supplied names.
    private static bool Present(string path)
    {
        try{_=File.GetAttributes(path);return true;}
        catch(FileNotFoundException){return false;}
        catch(DirectoryNotFoundException){return false;}
    }
    private static void RequireModuleOperationsEnabled()
    {if(File.ReadAllText("/proc/sys/kernel/modules_disabled").Trim()!="0")throw new InvalidOperationException("Kernel module operations are disabled or unavailable");}
    private void Record(string step,object evidence,Action? committed=null)
    {
        if(pending!=null)throw new IOException("A module receipt must commit before recording another boundary");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new{Version=1,OwnerId,Sequence=sequence,PreviousSha256=previousHash,RecordedUtc=DateTimeOffset.UtcNow,
            RecordedMonotonic=Stopwatch.GetTimestamp(),MonotonicFrequency=Stopwatch.Frequency,Step=step,Evidence=evidence});
        if(bytes.Length>65536)throw new IOException("Module receipt exceeds bound");
        pending=($"{sequence:D6}-{step}.json",bytes);pendingCommitted=committed;FlushPendingCore();
    }
    private void FlushPendingCore()
    {
        if(pending is not {} receipt)return;
        qualificationCheckpoint?.Invoke("RECEIPT:"+receipt.Name);
        byte[]? existing=null;
        try{existing=journal.Read(receipt.Name,65536).Bytes;}
        catch(Win32Exception error)when(error.NativeErrorCode==2){}
        if(existing!=null)
        {
            if(!existing.AsSpan().SequenceEqual(receipt.Bytes))throw new IOException("Original module receipt changed; retained");
            journal.CommitDirectory();
        }
        else journal.PublishNew(receipt.Name,receipt.Bytes);
        qualificationCheckpoint?.Invoke("PUBLISHED:"+receipt.Name);
        previousHash=Convert.ToHexString(SHA256.HashData(receipt.Bytes));sequence=checked(sequence+1);pending=null;
        var committed=pendingCommitted;pendingCommitted=null;committed?.Invoke();
    }
    internal void RetryReceipt(){lock(gate){ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();}}
    internal void Load()
    {
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();
            if(state is not ("Prepared" or "LoadIntentPending"))throw new InvalidOperationException("Module load is one-use");
            package.RequireCurrent();targets.RequireCurrent();RequireModuleOperationsEnabled();
            if(Present("/sys/module/"+ModuleName)||Present("/dev/"+ModuleName))
            {state="LoadFailedNoOwnership";Record("load-refused",new{Reason="PREEXISTING_MODULE_OR_DEVICE",Owned=false});return;}
            if(state=="Prepared")
            {
                state="LoadIntentPending";Record("load-intent",new{Module=ModuleName,package.Definition.ConfigurationSha256,Targets=targets.Proofs,Flags=0});
            }
            DateTimeOffset utc=default,returnedUtc=default;long tick=0,returnedTick=0,result=0;int error=0;
            // The callback receives the original readable and already hashed
            // descriptor. Flags never ignore vermagic, modversions or signing.
            package.WithOwnedModuleDescriptor(file=>
            {
                utc=DateTimeOffset.UtcNow;tick=Stopwatch.GetTimestamp();state="LoadCalling";result=LoadModule(313,file,"",0);
                if(result==0)state="LoadedOwned";else{error=Marshal.GetLastPInvokeError();state="LoadFailedNoOwnership";}
                returnedTick=Stopwatch.GetTimestamp();returnedUtc=DateTimeOffset.UtcNow;
                return result;
            });
            LoadReturn=new(utc,returnedUtc,tick,returnedTick,Stopwatch.Frequency,result,error);
            Record("load-return",new{State=state,Call=LoadReturn});
            qualificationCheckpoint?.Invoke("LOAD_VERIFY");
            if(state=="LoadedOwned"&&(!Present("/sys/module/"+ModuleName)||!Present("/dev/"+ModuleName)))
                throw new IOException("Successful module load retained; module/device observation is incomplete");
        }
    }
    internal void UnloadBeforeSource()
    {
        lock(gate)
        {
            if(source!=null)throw new InvalidOperationException("Registered source must actually close before module unload");
            UnloadCore("NOT_STARTED");
        }
    }
    private void UnloadCore(string sourceState)
    {
            ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();
            if(state=="UnloadVerifiedAbsent")return;
            if(state is not ("LoadedOwned" or "UnloadIntentPending" or "UnloadReturned"))throw new InvalidOperationException("No known owned module can be unloaded");
            if(state!="UnloadReturned")
            {
                RequireModuleOperationsEnabled();
                if(state=="LoadedOwned"){state="UnloadIntentPending";Record("unload-intent",new{Module=ModuleName,Source=sourceState,Flags=0x800});}
                var utc=DateTimeOffset.UtcNow;var tick=Stopwatch.GetTimestamp();state="UnloadCalling";
                var result=UnloadModule(176,ModuleName,0x800);
                var error=0;if(result==0)state="UnloadReturned";else{error=Marshal.GetLastPInvokeError();state="LoadedOwned";}
                UnloadReturn=new(utc,DateTimeOffset.UtcNow,tick,Stopwatch.GetTimestamp(),Stopwatch.Frequency,result,error);
                Record("unload-return",new{State=state,Call=UnloadReturn});
                if(result!=0)return; // Busy/error keeps both admissions held.
            }
            // A successful delete_module is never repeated after a later
            // query/receipt failure. Only absence verification is retried.
            qualificationCheckpoint?.Invoke("UNLOAD_VERIFY");
            if(Present("/sys/module/"+ModuleName)||Present("/dev/"+ModuleName))throw new IOException("Returned module unload has not yet verified exact absence");
            Record("unload-verified",new{ModuleAbsent=true,DeviceAbsent=true},()=>state="UnloadVerifiedAbsent");
    }
    internal LinuxControlledSourceRuntime StartRegisteredSource(LinuxForensicJournal sourceJournal,ForensicPipeline pipeline,EventSpool spool,
        ForensicPolicy policy,LinuxNativeSourcePolicy signedPolicy,Action<string> report,long rawBankQuotaBytes=LinuxNativeRawStorageCapacity.DefaultBytes)
    {
        ArgumentNullException.ThrowIfNull(signedPolicy);
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();
            if(state!="LoadedOwned"||source!=null)throw new InvalidOperationException("One source per actually loaded module owner");
            package.RequireCurrent();targets.RequireCurrent();var definition=package.Definition;
            sourceJournal.RequireNativeInstallation(definition.Configuration);signedPolicy.RequireInstallation(definition.Configuration,sourceJournal,policy);
            var root=definition.Configuration.PackageDirectory;var manifest=definition.Manifest;
            var loader=manifest.Members.Single(x=>x.Role=="loader");var obj=manifest.Members.Single(x=>x.Role=="object");
            var paths=manifest.Targets.Select(x=>x.Path).ToImmutableArray();
            var launch=new LinuxOwnedLoaderProcess.Launch(Path.Combine(root,loader.Name),Path.Combine(root,obj.Name),paths[0],root){ControlVersion=manifest.ControlVersion,Targets=paths};
            var config=new LinuxControlledSourceRuntime.Qualification(launch,manifest.Kernel,manifest.BtfSha256,loader.Sha256,obj.Sha256,
                Path.Combine(definition.Configuration.PrivateDirectory,"source-"+Guid.NewGuid().ToString("N"))){ExpectedTargets=targets.Prepared.Targets,RawBankQuotaBytes=LinuxNativeRawStorageCapacity.RequireQuota(rawBankQuotaBytes)};
            var created=LinuxControlledSourceRuntime.CreateForRegisteredOwner(config,sourceJournal,pipeline,spool,definition.Configuration.SensorId,policy,report,signedPolicy,
                ()=>{package.RequireCurrent();targets.RequireCurrent();});
            source=created; // Register before the first potentially failing I/O or scheduling call.
            Record("source-registered",new{created.RuntimeId,Directory=config.Directory});
            BeginSource();return created;
        }
    }
    private void BeginSource()
    {
        if(sourceBeginAttempted)return;sourceBeginAttempted=true;
        if(qualificationCheckpoint==null)source!.BeginRegistered();
        else source!.BeginRegisteredForQualification(()=>qualificationCheckpoint("RUNTIME_SUBMISSION"));
    }
    internal async Task<LinuxControlledSourceRuntime.Outcome> StopSourceAndUnloadAsync()
    {
        LinuxControlledSourceRuntime registered;
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();
            registered=source??throw new InvalidOperationException("No registered source exists");
            registered.RequestStop("MODULE_OWNER_SOURCE_STOP");BeginSource();
        }
        // Drain must never hold this gate or accept a caller-supplied task.
        var outcome=await registered.Completion.ConfigureAwait(false);
        lock(gate)
        {
            ObjectDisposedException.ThrowIf(disposed||releasing,this);FlushPendingCore();
            var closure=registered.NativeClosure;
            if(!ReferenceEquals(source,registered)||!registered.Completion.IsCompletedSuccessfully||closure==null||
                !ReferenceEquals(outcome.NativeClosure,closure)||closure.RuntimeId!=registered.RuntimeId||closure.Session!=registered.Session)
                throw new InvalidOperationException("Actual registered source native closure remains unresolved");
            if(!sourceClosureRecorded)Record("source-closed",closure,()=>sourceClosureRecorded=true);
            if(state!="UnloadVerifiedAbsent")UnloadCore("REGISTERED_SOURCE_CLOSED:"+registered.RuntimeId);
            return outcome;
        }
    }
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;FlushPendingCore();
            if(state is not ("Prepared" or "LoadIntentPending" or "LoadFailedNoOwnership" or "UnloadVerifiedAbsent"))
                throw new InvalidOperationException("Known or unresolved native ownership must finish before admission release");
            releasing=true;
            var failures=new List<Exception>();
            if(!targetReleased)try{qualificationCheckpoint?.Invoke("RELEASE_TARGET");targetHold.Dispose();targetReleased=true;}catch(Exception error){failures.Add(error);}
            if(!packageReleased)try{qualificationCheckpoint?.Invoke("RELEASE_PACKAGE");packageHold.Dispose();packageReleased=true;}catch(Exception error){failures.Add(error);}
            if(!journalReleased)try{qualificationCheckpoint?.Invoke("RELEASE_JOURNAL");journal.Dispose();journalReleased=true;}catch(Exception error){failures.Add(error);}
            if(failures.Count!=0)throw new AggregateException("Native admission release remains incomplete",failures);
            disposed=true;live.TryRemove(OwnerId,out _);
        }
    }
}
