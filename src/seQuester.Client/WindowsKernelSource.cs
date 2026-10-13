using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
using RansomFree.Client.Forensics;

namespace RansomFree.Client;

public static class WindowsKernelDecoder
{
    public const int EventBytes=3800;
    public const int ExtendedEventBytes=3984;
    public const int DeferredTokenContextBytes=2048;
    public const int DeferredEventBytes=ExtendedEventBytes+DeferredTokenContextBytes;
    // Explicit decoding only; production ingestion is not enabled until native
    // worker qualification and versioned durable transport are complete.
    public static WindowsDeferredTokenEvidence DecodeDeferredTokenContext(WindowsKernelEvidence operation,byte[] b)
    {
        if(!operation.IsValid()||b.Length!=DeferredTokenContextBytes||U32(b,0)!=1||U32(b,4)!=DeferredTokenContextBytes||U32(b,60)!=1||U32(b,68)!=0||
            U32(b,44)>2||U32(b,48)>2||U32(b,52)>2||I64(b,24)<=0||I64(b,32)<=0||I64(b,504)<0)throw new InvalidDataException("Deferred Windows token schema mismatch");
        var evidence=new WindowsDeferredTokenEvidence{Instance=U64(b,8).ToString("X16"),Sequence=checked((long)U64(b,16)),
            ReferencedUtc=DateTimeOffset.FromFileTime(I64(b,24)),QueryStartedUtc=DateTimeOffset.FromFileTime(I64(b,32)),
            ReferenceIrql=U32(b,40),ThreadImpersonating=Tri(b,44),CopyOnOpen=Tri(b,48),EffectiveOnly=Tri(b,52),
            EntryImpersonationLevel=U32(b,64)==uint.MaxValue?null:U32(b,64),CollectionStatus=Status(b,56),
            ThreadEffective=Token(b,72),ThreadOwnerPrimary=Token(b,216),RequestorPrimary=Token(b,360),
            ThreadProcessCreatedFileTime=I64(b,504)>0?I64(b,504):null,NativeImage=Text(b,512),RawSha256=Convert.ToHexString(SHA256.HashData(b))};
        if(!evidence.IsValid(operation))throw new InvalidDataException("Deferred Windows token evidence does not match its operation or collection status");
        return evidence;
    }
    public static bool ValidRecordLength(int size)=>size is EventBytes or ExtendedEventBytes or DeferredEventBytes;
    public static byte[] ExtendWithDeferred(byte[] original,byte[] context)
    {
        if(original.Length!=ExtendedEventBytes||U32(original,0)!=((U32(original,72)&1024)!=0?6u:5u)||
            context.Length!=DeferredTokenContextBytes||U32(context,0)!=1||U32(context,4)!=DeferredTokenContextBytes||
            U64(context,8)!=U64(original,8)||U64(context,16)!=U64(original,16))throw new InvalidDataException("Deferred context linkage mismatch");
        var result=new byte[DeferredEventBytes];original.CopyTo(result,0);context.CopyTo(result,ExtendedEventBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(result,(U32(original,72)&1024)!=0?8u:7u);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4),DeferredEventBytes);return result;
    }
    public static byte[] ExtendFromReply(byte[] original,byte[] reply)
    {
        if(reply.Length!=ExtendedEventBytes||original.Length!=EventBytes||!reply.AsSpan(0,EventBytes).SequenceEqual(original))throw new InvalidDataException("Context reply changed the peeked operation bytes");
        return Extend(original,reply.AsSpan(EventBytes).ToArray());
    }
    public static byte[] Extend(byte[] original,byte[] extension)
    {
        if(original.Length!=EventBytes||U32(original,0)!=4||U32(original,4)!=EventBytes||extension.Length!=184||U32(extension,0)!=1||U32(extension,4)!=184||
            U64(original,8)!=U64(extension,8)||U64(original,16)!=U64(extension,16))throw new InvalidDataException("Thread owner extension does not match its operation");
        var result=new byte[ExtendedEventBytes];original.CopyTo(result,0);extension.CopyTo(result,EventBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(result,(U32(original,72)&1024)!=0?6u:5u);BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4),ExtendedEventBytes);
        return result;
    }
    public static AgentEvent Decode(byte[] b,string sensor,Func<string,string> resolvePath,bool resolveAccount=true)
    {
        var remote=(b.Length>=EventBytes&&(U32(b,72)&1024)!=0);
        if(!ValidRecordLength(b.Length)||U32(b,0)!=(b.Length==EventBytes?4u:b.Length==DeferredEventBytes?remote?8u:7u:remote?6u:5u)||U32(b,4)!=b.Length)throw new InvalidDataException("Windows kernel protocol mismatch");
        var observed=DateTimeOffset.FromFileTime(I64(b,24));var completed=DateTimeOffset.FromFileTime(I64(b,32));
        var instance=U64(b,8).ToString("X16");var sequence=checked((long)U64(b,16));var nativePid=U64(b,48);var nativeTid=U64(b,56);
        if(nativePid>int.MaxValue||nativeTid>uint.MaxValue)throw new InvalidDataException("Invalid kernel process/thread identity");
        var path=Text(b,240);var image=Text(b,1776);var major=U32(b,76);var kind=U32(b,84);var status=I32(b,88);var flags=U32(b,72);
        var k=new WindowsKernelEvidence{Version=(int)U32(b,0),Instance=instance,Sequence=sequence,ProcessId=nativePid>0?(int)nativePid:null,ThreadId=nativeTid>0?(uint)nativeTid:null,
            ProcessCreatedFileTime=I64(b,40)>0?I64(b,40):null,CompletedUtc=completed,Flags=flags,Major=major,OperationClass=kind,NativePath=path,
            FileIoBoundary=(flags&1024)!=0?"client-network-filesystem":null,RemoteProviderStatus=(flags&1024)!=0?"unavailable: MUP provider not verified":null,
            SubjectSource=U32(b,3312) switch{1=>"create-access-state",2=>"request-thread-snapshot",_=>"unavailable"},ThreadImpersonating=Tri(b,3316),
            CreateAuthorization=Token(b,3320),ThreadEffective=Token(b,3464),RequestorPrimary=Token(b,3608),
            DesiredAccess=U32(b,3752),CreateOptions=U32(b,3756),NameSource=U32(b,3760) switch{1=>"normalized",2=>"opened",_=>"unavailable"},NormalizedNameStatus=Status(b,3764),
            CopyOnOpen=Tri(b,3768),EffectiveOnly=Tri(b,3772),CaptureIrql=U32(b,3776),ThreadProcessId=U32(b,3780)>0?U32(b,3780):null,MonotonicTicks=I64(b,3784),MonotonicFrequency=I64(b,3792)};
        if(b.Length>=ExtendedEventBytes){
            if(U32(b,3800)!=1||U32(b,3804)!=184||U64(b,3808)!=U64(b,8)||U64(b,3816)!=U64(b,16)||U32(b,3980)!=U32(b,92))throw new InvalidDataException("Invalid durable thread context linkage");
            var owner=Token(b,3824);
            k=k with{ThreadOwnerPrimary=owner,ThreadProcessCreatedFileTime=I64(b,3968)>0?I64(b,3968):null,CallbackDataFlags=U32(b,3976),RequestorMode=U32(b,3980),
                ThreadOwnerStatus=k.ThreadId==null?"thread-unavailable":k.CaptureIrql!=0?"irql-not-passive":owner.Captured==31?"captured":owner.Captured>0?"partial":"token-unavailable"};
            var legacy=b.AsSpan(0,EventBytes).ToArray();BinaryPrimitives.WriteUInt32LittleEndian(legacy,4);BinaryPrimitives.WriteUInt32LittleEndian(legacy.AsSpan(4),EventBytes);
            k=k with{BaseRecordSha256=Convert.ToHexString(SHA256.HashData(legacy)),ThreadContextSha256=Convert.ToHexString(SHA256.HashData(b.AsSpan(EventBytes,184)))};
        }
        if(b.Length==DeferredEventBytes){
            var deferred=DecodeDeferredTokenContext(k with{Version=remote?6:5},b.AsSpan(ExtendedEventBytes).ToArray());
            k=k with{DeferredTokenContext=deferred,SubjectSource=deferred.ThreadImpersonating switch{true=>"callback-referenced-thread-token",false=>"later-thread-owner-primary",_=>"unavailable"}};
            if(image.Length==0)image=deferred.NativeImage;
        }
        // Wall clocks may step backwards during an operation. Native sequence and
        // QPC order the evidence; clock correction must not discard an event.
        if(!k.IsValid()||sequence<=0)throw new InvalidDataException("Invalid Windows kernel evidence");
        var operation=major switch{0=>"File open",3=>"Content read (copy possible)",4=>"Content written",6 when kind is 10 or 65=>"File renamed",6 when kind is 13 or 64=>"Delete requested",6=>"File metadata changed",21=>"Permissions changed",255=>"Memory mapping requested",_=>"File operation"};
        var sid=k.Subject.Sid;string? account=sid;
        if(resolveAccount&&sid!=null&&OperatingSystem.IsWindows())try{account=new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;}catch(IdentityNotMappedException){}
        var complete=k.ProcessId.HasValue&&sid!=null&&image.Length>0&&(flags&63)==0&&k.Subject.Captured==31&&k.ThreadEffective.Captured==31&&k.RequestorPrimary.Captured==31&&(k.Version==4||k.ThreadOwnerPrimary?.Captured==31);
        var id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sensor+":"+instance+":"+sequence+":"+observed.ToFileTime()+(k.Version>=5?":thread-context-v1":""))).AsSpan(0,16)).ToLowerInvariant();
        return new(id,observed,operation,resolvePath(path),account,image.Length>0?resolvePath(image):null,k.ProcessId,"Windows minifilter"){
            Attribution=new(){Provider="Windows minifilter",Level=complete?"Full attribution":"Partial attribution",EvidenceId=instance+":"+sequence,
                Basis="Operation-time kernel observations; CREATE authorization, requesting-thread effective token and process-primary token remain distinct. Inspect token query statuses and provider loss telemetry."+(k.DeferredTokenContext!=null?" Impersonation metadata is queried later from the callback-referenced token; primary and image metadata are later observations, not entry-time snapshots.":"")+((flags&1024)!=0?" Completion is at the client MUP boundary; remote provider identity and server-side file operation are not verified.":""),
                UserSid=sid,UserName=account,LogonId=k.Subject.AuthenticationId,ProcessName=image.Length>0?Path.GetFileName(image):null,ProcessStartTicks=k.ProcessCreatedFileTime?.ToString(System.Globalization.CultureInfo.InvariantCulture),
                Outcome=(flags&128)!=0?"Unknown":status>=0?"Success":"Failed",OsStatus="0x"+unchecked((uint)status).ToString("X8"),AccessMask=major==0?"0x"+k.DesiredAccess.ToString("X8"):null,
                BytesTransferred=major is 3 or 4&&status>=0&&(flags&128)==0?checked((long)U64(b,64)):null,EventTimeCredentials=sid!=null&&k.DeferredTokenContext==null,CompleteRecordSet=complete,WindowsKernel=k}
        };
    }
    public static WindowsTokenSnapshot Token(byte[] b,int o)
    {
        var mask=U32(b,o);uint? Number(uint bit,int offset)=>(mask&bit)!=0?U32(b,o+offset):null;
        var length=U32(b,o+24);string? sid=null;
        if((mask&1)!=0){if(length is <8 or >68||b[o+72]!=1||length!=8+4*b[o+73])throw new InvalidDataException("Invalid kernel SID");
            ulong authority=0;for(var i=2;i<8;i++)authority=(authority<<8)|b[o+72+i];sid="S-1-"+authority;for(var i=0;i<b[o+73];i++)sid+="-"+U32(b,o+80+4*i);}
        return new(){Captured=mask,Sid=sid,TokenId=(mask&2)!=0?U64(b,o+48).ToString("X16"):null,AuthenticationId=(mask&2)!=0?U64(b,o+56).ToString("X16"):null,ModifiedId=(mask&2)!=0?U64(b,o+64).ToString("X16"):null,
            Type=Number(2,40),ImpersonationLevel=Number(2,40)==2?Number(2,44):null,SessionId=Number(4,28),IntegrityRid=Number(8,32),Elevated=Number(16,36) is {} elevated?elevated!=0:null,
            QueryStatus=[Status(b,o+4),Status(b,o+8),Status(b,o+12),Status(b,o+16),Status(b,o+20)]};
    }
    internal static uint U32(byte[] b,int o)=>BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));
    internal static ulong U64(byte[] b,int o)=>BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));
    internal static long I64(byte[] b,int o)=>BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(o));
    private static int I32(byte[] b,int o)=>BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(o));
    private static string Status(byte[] b,int o)=>"0x"+U32(b,o).ToString("X8");
    private static bool? Tri(byte[] b,int o)=>U32(b,o) switch{1=>false,2=>true,_=>null};
    private static string Text(byte[] b,int o){var text=Encoding.Unicode.GetString(b,o,1536);var end=text.IndexOf('\0');if(end<0)throw new InvalidDataException("Unterminated kernel string");return text[..end];}
}

// Opt-in native source. ACK follows durable journal persistence; dispatch failures
// retain journal files. Existing audit/watcher sources remain active independently.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class WindowsKernelSource:IAsyncDisposable
{
    private readonly string sensor,directory;
    private readonly Func<string[]> paths;
    private readonly Action<AgentEvent> publish;
    private readonly Action<AgentEvent,ActorLease?>? publishCaptured;
    private readonly Action<string> health;
    private readonly CancellationTokenSource stop=new();
    private readonly Task worker;
    private readonly Task dispatcher;
    private readonly AsyncDisposeOnce disposal;
    private readonly ConcurrentQueue<string> deliveries=new();
    private readonly WindowsKernelOperationJournal journal;
    private readonly WindowsKernelAcquisitionJournal acquisition;
    private readonly SemaphoreSlim available=new(0);
    private readonly WindowsKernelActorInbox actors=new(64);
    private readonly WindowsKernelImageRetention images=new();
    private readonly WindowsStagedActorStore? stagedActors;
    private sealed record SyscallAcquisitionProvider(string Provider,ulong Instance);
    private SyscallAcquisitionProvider? syscallAcquisitionProvider;
    internal ActorLease CaptureSyscallActor(AgentEvent observed,out AgentEvent value)
    {
        value=observed;var active=Volatile.Read(ref syscallAcquisitionProvider);
        if(stagedActors==null||active==null){var missing=ActorLease.Unavailable(observed,"syscall-proactive-acquisition-provider-unavailable");missing.ApplyKernel(observed,sensor);return missing;}
        return stagedActors.CaptureSyscall(observed,active.Provider,active.Instance,DisplayPath,out value,health);
    }
    private readonly bool captureProactiveExecutables;
    private readonly bool captureRemoteFilesystem;
    private readonly bool captureDeferredTokenContext;
    private readonly long ownCreated=System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime().ToFileTimeUtc();
    private readonly Dictionary<string,string> drives=new(StringComparer.OrdinalIgnoreCase);
    // In-assembly qualification seam. Production has no subscriber. The owned
    // port stays valid only for the duration of this synchronous callback.
    internal Action<Func<byte[],int,byte[]>>? DiagnosticAfterIntake {get;set;}
    public WindowsKernelSource(string sensor,string directory,Func<string[]> paths,Action<AgentEvent> publish,Action<string> health,Action<AgentEvent,ActorLease?>? publishCaptured=null,bool captureStagedExecutables=false,bool captureProactiveExecutables=false,bool captureRemoteFilesystem=false,bool captureDeferredTokenContext=false)
    {
        this.sensor=sensor;this.paths=paths;this.publish=publish;this.publishCaptured=publishCaptured;this.health=health;this.directory=Path.Combine(directory,"kernel-inbox");
        Directory.CreateDirectory(this.directory);
        journal=new(this.directory);
        acquisition=new(this.directory);
        if(captureProactiveExecutables&&!captureStagedExecutables)throw new ArgumentException("Proactive acquisition requires staged executable capture");
        this.captureProactiveExecutables=captureProactiveExecutables;
        this.captureRemoteFilesystem=captureRemoteFilesystem;
        this.captureDeferredTokenContext=captureDeferredTokenContext;
        if(captureStagedExecutables){if(publishCaptured==null)throw new ArgumentException("Staged actor capture requires forensic publication");stagedActors=new(directory,sensor);}
        foreach(var drive in DriveInfo.GetDrives()){var name=drive.Name[..2];var target=new StringBuilder(32768);if(QueryDosDevice(name,target,target.Capacity)>0)drives[name]=target.ToString();}
        // Recovery records were durably written before the previous process stopped.
        foreach(var file in Directory.EnumerateFiles(this.directory,"*.record").OrderBy(x=>x,StringComparer.Ordinal))
        {
            try{Schedule(file);}
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {health("Windows kernel acquisition recovery held record "+Path.GetFileName(file)+": "+ex.GetType().Name);}
        }
        dispatcher=Task.Run(Dispatch);worker=StartReceiver(Run);
        disposal=new(DisposeCoreAsync);
    }
    private string NativePath(string path)
    {
        var full=Path.GetFullPath(path);
        if(full.StartsWith("\\\\",StringComparison.Ordinal)){
            if(!captureRemoteFilesystem||full.StartsWith("\\\\?\\",StringComparison.Ordinal)||full.StartsWith("\\\\.\\",StringComparison.Ordinal))throw new IOException("Remote kernel scope requires explicit qualification mode and a plain UNC path");
            var parts=full[2..].Split('\\');if(parts.Length<3||parts.Any(p=>p.Length==0||p is "." or ".."||p.Contains(':')||p.Contains(';')||p.Any(char.IsControl)))throw new IOException("Unsupported remote scope path");
            return "\\Device\\Mup\\"+full[2..];
        }
        return full.Length>=3&&drives.TryGetValue(full[..2],out var device)?device+full[2..]:throw new IOException("Kernel scope requires a resolved local drive path");
    }
    private string DisplayPath(string path)
        =>WindowsNativePaths.Display(path,drives,captureRemoteFilesystem);
    internal WindowsSyscallObservation DisplaySyscallTarget(WindowsSyscallObservation value)=>value.NativeTargetPath is {} native?value with{TargetPath=DisplayPath(native)}:value;
    private static byte[] Message(uint command){var b=new byte[8];BinaryPrimitives.WriteUInt32LittleEndian(b,4);BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4),command);return b;}
    private byte[] Scope(string[] watched)
    {
        if(watched.Length>128)throw new IOException("Kernel exact-path scope exceeds 128 files");
        var b=new byte[12+watched.Length*1536];Message(5).CopyTo(b,0);BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8),(uint)watched.Length);
        for(var i=0;i<watched.Length;i++){var native=NativePath(watched[i]);if(native.Length>=767)throw new IOException("Kernel scope path too long");Encoding.Unicode.GetBytes(native).CopyTo(b,12+i*1536);}return b;
    }
    private static void Send(SafeFileHandle port,byte[] request,byte[]? output,out uint returned)=>Marshal.ThrowExceptionForHR(FilterSendMessage(port,request,(uint)request.Length,output,(uint)(output?.Length??0),out returned));
    public static AgentEvent? RestorePrepared(string directory,string eventId)
    {
        if(!Guid.TryParseExact(eventId,"N",out _))throw new InvalidDataException("Invalid kernel event ID");
        var file=Path.Combine(directory,"kernel-inbox",eventId+".prepared");
        if(!File.Exists(file))return null;
        var e=JsonSerializer.Deserialize<AgentEvent>(File.ReadAllBytes(file))??throw new InvalidDataException("Empty prepared kernel event");
        if(e.EventId!=eventId||e.Source!="Windows minifilter"||e.Forensics==null)throw new InvalidDataException("Invalid prepared kernel event");return e;
    }
    internal static AgentEvent ForDelivery(string directory,AgentEvent observed)=>RestorePrepared(directory,observed.EventId)??observed;
    internal static bool IsOwnProcess(AgentEvent e,int pid,long created)=>e.ProcessId==pid&&e.Attribution?.WindowsKernel?.ProcessCreatedFileTime==created;
    public static void SavePrepared(string directory,AgentEvent e)
    {
        if(e.Source!="Windows minifilter"||e.Forensics==null||!Guid.TryParseExact(e.EventId,"N",out _))throw new InvalidDataException("Invalid prepared kernel event");
        var folder=Path.Combine(directory,"kernel-inbox");Directory.CreateDirectory(folder);var file=Path.Combine(folder,e.EventId+".prepared");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(e);
        if(File.Exists(file)){if(!File.ReadAllBytes(file).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Prepared kernel event changed");return;}
        var temp=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        using(var stream=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){stream.Write(bytes);stream.Flush(true);}File.Move(temp,file);
    }
    private void Schedule(string file)
    {
        if(journal.Schedule(file)){deliveries.Enqueue(file);available.Release();}
    }
    internal static void CleanupPrepared(string directory,string id,Action<string> health)
    {
        // Called only after successful publication and durable-record removal.
        // A leftover retry cache cannot block subsequent observations.
        try{foreach(var suffix in new[]{".prepared",".acq-required",".acq1",".acq-unavailable"})File.Delete(Path.Combine(directory,id+suffix));}
        catch(Exception ex)when(ex is IOException or UnauthorizedAccessException){health("Windows kernel delivered-event cache cleanup failed: "+ex.GetType().Name);}
    }
    private async Task Dispatch()
    {
        while(!stop.IsCancellationRequested)
        {
            try{await available.WaitAsync(stop.Token);}catch(OperationCanceledException){break;}
            if(!deliveries.TryDequeue(out var file))continue;
            string? error=null;
            ActorLease? retained=null;
            while(!stop.IsCancellationRequested)
            {
                ActorLease? actor=retained;retained=null;
                try
                {
                    var timing=Stopwatch.StartNew();
                    var bytes=File.ReadAllBytes(file);var observed=WindowsKernelDecoder.Decode(bytes,sensor,DisplayPath,false);
                    if(!journal.RecordPath(observed.EventId).Equals(file,StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("Recovered kernel record identity does not match its filename");
                    // Take the retained executable before optional account resolution or publication.
                    actor??=actors.Take(observed.EventId)??stagedActors?.RestoreForDelivery(observed,health);
                    TraceSlow(timing,"snapshot-recovery",observed.EventId);timing.Restart();
                    var e=ForDelivery(Path.GetDirectoryName(directory)!,acquisition.Attach(WindowsKernelDecoder.Decode(bytes,sensor,DisplayPath),bytes));
                    TraceSlow(timing,"account-and-prepared-event",observed.EventId);timing.Restart();
                    if(!IsOwnProcess(e,Environment.ProcessId,ownCreated))
                    {
                        if(publishCaptured!=null&&e.Forensics==null){publishCaptured(e,actor);actor=null;}
                        else publish(e);
                    }
                    TraceSlow(timing,"publication",observed.EventId);
                    journal.Complete(file); // only the successfully delivered durable record
                    // Failure to remove this retry cache must not re-publish a
                    // delivered event or stall the queue on its deleted record.
                    CleanupPrepared(directory,e.EventId,health);
                    break;
                }
                catch(ForensicQueueCapacityException ex)
                {
                    // Admission has emitted nothing and consumed no lease. Keep the
                    // exact captured descriptor rather than reopening the actor PID/path.
                    retained=actor;actor=null;
                    if(error!=ex.Message){health(ex.Message);error=ex.Message;}
                    try{await Task.Delay(3000,stop.Token);}catch(OperationCanceledException){break;}
                }
                catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or Win32Exception or ArgumentException or InvalidOperationException or OverflowException or JsonException)
                {
                    var message="Windows kernel dispatch delayed; journal retained: "+ex.GetType().Name+" "+ex.Message;
                    if(message!=error){health(message);error=message;}
                    try{await Task.Delay(3000,stop.Token);}catch(OperationCanceledException){break;}
                }
                finally{actor?.Dispose();}
            }
            retained?.Dispose();
        }
    }
    // This loop must stay synchronous on its dedicated thread. Awaiting a delay
    // would move subsequent receives back onto the shared pool, where signature
    // verification/publication can postpone the first executable acquisition.
    // This reduces scheduling delay; it does not guarantee capture before exit.
    internal static Task StartReceiver(Action run)=>Task.Factory.StartNew(run,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    internal static void Intake(WindowsKernelOperationJournal journal,AgentEvent e,byte[] raw,Action collect,Action acknowledge,Action<string> schedule,Action<string> health,Action? requiredEvidence=null)
    {
        var ownsIntake=journal.Prepare(e.EventId,raw);
        // A required companion failure is not optional actor enrichment. Preserve
        // raw bytes and withhold ACK/scheduling until its validated durable commit.
        requiredEvidence?.Invoke();
        if(ownsIntake)
        {
            try{collect();}
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or Win32Exception or ArgumentException or InvalidOperationException or OverflowException or JsonException)
            {
                health("Actor intake incomplete; durable raw operation/token evidence retained: "+e.EventId+" "+ex.GetType().Name+" "+ex.Message);
            }
        }
        // A failed/lost native ACK response must not strand the committed record
        // until service restart. Retrying may redeliver the same stable event ID.
        try{acknowledge();}
        finally{if(ownsIntake)schedule(journal.RecordPath(e.EventId));}
    }
    private void TraceSlow(Stopwatch timing,string stage,string? eventId=null)
    {if(timing.ElapsedMilliseconds>=1000)health("Windows kernel slow stage="+stage+", elapsedMs="+timing.ElapsedMilliseconds+", event="+(eventId??"none"));}
    private void Run()
    {
        string? lastError=null;
        while(!stop.IsCancellationRequested)
        {
            var startupStage="kernel-port-connect";
            // Provider reconnect failures must not retain expired images indefinitely.
            images.Expire();
            try
            {
                Marshal.ThrowExceptionForHR(FilterConnectCommunicationPort("\\SeQuesterActorPrototype",0,IntPtr.Zero,0,IntPtr.Zero,out var port));
                using(port)
                {
                    byte[] Exchange(byte[] input,int length){var output=length==0?null:new byte[length];Send(port,input,output,out var n);if(n!=length)throw new InvalidDataException("Actor staging response length mismatch");return output??[];}
                    string? stagedProvider=null;
                    bool acquisitionSupported=false;ulong acquisitionEpoch=0;
                    if(stagedActors!=null)
                    {
                        startupStage="actor-binding-health(command=20)";
                        var bindingHealth=Exchange(Message(20),88);
                        if(WindowsKernelDecoder.U32(bindingHealth,0)!=1||WindowsKernelDecoder.U32(bindingHealth,4)!=88)throw new InvalidDataException("Actor binding protocol unavailable");
                        var stopped=WindowsKernelDecoder.U32(bindingHealth,68)!=0;
                        startupStage="actor-staging-health(command=12)";var stagingHealth=Exchange(Message(12),224);
                        if(stopped)health("Actor staging epoch stopped; draining recorded operations, new executable acquisition unavailable until qualified reload");
                        else if(WindowsKernelDecoder.U32(stagingHealth,8)==0){startupStage="actor-staging-enable(command=6)";Exchange(Message(6),0);}
                        stagedProvider=Convert.ToHexString(bindingHealth.AsSpan(8,16));
                        startupStage="actor-provider-epoch(command=3)";acquisitionEpoch=WindowsKernelDecoder.U64(Exchange(Message(3),48),8);
                        startupStage="actor-acquisition-capabilities(command=35)";
                        var capabilities=new byte[48];var capabilityResult=FilterSendMessage(port,WindowsAcquisitionOutcomeProtocol.CapabilitiesRequest(),8,capabilities,48,out var capabilityBytes);
                        if(capabilityResult==unchecked((int)0x80070057))health("Windows acquisition companion unavailable: legacy native provider");
                        else{Marshal.ThrowExceptionForHR(capabilityResult);if(capabilityBytes!=48)throw new InvalidDataException("Acquisition capability size differs");acquisitionSupported=WindowsAcquisitionOutcomeProtocol.Capabilities(capabilities,stagedProvider,acquisitionEpoch);}
                        acquisition.RecoverRetired(stagedProvider,acquisitionEpoch,Schedule,health);
                    }
                    string configured="";bool? threadContextSupported=null,deferredContextSupported=null;long dropped=-1,names=-1;DateTime nextHealth=DateTime.MinValue,nextScope=DateTime.MinValue;
                    var checkpoint=new WindowsKernelCheckpoint(Path.Combine(directory,"provider-checkpoint.json"));
                    startupStage="kernel-operation-intake";
                    // Connection alone does not mean watched-file capture is ready.
                    // Install the initial scope before announcing readiness, so a
                    // short-lived actor cannot run before the scope reaches the driver.
                    startupStage="kernel-initial-scope";
                    var initialWatched=paths().Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();
                    Send(port,Scope(initialWatched),null,out _);
                    configured=string.Join('\n',initialWatched);nextScope=DateTime.UtcNow.AddSeconds(2);
                    // The driver accepts one connection. Both workers share this
                    // owned handle; join diagnostic calls before disposing it.
                    // Supplementary GET/flush work cannot precede raw queue intake.
                    using var diagnostics=stagedProvider==null?null:new WindowsKernelDiagnosticWorker(
                        ()=>DrainStaging(port,stagedProvider),health,stop.Token);
                    var proactiveInstance=captureProactiveExecutables?WindowsKernelDecoder.U64(Exchange(Message(3),48),8):0;
                    Volatile.Write(ref syscallAcquisitionProvider,stagedProvider!=null&&proactiveInstance!=0?new(stagedProvider,proactiveInstance):null);
                    using var proactive=stagedProvider==null||!captureProactiveExecutables?null:new WindowsKernelDiagnosticWorker(
                        ()=>stagedActors!.DrainReady(stagedProvider,proactiveInstance,Exchange,health),health,stop.Token,"Proactive actor ready-feed unavailable");
                    using var acknowledgements=stagedProvider==null||!captureProactiveExecutables?null:new WindowsKernelDiagnosticWorker(
                        ()=>stagedActors!.RetryProcessAcknowledgements(stagedProvider,proactiveInstance,Exchange,health),health,stop.Token,"Proactive actor acknowledgement retry unavailable");
                    health("Windows kernel source connected; existing audit monitoring remains active");lastError=null;
                    while(!stop.IsCancellationRequested)
                    {
                        if(DateTime.UtcNow>=nextScope){var watched=paths().Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();var identity=string.Join('\n',watched);if(identity!=configured||nextScope==DateTime.MinValue){Send(port,Scope(watched),null,out _);configured=identity;}nextScope=DateTime.UtcNow.AddSeconds(2);}
                        var b=new byte[WindowsKernelDecoder.EventBytes];var result=FilterSendMessage(port,Message(2),8,b,(uint)b.Length,out var returned);
                        if(result>=0)
                        {
                            if(returned!=b.Length)throw new InvalidDataException("Kernel event length mismatch");
                            if(threadContextSupported!=false){
                                var query=new byte[24];Message(40).CopyTo(query,0);b.AsSpan(8,16).CopyTo(query.AsSpan(8));var extension=new byte[WindowsKernelDecoder.ExtendedEventBytes];
                                int contextResult;uint contextBytes;
                                contextResult=FilterSendMessage(port,query,24,extension,(uint)extension.Length,out contextBytes);
                                if(contextResult==unchecked((int)0x80070057)){
                                    threadContextSupported=false;health("Legacy Windows driver lacks separate thread-owner context; version 4 evidence retained explicitly");
                                }else{
                                    Marshal.ThrowExceptionForHR(contextResult);
                                    if(contextBytes!=extension.Length)throw new InvalidDataException("Thread context extension length mismatch");
                                    b=WindowsKernelDecoder.ExtendFromReply(b,extension);threadContextSupported=true;
                                }
                            }
                            if(captureDeferredTokenContext&&deferredContextSupported!=false&&b.Length==WindowsKernelDecoder.ExtendedEventBytes&&WindowsKernelDecoder.U32(b,3776)==1){
                                var query=new byte[24];Message(45).CopyTo(query,0);b.AsSpan(8,16).CopyTo(query.AsSpan(8));var context=new byte[WindowsKernelDecoder.DeferredTokenContextBytes];
                                var contextResult=FilterSendMessage(port,query,24,context,(uint)context.Length,out var contextBytes);
                                if(contextResult==unchecked((int)0x80070057)){
                                    deferredContextSupported=false;health("Windows driver lacks deferred APC token context; explicit partial operation evidence retained");
                                }else{
                                    Marshal.ThrowExceptionForHR(contextResult);
                                    if(contextBytes!=context.Length)throw new InvalidDataException("Deferred context length mismatch");
                                    b=WindowsKernelDecoder.ExtendWithDeferred(b,context);deferredContextSupported=true;
                                }
                            }
                            var e=WindowsKernelDecoder.Decode(b,sensor,DisplayPath,false);var target=journal.RecordPath(e.EventId);
                            acquisition.Require(e.EventId,b,stagedProvider,acquisitionEpoch,acquisitionSupported);
                            Intake(journal,e,b,()=>
                            {
                                // Raw user/process/thread evidence is already flushed.
                                // An actor quota or collection failure cannot prevent its delivery.
                                if(publishCaptured!=null&&!IsOwnProcess(e,Environment.ProcessId,ownCreated))
                                {
                                    if(stagedActors!=null&&stagedProvider!=null)
                                    {
                                        var timing=Stopwatch.StartNew();
                                        using var captured=stagedActors.Capture(e,stagedProvider,Exchange,health);
                                        TraceSlow(timing,"snapshot-intake",e.EventId);
                                    }
                                    else if(!actors.TryCapture(e.EventId,()=>images.Capture(e,sensor,health)))
                                        health("Windows kernel early actor capacity exhausted; event retained, later capture may be unavailable");
                                }
                                if(stagedActors!=null&&stagedProvider!=null&&!IsOwnProcess(e,Environment.ProcessId,ownCreated))stagedActors.AcknowledgeAfterJournal(e,target,Exchange,health);
                            },()=>
                            {
                                var ack=new byte[24];Message(4).CopyTo(ack,0);b.AsSpan(8,16).CopyTo(ack.AsSpan(8));Send(port,ack,null,out _);
                            },Schedule,health,()=>acquisition.Capture(e.EventId,b,Exchange));
                            DiagnosticAfterIntake?.Invoke(Exchange);
                        }
                        else if(result is not (unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A)))Marshal.ThrowExceptionForHR(result);
                        else if(stop.Token.WaitHandle.WaitOne(20))break;
                        if(DateTime.UtcNow>=nextHealth)
                        {
                            images.Expire();
                            var h=new byte[48];Send(port,Message(3),h,out returned);if(returned!=48||WindowsKernelDecoder.U32(h,0)!=4)throw new InvalidDataException("Kernel health protocol mismatch");
                            var boundary=checkpoint.Observe(WindowsKernelDecoder.U64(h,8).ToString("X16"),WindowsKernelDecoder.I64(h,16));
                            if(boundary!=null)health(boundary);
                            var newDropped=WindowsKernelDecoder.I64(h,24);var newNames=WindowsKernelDecoder.I64(h,32);
                            if(newDropped>dropped&&newDropped>0)health("Windows kernel evidence loss: dropped="+newDropped);
                            if(newNames>names&&newNames>0)health("Windows kernel global name lookup failures="+newNames+"; affected paths are unknown, not a count of missed watched-file events");
                            if(stagedProvider!=null)
                            {
                                var sh=Exchange(Message(12),224);var bh=Exchange(Message(20),88);
                                var admission=Exchange(Message(24),48);
                                if(WindowsKernelDecoder.U32(admission,0)!=1||WindowsKernelDecoder.U32(admission,4)!=48)throw new InvalidDataException("Actor admission health protocol unavailable");
                                if(WindowsKernelDecoder.U64(sh,192)>0||WindowsKernelDecoder.U64(sh,96)>0||WindowsKernelDecoder.U64(bh,56)>0)
                                    health("Actor staging capacity/loss telemetry: journal="+WindowsKernelDecoder.U64(sh,192)+", candidates="+WindowsKernelDecoder.U64(sh,96)+", registry="+WindowsKernelDecoder.U64(bh,56));
                                File.WriteAllBytes(Path.Combine(directory,stagedProvider+".staging-health"),sh);
                                File.WriteAllBytes(Path.Combine(directory,stagedProvider+".admission-health"),admission);
                                if(acquisitionSupported)
                                {
                                    var negative=Exchange(Message(37),88);
                                    var negativeHealth=WindowsAcquisitionOutcomeProtocol.NegativeHealth(negative,stagedProvider,acquisitionEpoch);
                                    if(negativeHealth.GapCount>0)health("Actor acquisition negative association gaps="+negativeHealth.GapCount+"; affected process identity is unavailable");
                                    File.WriteAllBytes(Path.Combine(directory,stagedProvider+".negative-acquisition-health"),negative);
                                }
                            }
                            dropped=newDropped;names=newNames;nextHealth=DateTime.UtcNow.AddSeconds(15);
                        }
                    }
                }
            }
            catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or Win32Exception or ArgumentException or InvalidOperationException or OverflowException or JsonException)
            {
                var message="Windows kernel source unavailable; journal retained: stage="+startupStage+"; hresult=0x"+ex.HResult.ToString("X8")+"; "+ex.GetType().Name+" "+ex.Message;
                if(message!=lastError){health(message);lastError=message;}
                if(stop.Token.WaitHandle.WaitOne(3000))break;
            }
            finally{Volatile.Write(ref syscallAcquisitionProvider,null);}
        }
    }
    private bool DrainStaging(SafeFileHandle port,string provider)
    {
        var more=false;
        // These diagnostic journals are supplementary; operation ACK is governed by the durable inbox.
        // Native sequence/loss counters expose any gap, including a crash between GET and journal flush.
        foreach(var (command,length,suffix) in new[]{(7u,88,"association"),(15u,112,"lifecycle")})
        {
            var path=Path.Combine(directory,provider+"."+suffix+".journal");
            if(File.Exists(path)&&new FileInfo(path).Length>=64L*1024*1024)throw new IOException("Actor diagnostic journal quota reached");
            // An empty GET must not open and synchronously flush a disk file on
            // every receive iteration. Flush every nonempty batch before return.
            using var pending=new MemoryStream();
            var budget=Stopwatch.StartNew();
            var batchFull=false;
            for(var i=0;i<64&&(i==0||budget.ElapsedMilliseconds<10);i++)
            {
                var b=new byte[length];var request=Message(command);var hr=FilterSendMessage(port,request,8,b,(uint)length,out var n);
                if(hr is unchecked((int)0x80070103) or unchecked((int)0x801F001A) or unchecked((int)0x8000001A)){batchFull=false;break;}
                Marshal.ThrowExceptionForHR(hr);if(n!=length||WindowsKernelDecoder.U32(b,0)!=1||WindowsKernelDecoder.U32(b,4)!=length)throw new InvalidDataException("Invalid actor lifecycle record");pending.Write(b);batchFull=true;
            }
            if(pending.Length>0){using var journal=new FileStream(path,FileMode.Append,FileAccess.Write,FileShare.Read);pending.Position=0;pending.CopyTo(journal);journal.Flush(true);}
            more|=batchFull;
        }
        return more;
    }
    public ValueTask DisposeAsync()=>new(disposal.DisposeAsync());
    private async Task DisposeCoreAsync(){stop.Cancel();try{await Task.WhenAll(worker,dispatcher);}finally{actors.Dispose();images.Dispose();available.Dispose();stop.Dispose();}}
    [DllImport("fltlib.dll",CharSet=CharSet.Unicode)]private static extern int FilterConnectCommunicationPort(string name,uint options,IntPtr context,ushort size,IntPtr security,out SafeFileHandle port);
    [DllImport("fltlib.dll")]private static extern int FilterSendMessage(SafeFileHandle port,byte[] input,uint size,[Out]byte[]? output,uint outputSize,out uint returned);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint QueryDosDevice(string name,StringBuilder target,int length);
}

// A single bounded supplementary worker per connection. File/transport failures
// are explicit gaps, never a reason to stop the independent operation receiver.
// Synchronous OS calls may take longer than a batch budget; do not force-close
// their port. Dispose joins the worker before the enclosing port can be closed.
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal sealed class WindowsKernelDiagnosticWorker:IDisposable
{
    private readonly CancellationTokenSource stop;
    private readonly Task worker;
    internal WindowsKernelDiagnosticWorker(Action drain,Action<string> health,CancellationToken parent,string errorPrefix="Windows kernel diagnostic journal gap")
        :this(()=>{drain();return false;},health,parent,errorPrefix){}
    internal WindowsKernelDiagnosticWorker(Func<bool> drain,Action<string> health,CancellationToken parent,string errorPrefix="Windows kernel diagnostic journal gap")
    {
        stop=CancellationTokenSource.CreateLinkedTokenSource(parent);
        worker=WindowsKernelSource.StartReceiver(()=>
        {
            string? previous=null;
            while(!stop.IsCancellationRequested)
            {
                var more=false;
                try{more=drain();previous=null;}
                catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or COMException or Win32Exception or ArgumentException or InvalidOperationException or OverflowException or JsonException)
                {
                    var message=errorPrefix+": "+ex.GetType().Name+" "+ex.Message;
                    if(message!=previous){health(message);previous=message;}
                }
                // A full bounded batch means a burst may still be queued. Yield
                // briefly instead of adding 100 ms of avoidable backlog growth.
                if(stop.Token.WaitHandle.WaitOne(more?1:100))break;
            }
        });
    }
    public void Dispose(){stop.Cancel();try{worker.GetAwaiter().GetResult();}finally{stop.Dispose();}}
}

// Bounded ownership of early handles. Each lease is transferred exactly once;
// shutdown disposes undelivered leases while their durable records remain.
internal sealed class WindowsKernelActorInbox(int capacity):IDisposable
{
    private readonly Dictionary<string,ActorLease> values=new(StringComparer.Ordinal);
    private readonly object gate=new();
    internal bool TryCapture(string id,Func<ActorLease> capture)
    {lock(gate){if(values.ContainsKey(id))return true;if(values.Count>=capacity)return false;values.Add(id,capture());return true;}}
    internal ActorLease? Take(string id){lock(gate)return values.Remove(id,out var value)?value:null;}
    public void Dispose(){lock(gate){foreach(var value in values.Values)value.Dispose();values.Clear();}}
}

internal sealed class WindowsKernelCheckpoint(string path)
{
    private sealed record State(string Instance,long Sequence,DateTimeOffset CheckedUtc);
    internal string? Observe(string instance,long sequence)
    {
        if(instance.Length!=16||!instance.All(Uri.IsHexDigit)||sequence<0)throw new InvalidDataException("Invalid kernel provider checkpoint");
        State? before=File.Exists(path)?JsonSerializer.Deserialize<State>(File.ReadAllBytes(path)):null;
        var changed=before!=null&&(before.Instance!=instance||sequence<before.Sequence);
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new State(instance,sequence,DateTimeOffset.UtcNow));var temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        using(var stream=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){stream.Write(bytes);stream.Flush(true);}
        File.Move(temp,path,true);
        return changed?"Windows kernel provider restarted or ordering reset; an unquantified coverage gap may precede instance "+instance:null;
    }
}
