using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;
using RansomFree.Client.Forensics;

namespace RansomFree.Client;

public sealed record WindowsSyscallProgress(string Stage,long? NativeSequence,string? EventId,DateTimeOffset StartedUtc,long ElapsedMilliseconds);
public sealed record WindowsSyscallDiagnostics(int Version,bool StopRequested,WindowsSyscallProgress Receiver,WindowsSyscallProgress Dispatcher);

// Experimental intake only: driver registration remains explicitly limited to
// its owned thread and registered handles. This does not arm arbitrary processes.
public sealed class WindowsSyscallSource:IAsyncDisposable
{
    private readonly CancellationTokenSource stop=new();
    private readonly Task receiver,dispatcher;
    private readonly WindowsSyscallJournal journal;
    private readonly AsyncDisposeOnce disposal;
    private readonly string sensor;
    private readonly WindowsKernelSource? kernel;
    private readonly ForensicPipeline forensics;
    private readonly Func<ForensicPolicy> policy;
    private readonly Action<AgentEvent> publish;
    private readonly Action<string> health;
    private PreparedForensicPublication? uncommitted;
    private sealed record Progress(string Stage,long? Sequence,string? EventId,DateTimeOffset Utc,long Tick);
    private Progress receiveProgress=new("not-started",null,null,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp());
    private Progress dispatchProgress=new("not-started",null,null,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp());
    private static void Mark(ref Progress progress,string stage,long? sequence=null,string? eventId=null)=>Volatile.Write(ref progress,new(stage,sequence,eventId,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp()));
    private static WindowsSyscallProgress ReadProgress(Progress progress)=>new(progress.Stage,progress.Sequence,progress.EventId,progress.Utc,(long)Stopwatch.GetElapsedTime(progress.Tick).TotalMilliseconds);
    public WindowsSyscallDiagnostics CaptureDiagnostics()=>new(1,stop.IsCancellationRequested,ReadProgress(Volatile.Read(ref receiveProgress)),ReadProgress(Volatile.Read(ref dispatchProgress)));
    public WindowsSyscallSource(string sensor,string directory,WindowsKernelSource? kernel,ForensicPipeline forensics,Func<ForensicPolicy> policy,Action<AgentEvent> publish,Action<string> health)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        this.sensor=sensor;this.kernel=kernel;this.forensics=forensics;this.policy=policy;this.publish=publish;this.health=health;
        journal=new(directory,sensor);receiver=StartReceiver(Receive);dispatcher=Task.Run(Dispatch);
        disposal=DrainLifetime(stop,receiver,dispatcher,journal);
    }
    internal static Task StartReceiver(Action receive)=>Task.Factory.StartNew(receive,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    private static uint Code(int function,int access)=>0x00220000u|((uint)access<<14)|((uint)function<<2);
    private static byte[] Io(SafeFileHandle device,int function,int access,byte[]? input,int length)
    {
        var output=new byte[length];if(!DeviceIoControl(device,Code(function,access),input,input?.Length??0,output,length,out var received,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());
        if(received!=length)throw new InvalidDataException("Unexpected syscall intake reply length");return output;
    }
    private static uint U32(byte[] bytes,int offset)=>BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset,4));
    private static ulong U64(byte[] bytes,int offset)=>BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset,8));
    internal static bool SnapshotMayArrive(string? reason)=>reason is
        "syscall-proactive-acquisition-provider-unavailable" or
        "syscall-exact-process-snapshot-unavailable-or-index-capacity" or
        "syscall-exact-process-snapshot-unavailable; recovery-records-rejected";
    internal static (Guid Instance,string Status,long Lost) SourceInfo(byte[] source)
    {
        if(source.Length!=56||U32(source,0)!=1||U32(source,4)!=56||U32(source,28)!=0||U32(source,52)!=0||U32(source,48)>128)throw new InvalidDataException("Invalid native source identity");
        var id=new Guid(source.AsSpan(8,16));var status="0x"+U32(source,24).ToString("X8");
        if(id==Guid.Empty||status is not ("0x00000000" or "0x40020056"))throw new InvalidDataException("Native source UUID unavailable");
        return(id,status,checked((long)U64(source,40)));
    }
    internal static byte[] Key(Guid instance,long sequence)
    {
        if(instance==Guid.Empty||sequence<=0)throw new InvalidDataException("Invalid native intake key");
        var b=new byte[32];BinaryPrimitives.WriteUInt32LittleEndian(b,1);BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4),32);
        instance.TryWriteBytes(b.AsSpan(8,16));BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24),checked((ulong)sequence));return b;
    }
    internal static WindowsSyscallObservation Observation(byte[] raw,(Guid Instance,string Status,long Lost) source,byte[] target)
    {
        var native=WindowsSyscallDecoder.Decode(raw);
        if(target.Length!=3120||U32(target,0)!=1||U32(target,4)!=3120||new Guid(target.AsSpan(8,16))!=source.Instance||U64(target,24)!=(ulong)native.Sequence)throw new InvalidDataException("Target reply identity differs");
        var status=U32(target,40);var length=U32(target,44);string? name=null;
        if(length>3070||length%2!=0||status!=0&&length!=0)throw new InvalidDataException("Invalid target name length/status");
        string? undecodable=null;
        if(status==0){
            if(length==0)throw new InvalidDataException("Empty captured target name");
            try{name=new UnicodeEncoding(false,false,true).GetString(target,48,(int)length);if(name.Any(char.IsControl)){name=null;undecodable=Convert.ToBase64String(target,48,(int)length);}}
            catch(DecoderFallbackException){undecodable=Convert.ToBase64String(target,48,(int)length);}
        }
        var o=new WindowsSyscallObservation{SourceInstance=source.Instance.ToString("N"),SourceInstanceStatus=source.Status,LostRecords=source.Lost,Native=native,
            NativeTargetPath=name,TargetPath=name,TargetQueriedUtc=DateTimeOffset.FromFileTime(checked((long)U64(target,32))),
            TargetReplySha256=Convert.ToHexString(SHA256.HashData(target)),UnavailableTargetNameBase64=undecodable,
            TargetStatus=name!=null?EvidenceStatus.Captured("retained-file-object-name-queried-after-syscall"):new("unavailable",undecodable!=null?"retained-target-name-not-displayable":"retained-file-object-name-query-failed","0x"+status.ToString("X8"))};
        if(!o.IsValid())throw new InvalidDataException("Invalid native target observation");return o;
    }
    // Keep native intake on its own thread, as the existing minifilter receiver
    // does. Synchronous driver calls and durable commits must not compete with
    // signature verification/preservation for shared thread-pool workers. Do not
    // await a delay here: its continuation would return intake to that pool.
    private void Receive()
    {
        while(!stop.IsCancellationRequested)
        {
            try{
                Mark(ref receiveProgress,"device-open");
                using var device=CreateFile(@"\\.\SqSyscallObserverLab",0xC0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
                if(device.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());
                health("Experimental Windows syscall intake connected; scope is owned thread and registered handles only");
                while(!stop.IsCancellationRequested){
                    Mark(ref receiveProgress,"source-health-query");
                    var source=SourceInfo(Io(device,0xB10,1,null,56));byte[] raw;
                    Mark(ref receiveProgress,"native-peek");
                    try{raw=Io(device,0xB11,1,null,408);}catch(Win32Exception ex)when(ex.NativeErrorCode==259){if(stop.Token.WaitHandle.WaitOne(100))break;continue;}
                    var native=WindowsSyscallDecoder.Decode(raw);var key=Key(source.Instance,native.Sequence);
                    Mark(ref receiveProgress,"target-name-query",native.Sequence);
                    var observation=Observation(raw,source,Io(device,0xB13,1,key,3120));
                    if(OperatingSystem.IsWindows()&&kernel!=null)observation=kernel.DisplaySyscallTarget(observation);
                    Mark(ref receiveProgress,"raw-journal-commit",native.Sequence);
                    journal.Put(raw,observation); // FULL SQLite commit precedes destructive native acknowledgement.
                    Mark(ref receiveProgress,"native-acknowledgement",native.Sequence);
                    Io(device,0xB12,2,key,0);
                    if(source.Lost>0)health("Windows syscall native queue lost records: "+source.Lost);
                }
            }
            catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
            catch(Exception ex){health("Windows syscall intake pending: stage="+Volatile.Read(ref receiveProgress).Stage+"; hresult=0x"+ex.HResult.ToString("X8")+"; "+ex.GetType().Name+(ex is Win32Exception win?"; native-error="+win.NativeErrorCode:"")+"; raw records remain unacknowledged on failure");if(stop.Token.WaitHandle.WaitOne(2000))break;}
        }
        Mark(ref receiveProgress,"stopped");
    }
    private async Task Dispatch()
    {
        while(!stop.IsCancellationRequested)
        {
            try{
                Mark(ref dispatchProgress,"pending-journal-read");
                foreach(var observed in journal.Pending()){
                    if(stop.IsCancellationRequested)break;
                    var sequence=observed.Attribution?.WindowsSyscall?.Native.Sequence;
                    Mark(ref dispatchProgress,"prepared-journal-read",sequence,observed.EventId);
                    var publication=journal.Prepared(observed.EventId)??(uncommitted?.Original.EventId==observed.EventId?uncommitted:null);
                    if(publication==null){
                        AgentEvent value=observed;ActorLease? actor=null;
                        try{
                            Mark(ref dispatchProgress,"actor-snapshot-link",sequence,observed.EventId);
                            try{if(OperatingSystem.IsWindows())actor=kernel?.CaptureSyscallActor(observed,out value);}
                            catch(Exception ex)when(ActorLease.OptionalFailure(ex)){health("Syscall actor snapshot unavailable: "+ex.GetType().Name);}
                            // Give the independent creation-snapshot receiver a
                            // bounded opportunity to commit first-use bytes.
                            // Never reopen a live PID or path to fill the gap.
                            for(var attempt=0;attempt<20&&actor!=null&&SnapshotMayArrive(actor.Binding.Reason);attempt++){
                                actor.Dispose();actor=null;await Task.Delay(250,stop.Token);
                                try{if(OperatingSystem.IsWindows())actor=kernel?.CaptureSyscallActor(observed,out value);}
                                catch(Exception ex)when(ActorLease.OptionalFailure(ex)){health("Syscall actor snapshot unavailable: "+ex.GetType().Name);break;}
                            }
                            actor??=ActorLease.Unavailable(observed,"syscall-exact-process-snapshot-unavailable");actor.ApplyKernel(value,sensor);
                            Mark(ref dispatchProgress,"forensic-collection",sequence,observed.EventId);
                            publication=forensics.CollectForPublication(value,actor,policy());uncommitted=publication;
                        }
                        finally{actor?.Dispose();}
                    }
                    Mark(ref dispatchProgress,"prepared-pair-commit",sequence,observed.EventId);
                    journal.Prepare(publication);uncommitted=null;
                    // Register only an immutable prepared pair. Both events must
                    // reach the enrolled durable spool before retiring intake.
                    Mark(ref dispatchProgress,"publication-registration",sequence,observed.EventId);
                    forensics.RegisterPublication(publication);
                    Mark(ref dispatchProgress,"original-publication",sequence,observed.EventId);publish(publication.Original);
                    Mark(ref dispatchProgress,"completion-publication",sequence,observed.EventId);publish(publication.Completion);
                    Mark(ref dispatchProgress,"journal-retirement",sequence,observed.EventId);journal.Complete(observed.EventId);
                }
                await Task.Delay(250,stop.Token);
            }
            catch(OperationCanceledException)when(stop.IsCancellationRequested){break;}
            catch(Exception ex){health("Windows syscall reporting held for retry: stage="+Volatile.Read(ref dispatchProgress).Stage+"; hresult=0x"+ex.HResult.ToString("X8")+"; "+ex.GetType().Name);try{await Task.Delay(2000,stop.Token);}catch(OperationCanceledException){break;}}
        }
        Mark(ref dispatchProgress,"stopped");
    }
    internal static AsyncDisposeOnce DrainLifetime(CancellationTokenSource cancellation,Task intake,Task reporting,WindowsSyscallJournal ownedJournal)
        =>new(async()=>{cancellation.Cancel();try{await Task.WhenAll(intake,reporting).ConfigureAwait(false);}finally{ownedJournal.Dispose();cancellation.Dispose();}});
    public ValueTask DisposeAsync()=>new(disposal.DisposeAsync());
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool DeviceIoControl(SafeFileHandle file,uint code,byte[]? input,int inputLength,[Out]byte[] output,int outputLength,out int received,IntPtr overlapped);
}
