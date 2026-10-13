using RansomFree.Contracts;
using System.ComponentModel;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;

namespace RansomFree.Client;

// Owned process/pipe lifetime primitive for the opt-in controlled source.
// It opens no actor controller and grants no source activation authority.
// .NET10 Process.Unix creates AnonymousPipeClientStream for redirected pipes.
// Linux x64 syscall numbers are pinned to v6.12.94 syscall_64.tbl.
internal sealed class LinuxOwnedLoaderProcess:IDisposable
{
    internal sealed record Launch(string Loader,string ObjectFile,string Target,string LibraryDirectory)
    {
        public uint ControlVersion {get;init;}=1;
        public ImmutableArray<string> Targets {get;init;}=[];
    }
    internal sealed record CloseReceipt(DateTimeOffset AttemptedUtc,DateTimeOffset ReturnedUtc,int? Result,int? Error,string? ManagedFailure);
    internal sealed record PipeWrite(DateTimeOffset AttemptedUtc,DateTimeOffset ReturnedUtc,int Requested,long Written,int WriteError,int? CloseResult,int? CloseError,string? CloseFailure,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? CommandSha256=null,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] long? AttemptedMonotonic=null,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] long? ReturnedMonotonic=null,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] long? MonotonicFrequency=null);
    internal sealed record FramingFailure(DateTimeOffset RecordedUtc,string Reason,ReadOnlyMemory<byte> BufferedPrefix);
    internal sealed record Diagnostics(long StderrBytes,string StderrTailBase64,long UnframedDrainBytes,string? StdoutFailure,string? StderrFailure,string? StartupFailure,int? SignalError,int? InputCloseResult,int? InputCloseError,string State,int BufferedFailureBytes,string? BufferedFailureSha256,CloseReceipt? InputClose,CloseReceipt? PidfdClose);
    internal sealed record TestFaults(bool InputManagedFailure=false,bool InputReportedCloseError=false,bool BindFailure=false);
    private readonly Process child;
    private readonly Channel<byte[]> frames=Channel.CreateBounded<byte[]>(new BoundedChannelOptions(4){SingleReader=true,SingleWriter=true,FullMode=BoundedChannelFullMode.Wait});
    private readonly object control=new(),diagnosticsGate=new();
    private readonly byte[] stderrTail=new byte[8192];
    private int stderrUsed,reading;
    private long stderrBytes,unframedBytes;
    private string? stdoutFailure,stderrFailure,startupFailure;
    private readonly TaskCompletionSource<FramingFailure> framingFault=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task<FramingFailure> FramingFault=>framingFault.Task;
    private readonly TestFaults? testFaults;
    private readonly Action<FramingFailure>? framingFaultLatch;
    private CloseReceipt? inputClose,pidfdClose;
    private int? signalError;
    private int? inputCloseResult,inputCloseError;
    private bool inputClosed,activationAttempted,stopAttempted,disposed;
    private SafeFileHandle? pidfd;
    private readonly Task stdoutTask,stderrTask,exitTask;
    internal Task Completion {get;}
    internal PipeWrite? ActivationWrite {get;private set;}
    internal bool ActivationAttempted {get{lock(control)return activationAttempted;}}
    internal int Pid=>child.Id;
    internal int? ExitCode=>exitTask.IsCompletedSuccessfully?child.ExitCode:null;
    internal bool HasExited=>exitTask.IsCompletedSuccessfully;
    private static void Platform()
    {if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("Owned loader requires qualified Linux x64");}
    internal static LinuxOwnedLoaderProcess Start(Launch config,Action<FramingFailure>? faultLatch=null)
    {
        Platform();
        var arguments=BuildArguments(config);
        // Package/hash/permission validation is owned by the source's launch
        // configuration gate. No shell, caller process, or inherited preload.
        return StartCore(config.Loader,arguments,config.LibraryDirectory,faultLatch:faultLatch);
    }
    internal static string[] BuildArguments(Launch config)
    {
        foreach(var p in new[]{config.Loader,config.ObjectFile,config.Target,config.LibraryDirectory})
            if(p==null||!Path.IsPathFullyQualified(p)||p.Contains('\0'))throw new ArgumentException("Absolute controlled loader paths required");
        if(config.ControlVersion==1)
        {
            if(!config.Targets.IsDefaultOrEmpty)throw new ArgumentException("Legacy source cannot specify a v2 target list");
            return ["--controlled",config.ObjectFile,config.Target];
        }
        if(config.ControlVersion is not (2 or 3 or 4)||config.Targets.IsDefaultOrEmpty||config.Targets.Length>LinuxControlledTargetSet.MaximumTargets||config.Targets[0]!=config.Target||
            config.Targets.Any(p=>p==null||!Path.IsPathFullyQualified(p)||p.Contains('\0'))||config.Targets.Distinct(StringComparer.Ordinal).Count()!=config.Targets.Length)
            throw new ArgumentException("Explicit bounded controlled-v2 target list required; no fallback");
        return [config.ControlVersion==4?"--controlled-v4":config.ControlVersion==3?"--controlled-v3":"--controlled-v2",config.ObjectFile,..config.Targets];
    }
    internal static LinuxOwnedLoaderProcess StartForTest(string executable,string[] arguments,TestFaults? faults=null)
    {Platform();return StartCore(executable,arguments,null,faults);}
    private static LinuxOwnedLoaderProcess StartCore(string executable,string[] arguments,string? library,TestFaults? faults=null,Action<FramingFailure>? faultLatch=null)
    {
        var start=new ProcessStartInfo(executable){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true};
        start.Environment.Clear();start.Environment["PATH"]="/usr/sbin:/usr/bin:/sbin:/bin";start.Environment["LANG"]="C";
        start.Environment["DOTNET_SYSTEM_GLOBALIZATION_INVARIANT"]="1";
        if(library!=null)start.Environment["LD_LIBRARY_PATH"]=library;
        foreach(var arg in arguments)start.ArgumentList.Add(arg);
        return new(Process.Start(start)??throw new IOException("Loader process did not start"),faults,faultLatch);
    }
    private LinuxOwnedLoaderProcess(Process child,TestFaults? faults,Action<FramingFailure>? faultLatch)
    {
        this.child=child;testFaults=faults;framingFaultLatch=faultLatch;
        // Both drains start immediately, before any handshake or map/device I/O.
        stdoutTask=Task.Run(DrainFrames);stderrTask=Task.Run(DrainStderr);
        exitTask=child.WaitForExitAsync();
        try
        {
            if(child.HasExited)throw new IOException("Loader exited before process binding");
            if(testFaults?.BindFailure==true)throw new Win32Exception(24,"Owned test binding failure");
            var fd=PidfdOpen(434,child.Id,0);if(fd<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            pidfd=new SafeFileHandle((IntPtr)fd,true);
            // .NET reaps owned children asynchronously. Check its original
            // child wait-state AFTER opening; never signal a recycled PID.
            if(child.HasExited){ClosePidfd();pidfd=null;throw new IOException("Loader exited during process binding");}
        }
        catch(Exception ex)when(ex is IOException or Win32Exception or EntryPointNotFoundException)
        {startupFailure=ex.GetType().Name;TryCloseInput();}
        Completion=Complete();
    }
    private async Task Complete(){await Task.WhenAll(exitTask,stdoutTask,stderrTask).ConfigureAwait(false);}
    private async Task DrainFrames()
    {
        var stream=child.StandardOutput.BaseStream;Exception? failure=null;var reader=new LinuxLoaderFrameReader(stream,65536);
        try
        {
            while(await reader.ReadAsync().ConfigureAwait(false) is {} frame)await frames.Writer.WriteAsync(frame).ConfigureAwait(false);
        }
        catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException)
        {
            failure=ex;lock(diagnosticsGate)stdoutFailure=ex.GetType().Name+": "+ex.Message;
            // Publish independently of queued frames: the runtime must latch
            // its barrier before admitting any further native work. Keep the
            // exact bounded reader prefix separately from later pipe drainage.
            var captured=new FramingFailure(DateTimeOffset.UtcNow,stdoutFailure,reader.TakeFaultedRemainder());
            // The owned source uses only its short in-memory barrier here,
            // never disk/native I/O. Its latch closes authorization races even
            // while older frames remain queued ahead of the channel error.
            try{framingFaultLatch?.Invoke(captured);}
            catch(Exception latch)when(latch is not OutOfMemoryException){lock(diagnosticsGate)stdoutFailure+="; latch:"+latch.GetType().Name;}
            framingFault.TrySetResult(captured);
            frames.Writer.TryComplete(failure); // Notify owner before drain/EOF.
            // The framing contract is irrecoverably lost. Keep draining fixed
            // buffers so a child can finish teardown; never emit guessed frames.
            var discard=new byte[4096];
            try{int n;while((n=await stream.ReadAsync(discard).ConfigureAwait(false))>0)Interlocked.Add(ref unframedBytes,n);}
            catch(Exception drain)when(drain is IOException or InvalidOperationException){lock(diagnosticsGate)stdoutFailure+="; drain:"+drain.GetType().Name;}
        }
        finally{frames.Writer.TryComplete(failure);}
    }
    private async Task DrainStderr()
    {
        var buffer=new byte[4096];
        try
        {
            int n;while((n=await child.StandardError.BaseStream.ReadAsync(buffer).ConfigureAwait(false))>0)
            {
                lock(diagnosticsGate)
                {
                    stderrBytes=checked(stderrBytes+n);var keep=Math.Min(stderrUsed,stderrTail.Length-n);
                    if(keep>0)Buffer.BlockCopy(stderrTail,stderrUsed-keep,stderrTail,0,keep);
                    Buffer.BlockCopy(buffer,0,stderrTail,keep,n);stderrUsed=keep+n;
                }
            }
        }
        catch(Exception ex)when(ex is IOException or InvalidOperationException){lock(diagnosticsGate)stderrFailure=ex.GetType().Name;}
    }
    internal async ValueTask<byte[]?> ReadFrameAsync(CancellationToken waitCancellation=default)
    {
        if(Interlocked.Exchange(ref reading,1)!=0)throw new InvalidOperationException("Only one source may consume owned loader frames");
        try
        {
            // Cancellation affects this managed queue wait only. The real
            // stdout/stderr readers and child exit wait remain owned and live.
            return await frames.Reader.WaitToReadAsync(waitCancellation).ConfigureAwait(false)&&frames.Reader.TryRead(out var frame)?frame:null;
        }
        finally{Volatile.Write(ref reading,0);}
    }
    internal PipeWrite ActivateOnce(LinuxControlledLoaderProtocol.Ready ready,string session)
    {
        var frame=LinuxControlledLoaderProtocol.ActivationFrame(ready,session);
        lock(control)
        {
            if(disposed||activationAttempted||inputClosed||stopAttempted||startupFailure!=null||FramingFault.IsCompleted||HasExited)throw new InvalidOperationException("Owned activation is unavailable or already attempted");
            if(child.StandardInput.BaseStream is not AnonymousPipeClientStream pipe)throw new InvalidDataException("Qualified .NET anonymous input pipe required");
            var flags=GetFlags(pipe.SafePipeHandle,3);
            if(flags<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
            if((flags&0x800)!=0||frame.Length>4096)throw new InvalidDataException("One bounded blocking pipe write required");
            var digest=Convert.ToHexString(SHA256.HashData(frame));
            activationAttempted=true;var began=DateTimeOffset.UtcNow;var monotonic=Stopwatch.GetTimestamp();
            // One syscall, no retry even on EINTR/short return. EOF is mandatory.
            var written=Write(pipe.SafePipeHandle,frame,(nuint)frame.Length);var error=written<0?Marshal.GetLastPInvokeError():0;
            var closed=TryCloseInput();
            return ActivationWrite=new(began,DateTimeOffset.UtcNow,frame.Length,(long)written,error,closed.Result,closed.Error,closed.ManagedFailure,digest,monotonic,Stopwatch.GetTimestamp(),Stopwatch.Frequency);
        }
    }
    private CloseReceipt TryCloseInput()
    {
        lock(control)
        {
            if(inputClose!=null)return inputClose;inputClosed=true;var began=DateTimeOffset.UtcNow;
            try
            {
            if(testFaults?.InputManagedFailure==true)throw new InvalidDataException("Owned test managed pre-close failure");
            if(child.StandardInput.BaseStream is not AnonymousPipeClientStream pipe)throw new InvalidDataException("Qualified owned pipe required");
            // This private handle has no competing writer or asynchronous I/O.
            // Remove SafeHandle ownership before the one explicit close so its
            // error is observable and no finalizer retries a recycled fd.
            var fd=pipe.SafePipeHandle.DangerousGetHandle().ToInt32();pipe.SafePipeHandle.SetHandleAsInvalid();
            var result=Close(fd);var error=result<0?Marshal.GetLastPInvokeError():0;
            if(testFaults?.InputReportedCloseError==true){result=-1;error=5;}
            inputCloseResult=result;inputCloseError=error;
            return inputClose=new(began,DateTimeOffset.UtcNow,result,error,null);
            }
            catch(Exception ex)when(ex is not OutOfMemoryException)
            {return inputClose=new(began,DateTimeOffset.UtcNow,null,null,ex.GetType().Name);}
        }
    }
    private CloseReceipt? ClosePidfd()
    {
        if(pidfdClose!=null||pidfd==null)return pidfdClose;
        var began=DateTimeOffset.UtcNow;var fd=pidfd.DangerousGetHandle().ToInt32();pidfd.SetHandleAsInvalid();
        var result=Close(fd);var error=result<0?Marshal.GetLastPInvokeError():0;
        return pidfdClose=new(began,DateTimeOffset.UtcNow,result,error,null);
    }
    internal void RequestStop()
    {
        lock(control)
        {
            if(disposed||stopAttempted)return;stopAttempted=true;TryCloseInput();
            if(HasExited||pidfd==null)return;
            var result=SendSignal(424,pidfd,15,IntPtr.Zero,0);signalError=result<0?Marshal.GetLastPInvokeError():0;
            // ESRCH means the referenced child already exited, not a new PID.
            if(signalError is not (0 or 3))throw new Win32Exception(signalError.Value,"Owned loader stop signal failed; lifetime retained");
        }
    }
    internal Diagnostics Snapshot()
    {
        lock(control)lock(diagnosticsGate)
        {
            var fault=FramingFault.IsCompletedSuccessfully?FramingFault.Result:null;
            return new(stderrBytes,Convert.ToBase64String(stderrTail,0,stderrUsed),Interlocked.Read(ref unframedBytes),stdoutFailure,stderrFailure,startupFailure,signalError,inputCloseResult,inputCloseError,
                disposed?"DISPOSED":startupFailure!=null&&!HasExited?"STARTUP_BIND_FAILED_WAITING_FOR_EXIT":HasExited?"EXITED_DRAINING_OR_COMPLETE":startupFailure!=null?"STARTUP_BIND_FAILED_EXITED":"BOUND_OWNED_CHILD",
                fault?.BufferedPrefix.Length??0,fault==null?null:Convert.ToHexString(SHA256.HashData(fault.BufferedPrefix.Span)),inputClose,pidfdClose);
        }
    }
    public void Dispose()
    {
        lock(control)
        {
            if(disposed)return;
            if(!Completion.IsCompletedSuccessfully)throw new InvalidOperationException("Loader exit and both pipe drains must actually finish before disposal");
            TryCloseInput();ClosePidfd();child.Dispose();disposed=true;
        }
    }
    [DllImport("libc",SetLastError=true,EntryPoint="syscall")]private static extern long PidfdOpen(long number,int pid,uint flags);
    [DllImport("libc",SetLastError=true,EntryPoint="syscall")]private static extern long SendSignal(long number,SafeFileHandle pidfd,int signal,IntPtr info,uint flags);
    [DllImport("libc",SetLastError=true,EntryPoint="write")]private static extern nint Write(SafePipeHandle fd,byte[] bytes,nuint count);
    [DllImport("libc",SetLastError=true,EntryPoint="fcntl")]private static extern int GetFlags(SafePipeHandle fd,int command);
    [DllImport("libc",SetLastError=true,EntryPoint="close")]private static extern int Close(int fd);
}
