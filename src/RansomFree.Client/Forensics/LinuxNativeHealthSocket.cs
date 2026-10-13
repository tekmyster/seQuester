using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Authenticated live status only. Nothing received here can authorize actor
// matching, native selection, executable preservation or response actions.
internal sealed class LinuxNativeHealthSocket:IAsyncDisposable
{
    internal const string Name="health.sock";
    private const int MaximumFrame=32768;
    internal sealed record Request(int Version,string SensorId,string Server,string Nonce);
    internal sealed record Reply(int Version,string SensorId,string Server,string Nonce,int Pid,string StartTicks,string BootId,string InstanceId,
        long Sequence,long RecordedMonotonic,long MonotonicFrequency,DateTimeOffset RecordedUtc,LinuxControlledSourceRuntime.ServiceHealth? Source);
    internal sealed record Observation(Reply Reply,long ReceivedMonotonic,string Reason)
    {
        internal bool IsFresh(long now)=>now>=ReceivedMonotonic&&(decimal)now-ReceivedMonotonic<=10m*Stopwatch.Frequency;
        internal bool ActiveAtSample=>Reason=="LINUX_NATIVE_SERVICE_READY_AT_SAMPLE";
    }
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    [DllImport("libc",EntryPoint="syscall",SetLastError=true)]private static extern int PidfdOpen(long number,int pid,uint flags);
    [StructLayout(LayoutKind.Sequential)]private struct PollDescriptor {internal int Fd;internal short Events,Returned;}
    [DllImport("libc",EntryPoint="poll",SetLastError=true)]private static extern int Poll(ref PollDescriptor descriptor,nuint count,int timeout);
    private readonly LinuxProtectedDirectory directory;
    private readonly LinuxProtectedDirectory.Identity node;
    private readonly Socket listener;
    private readonly CancellationTokenSource closing=new();
    private readonly SemaphoreSlim single=new(1,1);
    private readonly object shutdownGate=new();
    private readonly string sensor,server,startTicks,bootId,instanceId=Guid.NewGuid().ToString("N");
    private readonly uint uid;
    private readonly Func<LinuxControlledSourceRuntime.ServiceHealth?> sample;
    private long sequence;
    private int disposed;
    private string closeState="OPEN";
    internal string CloseState=>Volatile.Read(ref closeState);
    private Task? shutdown;
    private static void Platform()
    {if(!OperatingSystem.IsLinux()||RuntimeInformation.ProcessArchitecture!=Architecture.X64)throw new PlatformNotSupportedException("Qualified Linux x64 health channel required");}
    private static void Context(string sensor,string server)
    {if(!Guid.TryParseExact(sensor,"N",out _)||!NativePolicySnapshot.ValidOrigin(server))throw new ArgumentException("Exact enrolled health context required");}
    private static string Boot()
    {
        var value=File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
        if(!Guid.TryParseExact(value,"D",out _))throw new IOException("Boot identity unavailable");return value;
    }
    private static string StartTicks(int pid)
    {
        if(pid<=1)throw new IOException("Health peer PID unavailable");
        var text=File.ReadAllText($"/proc/{pid}/stat");var close=text.LastIndexOf(')');
        if(text.Length>8192||close<0)throw new IOException("Health peer process identity unavailable");
        var fields=text[(close+2)..].Split(' ',StringSplitOptions.RemoveEmptyEntries);
        if(fields.Length<20||fields[0] is "Z" or "X"||!ulong.TryParse(fields[19],NumberStyles.None,CultureInfo.InvariantCulture,out var start)||start==0)
            throw new IOException("Health peer exited or process start identity unavailable");return fields[19];
    }
    private static void RequireAlive(SafeFileHandle pidfd)
    {
        var descriptor=new PollDescriptor{Fd=checked((int)pidfd.DangerousGetHandle()),Events=1};var result=Poll(ref descriptor,1,0);
        if(result<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        if(result!=0||descriptor.Returned!=0)throw new IOException("Root health peer has exited or is unavailable");
    }
    internal LinuxNativeHealthSocket(string rootDirectory,uint serviceUid,uint serviceGroup,string sensor,string server,Func<LinuxControlledSourceRuntime.ServiceHealth?> sample)
    {
        Platform();Context(sensor,server);ArgumentNullException.ThrowIfNull(sample);
        if(UserId()!=0)throw new UnauthorizedAccessException("Root health listener required");
        if(serviceUid is 0 or uint.MaxValue||serviceGroup is 0 or uint.MaxValue)throw new ArgumentException("Dedicated ordinary sensor identity required");
        this.sensor=sensor;this.server=server;uid=serviceUid;this.sample=sample;bootId=Boot();startTicks=StartTicks(Environment.ProcessId);
        directory=LinuxProtectedDirectory.OpenRoot(rootDirectory,serviceGroup);listener=new(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        try{listener.Bind(new UnixDomainSocketEndPoint(directory.SocketPath(Name)));directory.ConfigureSocket(Name);node=directory.RequireSocket(Name);listener.Listen(1);}
        catch{listener.Dispose();directory.Dispose();throw;}
    }
    internal async Task AcceptAsync(CancellationToken cancel)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed)!=0,this);
        if(!await single.WaitAsync(0,cancel).ConfigureAwait(false))throw new InvalidOperationException("One health exchange at a time");
        var phase="ACCEPT";var began=Stopwatch.GetTimestamp();
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel,closing.Token);
            using var socket=await listener.AcceptAsync(deadline.Token).ConfigureAwait(false);began=Stopwatch.GetTimestamp();phase="PEER_IDENTITY";_=LinuxNativePolicySocket.RequirePeer(socket,uid);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));var token=deadline.Token;
            phase="REQUEST_READ";
            using var stream=new NetworkStream(socket,ownsSocket:false);var request=await LinuxNativePolicySocket.Read<Request>(stream,token,MaximumFrame).ConfigureAwait(false);
            if(request.Version!=1||request.SensorId!=sensor||request.Server!=server||!Guid.TryParseExact(request.Nonce,"N",out _))throw new InvalidDataException("Health request context mismatch");
            // The I/O deadline cannot forcibly cancel a synchronous source/map
            // read. Retain exchange ownership until its actual return; shutdown
            // remains CLOSE_DRAINING throughout that interval.
            token.ThrowIfCancellationRequested();phase="SOURCE_SAMPLE";var source=sample();token.ThrowIfCancellationRequested();
            if(source!=null&&source.SensorId!=sensor)throw new InvalidDataException("Health callback returned a foreign source");
            var reply=new Reply(1,sensor,server,request.Nonce,Environment.ProcessId,startTicks,bootId,instanceId,checked(++sequence),Stopwatch.GetTimestamp(),Stopwatch.Frequency,DateTimeOffset.UtcNow,source);
            phase="REPLY_WRITE";await LinuxNativePolicySocket.Write(stream,reply,token).ConfigureAwait(false);
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {RecordFailure(error,"SERVER",phase,began);throw;}
        finally{single.Release();}
    }
    internal static async Task<Observation> QueryAsync(string rootDirectory,uint group,string sensor,string server,CancellationToken cancel)
    {
        Platform();Context(sensor,server);var began=Stopwatch.GetTimestamp();var phase="BOOT_IDENTITY";
        try
        {
        var boot=Boot();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);deadline.CancelAfter(TimeSpan.FromSeconds(5));var token=deadline.Token;
        phase="CHANNEL_IDENTITY";
        using var parent=LinuxProtectedDirectory.OpenRoot(rootDirectory,group);parent.RequireSocket(Name);
        using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        phase="CONNECT";await socket.ConnectAsync(new UnixDomainSocketEndPoint(parent.SocketPath(Name)),token).ConfigureAwait(false);
        phase="PEER_IDENTITY";var peer=LinuxNativePolicySocket.RequirePeer(socket,0);
        phase="PIDFD_OPEN";
        var pid=PidfdOpen(434,peer.Pid,0);if(pid<0)throw new Win32Exception(Marshal.GetLastPInvokeError());
        using var pidfd=new SafeFileHandle((nint)pid,true);phase="PROCESS_IDENTITY";RequireAlive(pidfd);var start=StartTicks(peer.Pid);
        using var stream=new NetworkStream(socket,ownsSocket:false);var nonce=Guid.NewGuid().ToString("N");
        phase="REQUEST_WRITE";await LinuxNativePolicySocket.Write(stream,new Request(1,sensor,server,nonce),token).ConfigureAwait(false);
        phase="REPLY_READ";
        var reply=await LinuxNativePolicySocket.Read<Reply>(stream,token,MaximumFrame).ConfigureAwait(false);
        phase="REPLY_IDENTITY";
        if(reply.Version!=1||reply.SensorId!=sensor||reply.Server!=server||reply.Nonce!=nonce||reply.Pid!=peer.Pid||reply.StartTicks!=start||reply.BootId!=boot||!Guid.TryParseExact(reply.InstanceId,"N",out _)||reply.Sequence<1)
            throw new InvalidDataException("Root health reply identity or nonce mismatch");
        phase="PROCESS_RECHECK";if(StartTicks(peer.Pid)!=start||Boot()!=boot)throw new IOException("Root health process or boot changed");RequireAlive(pidfd);
        var returned=Stopwatch.GetTimestamp();token.ThrowIfCancellationRequested();
        phase="FRESHNESS";
        if(reply.MonotonicFrequency!=Stopwatch.Frequency||reply.RecordedMonotonic<began||reply.RecordedMonotonic>returned||returned<began||(decimal)returned-began>5m*Stopwatch.Frequency)
            throw new InvalidDataException("Root health response timing unavailable or stale");
        var reason=Readiness(reply.Source,sensor,began,reply.RecordedMonotonic,DateTimeOffset.UtcNow);
        return new(reply,returned,reason);
        }
        catch(Exception error)when(error is not OutOfMemoryException)
        {RecordFailure(error,"CLIENT",phase,began);throw;}
    }
    // Keep original exception types and raw OS codes. Do not emit credentials,
    // nonces, paths, token contents or arbitrary exception messages.
    private static void RecordFailure(Exception error,string side,string phase,long began)
    {
        error.Data["LinuxNativeHealthSide"]=side;error.Data["LinuxNativeHealthPhase"]=phase;
        error.Data["LinuxNativeHealthElapsedMs"]=Math.Max(0,(long)((decimal)(Stopwatch.GetTimestamp()-began)*1000/Stopwatch.Frequency));
    }
    internal static string FailureDiagnostic(Exception error)
    {
        var code=error is Win32Exception native?native.NativeErrorCode:error is SocketException socket?socket.ErrorCode:(int?)null;
        var side=error.Data["LinuxNativeHealthSide"] as string;var phase=error.Data["LinuxNativeHealthPhase"] as string;
        var elapsed=error.Data["LinuxNativeHealthElapsedMs"] is long milliseconds?milliseconds:(long?)null;
        return System.Text.Json.JsonSerializer.Serialize(new{Component="linux-native-health",Side=side,Phase=phase,
            ErrorType=error.GetType().Name,NativeCode=code,HResult=error.HResult,ElapsedMs=elapsed});
    }
    internal static string Readiness(LinuxControlledSourceRuntime.ServiceHealth? source,string sensor,long began,long recorded,DateTimeOffset now)
    {
        if(source==null)return "LINUX_NATIVE_SERVICE_STARTING_OR_UNAVAILABLE";
        if(source.SensorId!=sensor||!Guid.TryParseExact(source.RuntimeId,"N",out _))return "LINUX_NATIVE_SERVICE_SOURCE_MISMATCH";
        if(source.Phase!="ACTIVE"||source.Reason!="LINUX_SOURCE_HEALTH_SAMPLED"||source.Sample==null)return "LINUX_NATIVE_SERVICE_SOURCE_UNAVAILABLE";
        var sample=source.Sample;
        if(!Guid.TryParseExact(source.Session,"N",out _)||!Guid.TryParseExact(source.CollectorInstance,"N",out _)||
            !ulong.TryParse(source.ProviderEpoch,NumberStyles.None,CultureInfo.InvariantCulture,out var epoch)||epoch==0||
            source.TargetSetSha256 is not {Length:64}||!source.TargetSetSha256.All(Uri.IsHexDigit)||source.PolicyDigest is not {Length:64}||!source.PolicyDigest.All(Uri.IsHexDigit)||
            source.PolicyExpiresUtc==null||source.PolicyExpiresUtc<=now||!sample.IsValid(sample.Generation)||sample.MonotonicFrequency!=Stopwatch.Frequency||
            sample.ActiveBeforeTicks<began||sample.SealedTicks>recorded)
            return "LINUX_NATIVE_SERVICE_SAMPLE_INVALID_OR_EXPIRED";
        return "LINUX_NATIVE_SERVICE_READY_AT_SAMPLE";
    }
    public ValueTask DisposeAsync(){lock(shutdownGate)return new(shutdown??=StopAndDrain());}
    private async Task StopAndDrain()
    {
        Interlocked.Exchange(ref disposed,1);Volatile.Write(ref closeState,"CLOSE_DRAINING");Exception? failure=null;
        try{closing.Cancel();}catch(Exception e){failure=e;}try{listener.Dispose();}catch(Exception e){failure??=e;}
        await single.WaitAsync().ConfigureAwait(false);
        try{if(failure!=null)throw new IOException("Health listener close failed",failure);directory.RetireOwnedSocket(Name,node);Volatile.Write(ref closeState,"CLOSED");}
        catch{Volatile.Write(ref closeState,"CLOSE_FAILED");throw;}
        finally{directory.Dispose();single.Release();}
    }
}
