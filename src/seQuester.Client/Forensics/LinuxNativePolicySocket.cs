using System.Buffers.Binary;
using System.ComponentModel;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Linux-only bounded policy relay. It exposes no native operation, filename,
// executable or cleanup request. SO_PEERCRED describes the connection peer at
// connect/listen time, not a file-operation actor or a live thread identity.
internal sealed class LinuxNativePolicySocket:IDisposable,IAsyncDisposable
{
    internal const string Name="policy.sock";
    internal const int MaximumFrame=768*1024;
    internal static readonly TimeSpan ExchangeTimeout=TimeSpan.FromSeconds(90);
    internal sealed record Peer(int Pid,uint Uid,uint Gid);
    internal sealed record Request(int Version,string SensorId,string Server,string RequestId);
    internal sealed record Challenge(int Version,string SensorId,string Server,string RequestId,string Nonce);
    internal sealed record Reply(int Version,string RequestId,SignedNativePolicy Envelope);
    internal sealed record Accepted(int Version,string RequestId,string Nonce,string KeyId);
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    [DllImport("libc",EntryPoint="getsockopt",SetLastError=true)]private static extern int GetOption(SafeSocketHandle socket,int level,int name,[Out] byte[] value,ref uint length);
    private readonly LinuxProtectedDirectory directory;
    private readonly Socket listener;
    private readonly LinuxProtectedDirectory.Identity node;
    private readonly CancellationTokenSource closing=new();
    private readonly uint uid;
    private readonly string sensor,server;
    private readonly SemaphoreSlim single=new(1,1);
    private readonly object shutdownGate=new();
    private Task? shutdown;
    private int disposed;
    internal LinuxNativePolicySocket(string rootDirectory,uint serviceUid,uint serviceGroup,string sensor,string server)
    {
        Context(sensor,server);
        if(!OperatingSystem.IsLinux()||UserId()!=0)throw new UnauthorizedAccessException("Linux root listener required");
        if(serviceUid is 0 or uint.MaxValue||serviceGroup is 0 or uint.MaxValue)throw new ArgumentException("Dedicated ordinary service identity required");
        this.sensor=sensor;this.server=server;uid=serviceUid;directory=LinuxProtectedDirectory.OpenRoot(rootDirectory,serviceGroup);
        listener=new(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        try
        {
            // Bind refuses an existing path; never unlink another listener or
            // silently discard a stale node during startup.
            listener.Bind(new UnixDomainSocketEndPoint(directory.SocketPath(Name)));directory.ConfigureSocket(Name);node=directory.RequireSocket(Name);listener.Listen(1);
        }
        catch{listener.Dispose();directory.Dispose();throw;}
    }
    private static void Context(string sensor,string server)
    {if(!Guid.TryParseExact(sensor,"N",out _)||!NativePolicySnapshot.ValidOrigin(server))throw new ArgumentException("Exact enrolled policy relay context required");}
    internal static Peer RequirePeer(Socket socket,uint expectedUid)
    {
        if(!OperatingSystem.IsLinux()||socket.AddressFamily!=AddressFamily.Unix||socket.SocketType!=SocketType.Stream||!socket.Connected)throw new InvalidOperationException("Connected Linux Unix stream required");
        var bytes=new byte[12];uint size=12;
        if(GetOption(socket.SafeHandle,1,17,bytes,ref size)!=0)throw new Win32Exception(Marshal.GetLastPInvokeError()); // SOL_SOCKET/SO_PEERCRED
        var peer=new Peer(BitConverter.ToInt32(bytes,0),BitConverter.ToUInt32(bytes,4),BitConverter.ToUInt32(bytes,8));
        if(size!=12||peer.Pid<=0||peer.Uid!=expectedUid)throw new UnauthorizedAccessException("Policy relay peer identity mismatch");return peer;
    }
    internal static async Task<T> Read<T>(Stream stream,CancellationToken cancel,int maximum=MaximumFrame)
    {
        if(maximum is <1 or >MaximumFrame)throw new ArgumentOutOfRangeException(nameof(maximum));
        var header=new byte[4];await stream.ReadExactlyAsync(header,cancel).ConfigureAwait(false);var size=BinaryPrimitives.ReadUInt32LittleEndian(header);
        if(size==0||size>maximum)throw new InvalidDataException("Policy relay frame exceeds bound");
        var bytes=new byte[checked((int)size)];await stream.ReadExactlyAsync(bytes,cancel).ConfigureAwait(false);
        T value;try{value=JsonSerializer.Deserialize<T>(bytes)??throw new InvalidDataException("Empty policy relay object");}
        catch(JsonException ex){throw new InvalidDataException("Invalid policy relay JSON",ex);}
        if(!JsonSerializer.SerializeToUtf8Bytes(value).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Unknown, duplicate or noncanonical policy relay fields");return value;
    }
    internal static async Task Write<T>(Stream stream,T value,CancellationToken cancel)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(value);if(bytes.Length is 0 or >MaximumFrame)throw new InvalidDataException("Policy relay frame exceeds bound");
        var header=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(header,(uint)bytes.Length);await stream.WriteAsync(header,cancel).ConfigureAwait(false);await stream.WriteAsync(bytes,cancel).ConfigureAwait(false);
    }
    internal async Task<LinuxNativePolicyLease> AcceptAsync(LinuxNativePolicyAdmission owner,CancellationToken cancel)
        =>await AcceptAsync(owner,policy=>owner.AcceptLease(policy),cancel);
    internal async Task<LinuxNativePolicyLease> AcceptAsync(LinuxNativePolicyAdmission owner,Func<SignedNativePolicy,LinuxNativePolicyLease> admit,CancellationToken cancel,Action<LinuxNativePolicyLease>? confirmed=null)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed)!=0,this);
        if(!await single.WaitAsync(0,cancel).ConfigureAwait(false))throw new InvalidOperationException("One policy relay exchange at a time");
        LinuxNativePolicyLease? admitted=null;
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel,closing.Token);
            using var socket=await listener.AcceptAsync(deadline.Token).ConfigureAwait(false);_=RequirePeer(socket,uid);
            deadline.CancelAfter(ExchangeTimeout);var token=deadline.Token;
            using var stream=new NetworkStream(socket,ownsSocket:false);
            var request=await Read<Request>(stream,token).ConfigureAwait(false);
            if(request.Version!=1||request.SensorId!=sensor||request.Server!=server||!Guid.TryParseExact(request.RequestId,"N",out _))throw new InvalidDataException("Policy relay request context mismatch");
            var nonce=owner.Request();await Write(stream,new Challenge(1,sensor,server,request.RequestId,nonce),token).ConfigureAwait(false);
            var reply=await Read<Reply>(stream,token).ConfigureAwait(false);
            if(reply.Version!=1||reply.RequestId!=request.RequestId||reply.Envelope==null)throw new InvalidDataException("Policy relay response context mismatch");
            token.ThrowIfCancellationRequested();admitted=admit(reply.Envelope);
            if(!owner.IsActiveLease(admitted))throw new InvalidDataException("Relay admission returned a foreign or revoked lease");
            token.ThrowIfCancellationRequested();await Write(stream,new Accepted(1,request.RequestId,nonce,reply.Envelope.KeyId),token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            // Startup may proceed only after this exchange can no longer
            // invalidate its lease because the acceptance write failed.
            confirmed?.Invoke(admitted);
            return admitted;
        }
        catch{admitted?.Invalidate();throw;}
        finally{single.Release();}
    }
    internal static async Task RelayAsync(string rootDirectory,uint group,string sensor,string server,Func<string,CancellationToken,Task<SignedNativePolicy>> relay,CancellationToken cancel)
    {
        Context(sensor,server);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);deadline.CancelAfter(ExchangeTimeout);var token=deadline.Token;
        using var directory=LinuxProtectedDirectory.OpenRoot(rootDirectory,group);directory.RequireSocket(Name);
        using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(directory.SocketPath(Name)),token);_=RequirePeer(socket,0);
        using var stream=new NetworkStream(socket,ownsSocket:false);var id=Guid.NewGuid().ToString("N");
        await Write(stream,new Request(1,sensor,server,id),token);var challenge=await Read<Challenge>(stream,token);
        if(challenge.Version!=1||challenge.SensorId!=sensor||challenge.Server!=server||challenge.RequestId!=id||
            challenge.Nonce?.Length!=64||!challenge.Nonce.All(Uri.IsHexDigit))throw new InvalidDataException("Policy relay challenge context mismatch");
        // The callback uses the ordinary sensor's existing authenticated HTTPS
        // client. No credential or private signing key is passed to root.
        var envelope=await relay(challenge.Nonce,token);token.ThrowIfCancellationRequested();
        await Write(stream,new Reply(1,id,envelope),token);var accepted=await Read<Accepted>(stream,token);
        if(accepted!=new Accepted(1,id,challenge.Nonce,envelope.KeyId))throw new InvalidDataException("Policy relay acceptance context mismatch");
    }
    public ValueTask DisposeAsync()
    {
        lock(shutdownGate)return new ValueTask(shutdown??=StopAndDrain());
    }
    private async Task StopAndDrain()
    {
        Interlocked.Exchange(ref disposed,1);
        // .NET attempts pathname deletion but suppresses cleanup errors. Verify
        // through the held parent and reconcile only our exact original inode.
        // A changed/unsafe node or failed removal is an explicit shutdown error.
        Exception? closeFailure=null;
        try{closing.Cancel();}catch(Exception e){closeFailure=e;}
        try{listener.Dispose();}catch(Exception e){closeFailure??=e;}
        await single.WaitAsync().ConfigureAwait(false);
        try
        {
            if(closeFailure!=null)throw new IOException("Policy listener close failed",closeFailure);
            directory.RetireOwnedSocket(Name,node);
        }
        finally{directory.Dispose();single.Release();}
    }
    public void Dispose()=>DisposeAsync().AsTask().GetAwaiter().GetResult();
}
