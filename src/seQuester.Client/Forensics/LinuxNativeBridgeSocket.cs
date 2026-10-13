using System.Net.Sockets;
using System.Runtime.InteropServices;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// The only operation on this channel acknowledges an exact local import.
// It cannot select paths, release native calls, erase source evidence, change
// policy, or claim server delivery. The existing root ledger validates all IDs.
internal sealed class LinuxNativeBridgeSocket:IDisposable,IAsyncDisposable
{
    internal const string Name="delivery.sock";
    internal const int MaximumFrame=4096;
    internal sealed record Request(int Version,string SensorId,string Server,string RequestId,LinuxNativeBridgeImport.Receipt Receipt);
    internal sealed record Accepted(int Version,string RequestId,LinuxNativeBridgeImport.Receipt Receipt,string Meaning);
    private const string Meaning="LOCAL_IMPORT_DUPLICATES_RETIRED";
    [DllImport("libc",EntryPoint="geteuid")]private static extern uint UserId();
    private readonly LinuxProtectedDirectory directory;
    private readonly LinuxProtectedDirectory.Identity node;
    private readonly Socket listener;
    private readonly CancellationTokenSource closing=new();
    private readonly SemaphoreSlim single=new(1,1);
    private readonly object shutdownGate=new();
    private Task? shutdown;
    private readonly uint uid;
    private readonly string sensor,server;
    private int disposed;
    internal LinuxNativeBridgeSocket(string rootDirectory,uint serviceUid,uint serviceGroup,string sensor,string server)
    {
        Context(sensor,server);
        if(!OperatingSystem.IsLinux()||UserId()!=0)throw new UnauthorizedAccessException("Linux root delivery listener required");
        if(serviceUid is 0 or uint.MaxValue||serviceGroup is 0 or uint.MaxValue)throw new ArgumentException("Dedicated ordinary service identity required");
        this.sensor=sensor;this.server=server;uid=serviceUid;directory=LinuxProtectedDirectory.OpenRoot(rootDirectory,serviceGroup);
        listener=new(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        try
        {
            listener.Bind(new UnixDomainSocketEndPoint(directory.SocketPath(Name)));directory.ConfigureSocket(Name);node=directory.RequireSocket(Name);listener.Listen(1);
        }
        catch{listener.Dispose();directory.Dispose();throw;}
    }
    private static void Context(string sensor,string server)
    {if(!Guid.TryParseExact(sensor,"N",out _)||!NativePolicySnapshot.ValidOrigin(server))throw new ArgumentException("Exact enrolled delivery context required");}
    internal async Task<LinuxNativeBridgeImport.Receipt> AcceptAsync(LinuxNativeBridgeExport exporter,LinuxForensicJournal journal,EventSpool spool,CancellationToken cancel,Action<string>? checkpoint=null)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref disposed)!=0,this);
        if(!await single.WaitAsync(0,cancel).ConfigureAwait(false))throw new InvalidOperationException("One delivery acknowledgment at a time");
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel,closing.Token);
            using var socket=await listener.AcceptAsync(deadline.Token).ConfigureAwait(false);_=LinuxNativePolicySocket.RequirePeer(socket,uid);
            deadline.CancelAfter(TimeSpan.FromSeconds(20));var token=deadline.Token;
            using var stream=new NetworkStream(socket,ownsSocket:false);
            var request=await LinuxNativePolicySocket.Read<Request>(stream,token,MaximumFrame).ConfigureAwait(false);
            if(request.Version!=1||request.SensorId!=sensor||request.Server!=server||!Guid.TryParseExact(request.RequestId,"N",out _)||request.Receipt==null||request.Receipt.SensorId!=sensor)
                throw new InvalidDataException("Delivery acknowledgment context mismatch");
            token.ThrowIfCancellationRequested();
            // A cancellation or failed response after this durable procedure
            // requires idempotent retry, never undoing a committed import.
            exporter.AcknowledgeImport(journal,spool,request.Receipt,checkpoint);
            await LinuxNativePolicySocket.Write(stream,new Accepted(1,request.RequestId,request.Receipt,Meaning),token).ConfigureAwait(false);
            return request.Receipt;
        }
        finally{single.Release();}
    }
    internal static async Task ConfirmAsync(string rootDirectory,uint group,string sensor,string server,LinuxNativeBridgeImport.Receipt receipt,CancellationToken cancel)
    {
        Context(sensor,server);
        if(receipt.SensorId!=sensor)throw new InvalidDataException("Import receipt sensor mismatch");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);deadline.CancelAfter(TimeSpan.FromSeconds(20));var token=deadline.Token;
        using var parent=LinuxProtectedDirectory.OpenRoot(rootDirectory,group);parent.RequireSocket(Name);
        using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        await socket.ConnectAsync(new UnixDomainSocketEndPoint(parent.SocketPath(Name)),token);_=LinuxNativePolicySocket.RequirePeer(socket,0);
        using var stream=new NetworkStream(socket,ownsSocket:false);var id=Guid.NewGuid().ToString("N");
        await LinuxNativePolicySocket.Write(stream,new Request(1,sensor,server,id,receipt),token);
        var accepted=await LinuxNativePolicySocket.Read<Accepted>(stream,token,MaximumFrame);
        if(accepted!=new Accepted(1,id,receipt,Meaning))throw new InvalidDataException("Delivery acknowledgment reply mismatch");
    }
    public ValueTask DisposeAsync()
    {
        lock(shutdownGate)return new ValueTask(shutdown??=StopAndDrain());
    }
    private async Task StopAndDrain()
    {
        Interlocked.Exchange(ref disposed,1);
        Exception? closeFailure=null;
        try{closing.Cancel();}catch(Exception e){closeFailure=e;}
        try{listener.Dispose();}catch(Exception e){closeFailure??=e;}
        // Never release the held parent or allow dependent owner disposal while
        // an accepted acknowledgment is still using the journal/export/spool.
        await single.WaitAsync().ConfigureAwait(false);
        try
        {
            if(closeFailure!=null)throw new IOException("Delivery listener close failed",closeFailure);
            directory.RetireOwnedSocket(Name,node);
        }
        finally{directory.Dispose();single.Release();}
    }
    public void Dispose()=>DisposeAsync().AsTask().GetAwaiter().GetResult();
}
