using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Channels;

namespace RansomFree.LinuxAgent;

internal sealed record AuditInput(byte[] Bytes,bool Gap=false,long Dropped=0,long ReplayOrder=0);
internal sealed record AuditPeer(int Pid,string StartTicks);
internal sealed record AuditTransportFailure(DateTimeOffset TimeUtc,string Stage,string Category,int? NativeError,int HResult,int PeerPid);
internal sealed record AuditRelayQueueStatus(DateTimeOffset ReceivedUtc,AuditPeer Peer,Guid StreamInstance,long PendingFrames,long PendingBytes,long UnreportedLostChunks);
// One producer can have at most one complete frame awaiting queue space, or
// one partial payload followed by its explicit gap boundary. Keep this bounded
// tail outside the channel so cancellation never discards received evidence.
internal sealed class AuditInputDelivery
{
    readonly List<AuditInput> shutdownTail=new(2);
    public async ValueTask Publish(ChannelWriter<AuditInput> output,AuditInput item,CancellationToken ct)
    {
        if(output.TryWrite(item))return;
        try{await output.WriteAsync(item,ct);}
        catch(OperationCanceledException) when(ct.IsCancellationRequested){Retain(item);throw;}
    }
    public void Retain(AuditInput item)
    {
        if(shutdownTail.Count>=2)throw new InvalidOperationException("Audit shutdown tail exceeds its frame bound.");
        shutdownTail.Add(item);
    }
    // Call only after the producer has completed, preserving channel-before-tail order.
    public AuditInput[] TakeShutdownTail(){var items=shutdownTail.ToArray();shutdownTail.Clear();return items;}
}
internal sealed class AuditTransport:IDisposable
{
    const string DirectoryPath="/run/sequester-audit",SocketPath=DirectoryPath+"/ingest.sock";
    [StructLayout(LayoutKind.Sequential)] struct UCred{public int Pid;public uint Uid,Gid;}
    [DllImport("libc",SetLastError=true)] static extern int getsockopt(int socket,int level,int option,out UCred peer,ref uint size);
    readonly Socket listener;
    readonly AuditInputDelivery delivery=new();
    readonly AuditReplayJournal replay;
    readonly Dictionary<AuditPeer,long> legacyLosses=[];
    long publishedOrder;
    AuditPeer? peer;
    long lastFrameTicks;
    long failures;
    AuditTransportFailure? lastFailure;
    AuditRelayQueueStatus? queueStatus;
    DateTimeOffset nextFailureLog;
    public AuditPeer? Peer=>Volatile.Read(ref peer);
    public long FailureCount=>Interlocked.Read(ref failures);
    public AuditTransportFailure? LastFailure=>Volatile.Read(ref lastFailure);
    public AuditRelayQueueStatus? LastRelayQueueStatus=>Volatile.Read(ref queueStatus);
    public AuditInput[] TakeShutdownTail()=>delivery.TakeShutdownTail();
    public long ReplayLossTotal=>replay.TotalLoss;
    public int ReplayPendingCount=>replay.PendingCount;
    public long ReplayPendingBytes=>replay.PendingBytes;
    public void RetireReplayThrough(long order)=>replay.RetireThrough(order);
    public static void FlushOutputDirectory()=>FlushDirectory(AuditDispatcher.Root);
    [DllImport("libc",SetLastError=true)] static extern int open(string path,int flags);
    [DllImport("libc",SetLastError=true)] static extern int fsync(int descriptor);
    [DllImport("libc")] static extern int close(int descriptor);
    static void FlushDirectory(string path)
    {
        Native.ValidateAdminPath(path,true);var fd=open(path,0x10000|0x20000|0x80000);
        if(fd<0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        try{if(fsync(fd)!=0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());}finally{close(fd);}
    }
    public DateTimeOffset? LastFrameUtc=>Interlocked.Read(ref lastFrameTicks) is >0 and var ticks?new DateTimeOffset(ticks,TimeSpan.Zero):null;
    public AuditTransport()
    {
        Native.ValidateAdminPath(DirectoryPath,true,true);
        if(Path.Exists(SocketPath))throw new IOException("Existing audit socket preserved; stop the owning service before recovery.");
        replay=new(Path.Combine(AuditDispatcher.Root,"relay-replay-v2"),(p,d)=>Native.ValidateAdminPath(p,d));
        listener=new(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
        try{listener.Bind(new UnixDomainSocketEndPoint(SocketPath));File.SetUnixFileMode(SocketPath,UnixFileMode.UserRead|UnixFileMode.UserWrite);listener.Listen(1);}
        catch{listener.Dispose();replay.Dispose();throw;}
    }
    async Task PublishRetained(ChannelWriter<AuditInput> output,CancellationToken ct)
    {
        foreach(var entry in replay.Pending().Where(x=>x.Order>publishedOrder))
            await PublishEntry(output,entry,ct);
    }
    async Task PublishEntry(ChannelWriter<AuditInput> output,AuditReplayEntry entry,CancellationToken ct)
    {
        // A new relay process is an explicit stream boundary. Reconnecting
        // the same instance is not: its pending bytes must reassemble.
        await delivery.Publish(output,new(entry.Frame.Bytes,entry.LossDelta>0||entry.Frame.Sequence==1&&entry.Order>1,0,entry.Order),ct);
        publishedOrder=entry.Order;
    }
    public async Task Read(ChannelWriter<AuditInput> output,CancellationToken ct)
    {
        var connectedBefore=false;
        try
        {
            await PublishRetained(output,ct);
            while(!ct.IsCancellationRequested)
            {
                using var socket=await listener.AcceptAsync(ct);
                var stage="PeerCredentials";var peerPid=0;var received=0;var payloadReceived=0;var frameType=0;var mode=0;Guid? announcedInstance=null;byte[]? payload=null;
                try
                {
                    uint size=12;if(getsockopt(socket.Handle.ToInt32(),1,17,out var credentials,ref size)!=0)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
                    peerPid=credentials.Pid;
                    if(size!=12||credentials.Uid!=0||credentials.Pid<=1)throw new UnauthorizedAccessException("Audit relay peer must be root.");
                    stage="PeerExecutableRead";
                    var executable=Native.Link($"/proc/{credentials.Pid}/exe");
                    if(executable==null)throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
                    stage="PeerExecutableName";
                    if(Path.GetFileName(executable)!="RansomFree.AuditRelay")throw new UnauthorizedAccessException("Unexpected audit peer executable.");
                    stage="PeerExecutableOwnership";
                    Native.ValidateAdminPath(executable,false);
                    stage="PeerStartIdentity";
                    var identity=new AuditPeer(credentials.Pid,AuditHealth.StartTicks(credentials.Pid));
                    stage="ConnectionBoundary";
                    // A fresh collector/parser has no partial input to discard
                    // on its first connection. Reconnects still break continuity.
                    Volatile.Write(ref peer,identity);
                    using var stream=new NetworkStream(socket,false);
                    while(!ct.IsCancellationRequested)
                    {
                        stage="FrameHeaderRead";
                        received=0;payloadReceived=0;frameType=0;payload=null;
                        var header=new byte[8];await ReadFramePart(stream,header,n=>received+=n,ct);
                        stage="FrameHeaderValidation";
                        var type=BinaryPrimitives.ReadInt32LittleEndian(header);var length=BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(4));
                        if(type is <1 or >8||type==5||length<0||length>(type==4?8224:8192)||type==2&&length!=8||type is 3 or 7&&length!=0||type==1&&length==0||type==4&&length<32||type==6&&length!=16||type==8&&length!=24)throw new InvalidDataException("Invalid audit relay frame.");
                        var observedMode=type is 4 or 6 or 7 or 8?2:1;
                        if(mode!=0&&observedMode!=mode)throw new InvalidDataException("Audit relay changed protocol within a connection.");
                        if(mode==0)
                        {
                            mode=observedMode;
                            if(mode==1&&replay.PendingCount>0)throw new InvalidDataException("Legacy relay cannot bypass pending acknowledged input.");
                            if(mode==1&&connectedBefore)await delivery.Publish(output,new([],true),ct);
                            connectedBefore=true;
                        }
                        frameType=type;
                        stage="FramePayloadRead";
                        var bytes=new byte[length];payload=bytes;
                        await ReadFramePart(stream,bytes,n=>{received+=n;payloadReceived+=n;},ct);
                        stage="FrameDispatch";
                        Interlocked.Exchange(ref lastFrameTicks,DateTimeOffset.UtcNow.Ticks);
                        if(type==8)
                        {
                            if(announcedInstance==null)throw new InvalidDataException("Unannounced audit relay queue status.");
                            var pending=BinaryPrimitives.ReadInt64LittleEndian(bytes);var pendingBytes=BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(8));var unreported=BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(16));
                            if(pending is <0 or >4096||pendingBytes is <0 or >64L*1024*1024||unreported<0)throw new InvalidDataException("Invalid relay queue telemetry.");
                            Volatile.Write(ref queueStatus,new(DateTimeOffset.UtcNow,identity,announcedInstance.Value,pending,pendingBytes,unreported));
                        }
                        else if(type==7)
                        {
                            if(announcedInstance==null)throw new InvalidDataException("Unannounced audit relay heartbeat.");
                        }
                        else if(type==6)
                        {
                            var instance=new Guid(bytes);
                            if(instance==Guid.Empty||announcedInstance!=null)throw new InvalidDataException("Invalid repeated audit protocol announcement.");
                            announcedInstance=instance;
                            var hello=new byte[24];BinaryPrimitives.WriteInt32LittleEndian(hello,6);BinaryPrimitives.WriteInt32LittleEndian(hello.AsSpan(4),16);bytes.CopyTo(hello,8);await stream.WriteAsync(hello,ct);
                        }
                        else if(type==4)
                        {
                            stage="ReplayDurableAdmission";var frame=AuditReplayFrame.Decode(bytes);
                            if(announcedInstance!=frame.RelayInstance)throw new InvalidDataException("Unannounced audit relay instance.");
                            var admitted=replay.Admit(frame);
                            stage="ReplayParserAdmission";if(admitted.Entry!=null)await PublishEntry(output,admitted.Entry,ct);
                            // ACK after file + directory durability, not merely
                            // a successful socket read. Sender retains until ACK.
                            stage="ReplayAcknowledgement";var ack=new byte[32];BinaryPrimitives.WriteInt32LittleEndian(ack,4);BinaryPrimitives.WriteInt32LittleEndian(ack.AsSpan(4),24);frame.RelayInstance.TryWriteBytes(ack.AsSpan(8));BinaryPrimitives.WriteInt64LittleEndian(ack.AsSpan(24),frame.Sequence);
                            await stream.WriteAsync(ack,ct);
                        }
                        else if(type==1)await delivery.Publish(output,new(bytes),ct);
                        else if(type==2)
                        {
                            var priorDrops=legacyLosses.GetValueOrDefault(identity);
                            if(!legacyLosses.ContainsKey(identity)&&legacyLosses.Count>=256)throw new IOException("Legacy relay instance inventory full.");
                            var drops=BinaryPrimitives.ReadInt64LittleEndian(bytes);var delta=AuditLossCounter.Delta(drops,priorDrops);
                            // Relay announces zero on every initial connection.
                            // A repeated/zero count is telemetry, not lost input.
                            if(delta>0)await delivery.Publish(output,new([],true,delta),ct);
                            legacyLosses[identity]=drops;
                        }
                    }
                }
                catch(OperationCanceledException ex) when(ct.IsCancellationRequested)
                {
                    if(mode==1&&received>0&&(stage is "FrameHeaderRead" or "FramePayloadRead"))
                    {
                        // Only authenticated, validated type-1 payload bytes may
                        // reach the parser. A torn header is diagnostic evidence.
                        if(frameType==1&&payloadReceived>0&&payload!=null)delivery.Retain(new(payload[..payloadReceived]));
                        delivery.Retain(new([],true,1));
                        RecordFailure(ex,stage,peerPid);
                    }
                    break;
                }
                catch(Exception ex)
                {
                    // Fixed stage names and exception category/numeric codes only.
                    // Never journal audit payloads, paths, command lines or exception messages.
                    RecordFailure(ex,stage,peerPid);
                    if(replay.IsFaulted)throw;
                    // V2 sender still owns any unacknowledged bytes. A socket
                    // interruption is not fabricated evidence of input loss.
                    if(mode==1)await delivery.Publish(output,new([],true),ct);
                }
                finally{Volatile.Write(ref peer,null);Interlocked.Exchange(ref lastFrameTicks,0);}
            }
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
        finally{Volatile.Write(ref peer,null);output.TryComplete();}
    }
    static async ValueTask ReadFramePart(Stream stream,Memory<byte> bytes,Action<int> observed,CancellationToken ct)
    {
        var offset=0;
        while(offset<bytes.Length)
        {
            var count=await stream.ReadAsync(bytes[offset..],ct);
            if(count==0)throw new EndOfStreamException();
            observed(count);offset+=count;
        }
    }
    void RecordFailure(Exception ex,string stage,int peerPid)
    {
        var failure=new AuditTransportFailure(DateTimeOffset.UtcNow,stage,ex.GetType().Name,ex is System.ComponentModel.Win32Exception native?native.NativeErrorCode:null,ex.HResult,peerPid);
        Volatile.Write(ref lastFailure,failure);Interlocked.Increment(ref failures);
        if(DateTimeOffset.UtcNow<nextFailureLog)return;
        nextFailureLog=DateTimeOffset.UtcNow.AddSeconds(10);
        Console.Error.WriteLine($"Audit relay rejected: stage={failure.Stage}; category={failure.Category}; errno={failure.NativeError}; hresult={failure.HResult}; peerPid={peerPid}; failures={FailureCount}");
    }
    public void Dispose(){listener.Dispose();File.Delete(SocketPath);replay.Dispose();}
}
