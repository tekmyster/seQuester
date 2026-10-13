using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.Threading.Channels;
using RansomFree.AuditRelay;
using RansomFree.LinuxAgent;

// Native AOT: no JIT or dynamic callback thunk inside auditd's MDWE sandbox.
// No configuration, credentials, process response, parser or network endpoints.
if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException("Linux audit relay only.");
if(RuntimeFeature.IsDynamicCodeSupported)throw new InvalidOperationException("Relay must be published with Native AOT, never deployed as a JIT apphost.");
if(args is ["--version"]){Console.WriteLine("seQuester audit relay 0.9.7 Native AOT; acknowledged durable protocol v2; dynamic code disabled");return;}
if(args is ["--self-test-mdwe"])
{
    // Linux PR_SET_MDWE/REFUSE_EXEC_GAIN. Test-only, stricter child process policy;
    // never changes the host or auditd service. Requires kernel support (Linux 6.3+).
    if(NativeTest.prctl(65,1,0,0,0)!=0)throw new IOException("Kernel MDWE self-test unavailable; errno "+Marshal.GetLastPInvokeError());
    var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
    start.Environment.Clear(); // Match auditd's empty execve environment.
    using var child=Process.Start(start)??throw new IOException("MDWE child did not start.");child.StandardInput.Close();
    if(!child.WaitForExit(15000)||child.ExitCode!=0)throw new IOException("Native AOT startup/I/O under inherited MDWE failed.");
    Console.WriteLine("PASS: Native AOT relay startup, signal registrations, thread/channel/stdin lifecycle under inherited kernel MDWE and empty environment; no auditd/plugin activation.");return;
}
if(args.Length!=0)throw new ArgumentException("The auditd relay accepts no arguments.");
using var stop=new CancellationTokenSource();
using var signals=RelaySignals.Register(stop);
using var spool=new RelaySpool();
var instance=Guid.NewGuid();Exception? inputFailure=null;var nextCapacityLog=DateTimeOffset.MinValue;
var input=Task.Run(()=>
{
    try
    {
        RelayInput.Drain(stop.Token,bytes=>
        {
            if(!spool.Admit(instance,bytes)&&DateTimeOffset.UtcNow>=nextCapacityLog)
            {
                nextCapacityLog=DateTimeOffset.UtcNow.AddSeconds(10);
                Console.Error.WriteLine("Audit relay raw capacity full; dropped-chunk count durably retained, pending raw evidence preserved.");
            }
        });
    }
    catch(OperationCanceledException) when(stop.IsCancellationRequested){}
    catch(Exception ex){inputFailure=ex;Console.Error.WriteLine("Audit relay input/storage failed: "+ex.GetType().Name);stop.Cancel();}
});
async Task Frame(Socket socket,int type,byte[] payload)
{
    var header=new byte[8];BinaryPrimitives.WriteInt32LittleEndian(header,type);BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(4),payload.Length);
    foreach(var block in new[]{header,payload})for(var offset=0;offset<block.Length;)
    {var n=await socket.SendAsync(block.AsMemory(offset),SocketFlags.None,stop.Token);if(n==0)throw new IOException("Collector closed connection.");offset+=n;}
}
async Task<byte[]> Reply(Socket socket,int type,int length)
{
    using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop.Token);deadline.CancelAfter(TimeSpan.FromSeconds(6));
    using var stream=new NetworkStream(socket,false);var reply=new byte[8+length];await stream.ReadExactlyAsync(reply,deadline.Token);
    if(BinaryPrimitives.ReadInt32LittleEndian(reply)!=type||BinaryPrimitives.ReadInt32LittleEndian(reply.AsSpan(4))!=length)throw new InvalidDataException("Audit collector acknowledgement version/length mismatch.");
    return reply[8..];
}
try
{
    while(!stop.IsCancellationRequested)
    {
        spool.RecoverLosses();
        if(input.IsCompleted&&spool.FirstPending()==null&&!spool.HasPendingLosses)break;
        try
        {
            using var socket=new Socket(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            await socket.ConnectAsync(new UnixDomainSocketEndPoint("/run/sequester-audit/ingest.sock"),stop.Token);
            var streamInstance=spool.FirstPending()?.Frame.RelayInstance??instance;
            await Frame(socket,6,streamInstance.ToByteArray());
            if(new Guid(await Reply(socket,6,16))!=streamInstance)throw new InvalidDataException("Audit collector did not acknowledge the announced stream.");
            var pulse=DateTimeOffset.MinValue;
            while(!stop.IsCancellationRequested)
            {
                spool.RecoverLosses();
                if(DateTimeOffset.UtcNow>=pulse)
                {
                    var status=spool.Status;var metadata=new byte[24];BinaryPrimitives.WriteInt64LittleEndian(metadata,status.Frames);BinaryPrimitives.WriteInt64LittleEndian(metadata.AsSpan(8),status.Bytes);BinaryPrimitives.WriteInt64LittleEndian(metadata.AsSpan(16),status.UnreportedLosses);
                    await Frame(socket,8,metadata);pulse=DateTimeOffset.UtcNow.AddSeconds(1);
                }
                var pending=spool.FirstPending();
                if(pending!=null)
                {
                    // Old process frames drain before the new process's stream.
                    // A new connection explicitly announces each stream ID.
                    if(pending.Frame.RelayInstance!=streamInstance)break;
                    await Frame(socket,4,pending.Frame.Encode());var receipt=await Reply(socket,4,24);
                    if(new Guid(receipt.AsSpan(0,16))!=pending.Frame.RelayInstance||BinaryPrimitives.ReadInt64LittleEndian(receipt.AsSpan(16))!=pending.Frame.Sequence)throw new InvalidDataException("Audit acknowledgement does not match pending instance/sequence.");
                    spool.Acknowledge(pending);
                }
                else
                {
                    if(input.IsCompleted&&!spool.HasPendingLosses)return;
                    await Task.Delay(25,stop.Token);
                }
            }
        }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
        catch(OperationCanceledException){await Task.Delay(1000,stop.Token);} // ACK timeout; raw owner retained.
        catch(Exception ex)
        {
            if(DateTimeOffset.UtcNow>=nextCapacityLog){nextCapacityLog=DateTimeOffset.UtcNow.AddSeconds(10);Console.Error.WriteLine("Audit collector delivery pending: "+ex.GetType().Name);}
            await Task.Delay(1000,stop.Token);
        }
    }
}
catch(OperationCanceledException) when(stop.IsCancellationRequested){}
finally
{
    stop.Cancel();await input;spool.RecoverLosses();
    // Undelivered raw frames/loss notes remain protected on disk. Process exit
    // releases only the lease; it never silently clears outstanding evidence.
    if(inputFailure!=null)throw new IOException("Audit relay input/storage unavailable; retained evidence preserved.",inputFailure);
}

internal static class NativeTest
{
    [DllImport("libc",SetLastError=true)] internal static extern int prctl(int option,nuint a,nuint b,nuint c,nuint d);
}
