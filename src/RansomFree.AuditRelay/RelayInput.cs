using System.Runtime.InteropServices;
using System.Diagnostics;

namespace RansomFree.AuditRelay;

// auditd keeps stdin open between records. A console ReadAsync cancellation
// does not reliably interrupt that pipe on Linux. Bound the wait instead;
// only this relay's read descriptor is made nonblocking.
internal static class RelayInput
{
    private const int GetFlags=3, SetFlags=4, NonBlocking=0x800;
    private const short Input=1, Error=8, Hangup=16, Invalid=32;
    private const int Interrupted=4, Again=11;

    internal static void Drain(CancellationToken stop, Action<byte[]> admit)
    {
        var flags=fcntl(0,GetFlags,0);
        if(flags<0||fcntl(0,SetFlags,flags|NonBlocking)<0)throw Failure("fcntl");
        var descriptor=new PollDescriptor{Fd=0,Events=Input};
        var draining=false;long drainStarted=0,lastData=0;int drainBytes=0;
        while(true)
        {
            var now=Stopwatch.GetTimestamp();
            if(stop.IsCancellationRequested&&!draining){draining=true;drainStarted=lastData=now;}
            if(draining&&(drainBytes>=1024*1024||Stopwatch.GetElapsedTime(drainStarted,now)>=TimeSpan.FromSeconds(1)
                ||Stopwatch.GetElapsedTime(lastData,now)>=TimeSpan.FromMilliseconds(200)))return;
            descriptor.Returned=0;
            var ready=poll(ref descriptor,1,draining?20:100);
            if(ready<0)
            {
                if(Marshal.GetLastPInvokeError()==Interrupted)continue;
                throw Failure("poll");
            }
            if(ready==0)continue;
            if((descriptor.Returned&Invalid)!=0)throw new IOException("Audit input descriptor invalid.");
            if((descriptor.Returned&(Input|Hangup))!=0)
            {
                var bytes=new byte[8192];
                var count=read(0,bytes,(nuint)bytes.Length);
                if(count==0)return;
                if(count<0)
                {
                    var error=Marshal.GetLastPInvokeError();
                    if(error==Interrupted||error==Again)continue;
                    throw Failure("read");
                }
                if(count>bytes.Length)throw new IOException("Audit input read exceeded buffer.");
                if(count!=bytes.Length)Array.Resize(ref bytes,(int)count);
                // Once consumed, bytes must be admitted even if cancellation
                // arrived concurrently. The caller retains them before exit.
                admit(bytes);
                lastData=Stopwatch.GetTimestamp();if(draining)drainBytes=checked(drainBytes+(int)count);
            }
            else if((descriptor.Returned&Error)!=0)throw new IOException("Audit input pipe reported POLLERR.");
        }
    }

    private static IOException Failure(string operation)=>new("Audit input "+operation+" failed; errno "+Marshal.GetLastPInvokeError());
    [StructLayout(LayoutKind.Sequential)]
    private struct PollDescriptor { internal int Fd; internal short Events; internal short Returned; }
    [DllImport("libc",SetLastError=true)] private static extern int fcntl(int fd,int command,int value);
    [DllImport("libc",SetLastError=true)] private static extern int poll(ref PollDescriptor descriptor,nuint count,int timeout);
    [DllImport("libc",SetLastError=true)] private static extern nint read(int fd,[Out] byte[] bytes,nuint count);
}
