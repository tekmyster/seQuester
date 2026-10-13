using System.Runtime.InteropServices;

namespace RansomFree.AuditRelay;

internal sealed class RelaySignals:IDisposable
{
    // The native runtime finalizes a registration by removing its handler.
    // Give the long-lived relay registrations an explicit static owner until
    // its shutdown has joined stdin and completed durable storage cleanup.
    private static RelaySignals? active;
    private readonly PosixSignalRegistration term;
    private readonly PosixSignalRegistration hup;
    private bool disposed;

    private RelaySignals(CancellationTokenSource stop)
    {
        term=PosixSignalRegistration.Create(PosixSignal.SIGTERM,c=>{c.Cancel=true;stop.Cancel();});
        try{hup=PosixSignalRegistration.Create(PosixSignal.SIGHUP,c=>c.Cancel=true);}
        catch{term.Dispose();throw;}
    }

    internal static RelaySignals Register(CancellationTokenSource stop)
    {
        if(active!=null)throw new InvalidOperationException("Relay signals already owned.");
        // .NET deliberately respects inherited SIG_IGN and reports successful
        // registration without installing an OS handler in that case. These
        // are the two signals this executable explicitly owns. Reset only
        // their dispositions before the first managed registration; the parent
        // daemon and every other signal disposition are untouched.
        if(signal(15,0)==-1||signal(1,0)==-1)
            throw new IOException("Relay owned signal disposition reset failed; errno "+Marshal.GetLastPInvokeError());
        var owner=new RelaySignals(stop);active=owner;
        try{UnblockRegisteredSignals();return owner;}
        catch{owner.Dispose();throw;}
    }

    public void Dispose()
    {
        if(disposed)return;disposed=true;
        hup.Dispose();term.Dispose();
        if(ReferenceEquals(active,this))active=null;
    }
    // auditd 4.0.2 forks reload/restart children from a worker which blocks
    // TERM/HUP. Registration installs handlers but does not clear that inherited
    // mask. Change only the relay's own calling-thread mask after registration,
    // before starting its workers; never change auditd or host policy.
    private static void UnblockRegisteredSignals()
    {
        if(sigemptyset(out var set)!=0||sigaddset(ref set,15)!=0||sigaddset(ref set,1)!=0)
            throw new IOException("Relay signal set failed; errno "+Marshal.GetLastPInvokeError());
        var error=pthread_sigmask(1,ref set,0); // Linux SIG_UNBLOCK
        if(error!=0)throw new IOException("Relay signal unblock failed; errno "+error);
    }

    // Linux glibc sigset_t is 128 bytes on the supported x64/arm64 targets.
    [StructLayout(LayoutKind.Sequential,Size=128)] private struct SignalSet { }
    [DllImport("libc",SetLastError=true)] private static extern int sigemptyset(out SignalSet set);
    [DllImport("libc",SetLastError=true)] private static extern nint signal(int signal,nint handler);
    [DllImport("libc",SetLastError=true)] private static extern int sigaddset(ref SignalSet set,int signal);
    [DllImport("libc")] private static extern int pthread_sigmask(int how,ref SignalSet set,nint oldSet);
}
