using System.Runtime.InteropServices;

// Private test lifetime only. No power policy, registry value or boot setting is
// changed. Windows requires the request and its release on the owning thread.
internal sealed class QualificationPowerLease : IDisposable
{
    private const uint Continuous = 0x80000000, SystemRequired = 0x00000001;
    private readonly ManualResetEventSlim stop = new(), ready = new();
    private readonly Thread owner;
    private bool held;

    public QualificationPowerLease()
    {
        owner = new Thread(() =>
        {
            held = SetThreadExecutionState(Continuous | SystemRequired) != 0;
            ready.Set();
            if (!held) return;
            try { stop.Wait(); }
            finally { SetThreadExecutionState(Continuous); }
        }) { IsBackground = true, Name = "private-qualification-power-request" };
        owner.Start();
        ready.Wait();
        if (!held)
        {
            owner.Join(); ready.Dispose(); stop.Dispose();
            throw new InvalidOperationException("Windows rejected the private qualification system-required power request");
        }
    }

    public void Dispose()
    {
        stop.Set(); owner.Join(); ready.Dispose(); stop.Dispose();
    }

    [DllImport("kernel32.dll")]
    private static extern uint SetThreadExecutionState(uint flags);
}
