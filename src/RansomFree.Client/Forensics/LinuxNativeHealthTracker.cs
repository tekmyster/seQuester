using System.Diagnostics;

namespace RansomFree.Client.Forensics;

// Volatile client ordering only. Never reload observations from a health file
// and never use this readiness cache to authorize an event exception.
internal sealed class LinuxNativeHealthTracker
{
    private readonly object gate=new();
    private LinuxNativeHealthSocket.Observation? floor,current;
    internal bool Accept(LinuxNativeHealthSocket.Observation value,long now)
    {
        lock(gate)
        {
            if(!value.IsFresh(now)){current=null;return false;}
            if(floor is {} prior)
            {
                var a=value.Reply;var b=prior.Reply;
                var same=a.BootId==b.BootId&&a.Pid==b.Pid&&a.StartTicks==b.StartTicks&&a.InstanceId==b.InstanceId;
                if(value.ReceivedMonotonic<=prior.ReceivedMonotonic||same&&(a.Sequence<=b.Sequence||a.RecordedMonotonic<=b.RecordedMonotonic))
                {current=null;return false;}
            }
            floor=current=value;return true;
        }
    }
    internal bool ReadyAtRecentSample
    {get{lock(gate)return current is {ActiveAtSample:true} active&&active.IsFresh(Stopwatch.GetTimestamp())&&active.Reply.Source?.PolicyExpiresUtc>DateTimeOffset.UtcNow;}}
    internal LinuxNativeHealthSocket.Observation? Current {get{lock(gate)return current;}}
    internal void Invalidate(){lock(gate)current=null;}
}
