using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Volatile lifetime of an actually admitted signed snapshot. Persisted journal
// history cannot recreate it. A backwards wall clock cannot extend its TTL.
internal sealed class LinuxNativePolicyLease
{
    private readonly byte[] snapshot;
    private readonly Func<DateTimeOffset> utc;
    private readonly Func<long> ticks;
    private readonly long frequency,started;
    private readonly DateTimeOffset issued,expires;
    private readonly decimal lifetimeTicks;
    private int invalid;
    internal LinuxNativePolicyLease(NativePolicySnapshot value,DateTimeOffset acceptedUtc,long acceptedTicks,long frequency,
        Func<DateTimeOffset> utc,Func<long> ticks)
    {
        if(frequency<=0||value.ExpiresUtc<=acceptedUtc)throw new InvalidDataException("Current monotonic policy lifetime required");
        snapshot=JsonSerializer.SerializeToUtf8Bytes(value);issued=value.IssuedUtc;expires=value.ExpiresUtc;
        this.utc=utc;this.ticks=ticks;this.frequency=frequency;started=acceptedTicks;
        lifetimeTicks=(decimal)Math.Min((expires-acceptedUtc).Ticks,(expires-issued).Ticks)*frequency/TimeSpan.TicksPerSecond;
    }
    internal bool IsCurrent
    {
        get
        {
            if(Volatile.Read(ref invalid)!=0)return false;
            var now=ticks();var wall=utc();
            if(now<started||(decimal)now-started>=lifetimeTicks||wall<issued.AddSeconds(-30)||wall>=expires)
            {Invalidate();return false;}
            return Volatile.Read(ref invalid)==0;
        }
    }
    internal NativePolicySnapshot Current()
    {
        if(!IsCurrent)throw new InvalidDataException("Native policy lease unavailable or expired");
        var value=JsonSerializer.Deserialize<NativePolicySnapshot>(snapshot)!;
        if(!IsCurrent)throw new InvalidDataException("Native policy expired while read");return value;
    }
    internal void Invalidate()=>Interlocked.Exchange(ref invalid,1);
}
