namespace RansomFree.LinuxAgent;

// Written only by the root collector into the protected audit inbox. This is a
// privilege-separated health report, not an assertion of complete event coverage.
internal sealed record AuditCollectorHealth(int Version,DateTimeOffset CheckedUtc,string? Failure);
internal sealed record AuditHeartbeat(DateTimeOffset UpdatedUtc,bool Running,string BootId,string InstanceId,int Pid,string StartTicks,long Sequence,AuditCollectorHealth? Health);

internal sealed class AuditHeartbeatVerifier
{
    AuditHeartbeat? previous;
    DateTimeOffset advancedUtc;
    bool hasAdvanced;
    const string Ready="Linux Audit: collector and relay verified; user/process attribution enabled (per-event completeness varies)";
    public string Evaluate(AuditHeartbeat current,string bootId,DateTimeOffset now)
    {
        string Unavailable(string reason)=>"Linux Audit degraded: "+reason;
        var age=now-current.UpdatedUtc;
        if(!current.Running||age>TimeSpan.FromSeconds(20)||age<TimeSpan.FromSeconds(-5))return Unavailable("collector stopped or heartbeat stale");
        if(current.BootId!=bootId||!Guid.TryParseExact(current.InstanceId,"N",out _)||current.Pid<=1||!ulong.TryParse(current.StartTicks,out var start)||start==0||current.Sequence<1)
            return Unavailable("collector identity invalid");
        if(current.Health is not {Version:1} health||health.CheckedUtc!=current.UpdatedUtc)
            return Unavailable("root collector health report missing or incompatible");
        if(health.Failure!=null)return Unavailable(health.Failure);
        var same=previous is {} prior&&prior.InstanceId==current.InstanceId&&prior.BootId==current.BootId&&prior.Pid==current.Pid&&prior.StartTicks==current.StartTicks;
        if(same&&current.Sequence<previous!.Sequence)return Unavailable("collector heartbeat regressed");
        if(!same)
        {
            previous=current;advancedUtc=now;hasAdvanced=false;
            return "Linux Audit: root checks passed; awaiting heartbeat advancement";
        }
        if(current.Sequence>previous!.Sequence)
        {
            if(current.UpdatedUtc<=previous.UpdatedUtc)return Unavailable("collector heartbeat time did not advance");
            previous=current;advancedUtc=now;hasAdvanced=true;
            return Ready;
        }
        if(now-advancedUtc>TimeSpan.FromSeconds(20))return Unavailable("collector heartbeat not advancing");
        return hasAdvanced?Ready:"Linux Audit: root checks passed; awaiting next heartbeat";
    }
}
