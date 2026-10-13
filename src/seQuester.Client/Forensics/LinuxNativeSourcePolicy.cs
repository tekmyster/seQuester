using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// One source session keeps a fixed monitoring/target assignment. Signed trust
// refreshes may replace its policy while each prepared event retains the exact
// decision it observed. No ordinary-worker cache supplies root authority.
internal sealed class LinuxNativeSourcePolicy
{
    internal sealed record Observation(LinuxNativePolicyLease Lease,NativePolicySnapshot Snapshot);
    private readonly object gate=new();
    private readonly LinuxNativePolicyAdmission owner;
    private readonly string sensor,server;
    private readonly byte[] monitoring;
    private LinuxNativePolicyLease current;
    private string? stopped;
    internal LinuxNativeSourcePolicy(LinuxNativePolicyAdmission owner,LinuxNativePolicyLease first,string sensor,ForensicPolicy forensic)
    {
        if(!owner.IsActiveLease(first))throw new InvalidOperationException("Source requires this policy owner's admitted lease");
        var snapshot=first.Current();
        if(snapshot.SensorId!=sensor||(snapshot.Monitoring.Settings.Forensics??new ForensicPolicy())!=forensic)
            throw new InvalidDataException("Source forensic policy differs from signed assignment");
        this.owner=owner;current=first;this.sensor=sensor;server=snapshot.Server;
        monitoring=JsonSerializer.SerializeToUtf8Bytes(snapshot.Monitoring);
    }
    internal string? UnavailableReason
    {
        get{lock(gate){if(stopped!=null)return stopped;if(!current.IsCurrent)stopped="LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED";return stopped;}}
    }
    internal void RequireSource(string expectedSensor,ForensicPolicy forensic)
    {
        lock(gate)
        {
            var sample=Observe()??throw new InvalidDataException("Current signed source policy required");
            if(expectedSensor!=sensor||(sample.Snapshot.Monitoring.Settings.Forensics??new ForensicPolicy())!=forensic)
                throw new InvalidDataException("Native source identity or forensic policy does not match signed binding");
        }
    }
    internal void RequireInstallation(LinuxNativeInstallation.Configuration configuration,LinuxForensicJournal journal,ForensicPolicy forensic)
    {
        lock(gate){owner.RequireInstallation(configuration,journal);RequireSource(configuration.SensorId,forensic);}
    }
    internal Observation? Observe()
    {
        lock(gate)
        {
            if(UnavailableReason!=null)return null;
            try{return new(current,current.Current());}
            catch(InvalidDataException){stopped="LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED";return null;}
        }
    }
    internal bool StillCurrent(Observation sample)
    {lock(gate)return UnavailableReason==null&&ReferenceEquals(current,sample.Lease)&&sample.Lease.IsCurrent;}
    // A refresh may revoke a rule while enrichment is running. Discard that
    // entire result and retry once against the newly admitted lease, including
    // a new source sample. Never hold the policy gate over evidence I/O or
    // delay replacement admission. Repeated changes retain the alert.
    internal T? EvaluateCurrent<T>(Func<Observation,T?> evaluate) where T:class
    {
        for(var attempt=0;attempt<2;attempt++)
        {
            var sample=Observe();if(sample==null)return null;
            var result=evaluate(sample);
            if(StillCurrent(sample))return result;
        }
        return null;
    }
    // Serialize replacement admission with source observation, so the brief
    // old-lease invalidation/commit/new-lease window is never interpreted as
    // an unrelated expiry. No source/native operation is awaited in this gate.
    internal LinuxNativePolicyLease AcceptReplacement(SignedNativePolicy envelope)
    {
        lock(gate)
        {
            if(UnavailableReason!=null)throw new InvalidOperationException("Stopped policy binding requires a new source session");
            var next=owner.AcceptLease(envelope);
            try
            {
                var snapshot=next.Current();
                if(snapshot.SensorId!=sensor||snapshot.Server!=server||!JsonSerializer.SerializeToUtf8Bytes(snapshot.Monitoring).AsSpan().SequenceEqual(monitoring))
                {stopped="LINUX_NATIVE_MONITORING_ASSIGNMENT_CHANGED";throw new InvalidDataException("Signed monitoring/group assignment changed; stop and revalidate source targets");}
                return current=next;
            }
            catch{next.Invalidate();throw;}
        }
    }
    internal void Invalidate(){lock(gate){stopped??="LINUX_NATIVE_POLICY_SOURCE_STOPPED";current.Invalidate();}}
    internal static TrustRuntimeDecision Evaluate(Observation sample,TrustContext context,DateTimeOffset now)
    {
        var assignment=sample.Snapshot.Trust;
        if(!sample.Lease.IsCurrent||assignment.EndpointId!=context.Host||assignment.GroupId!=context.Group||assignment.Organization!=context.Organization||assignment.IssuedUtc>now.AddMinutes(1)||assignment.ExpiresUtc<=now)
            return new(assignment.Policy.Revision,assignment.Digest,"pending",new(1,"normal",false,true,"normal",[],"Native signed policy unavailable. Alerts retained; automatic response paused."));
        if(assignment.Policy.Mode=="legacy")return new(assignment.Policy.Revision,assignment.Digest,"legacy",new(1,"normal",false,false,"normal",[],"Existing policy controls apply."));
        return new(assignment.Policy.Revision,assignment.Digest,"enforce",TrustEvaluation.Evaluate(assignment.Policy.Rules,context,now,assignment.Policy.ApprovedRules()));
    }
}
