using RansomFree.Contracts;

namespace RansomFree.LinuxAgent;

internal enum BaitVerification {Healthy,Changed,Missing,Unknown}
internal sealed record DeploymentProtectionEvidence(int DeployedItems,bool Complete,bool IntegrityHealthy,DateTimeOffset VerifiedUtc);

// Builds the optional structured heartbeat only from evidence the running Linux
// agent already owns. A missing input stays unreported instead of becoming a
// fabricated zero-item or healthy protection state.
internal static class LinuxProtectionStatus
{
    public static DeploymentProtectionEvidence Summarize(IEnumerable<BaitVerification> items,DateTimeOffset verifiedUtc)
    {
        var values=items.ToArray();
        return new(values.Count(x=>x is BaitVerification.Healthy or BaitVerification.Changed),!values.Contains(BaitVerification.Unknown),values.All(x=>x==BaitVerification.Healthy),verifiedUtc);
    }

    public static EndpointProtectionReport? Build(int? deployedItems,int? configuredItems,bool? inventoryHealthy,bool? monitorRunning,string? agentHealth,string? auditStatus)
    {
        if(deployedItems is null||configuredItems is null||inventoryHealthy is null||monitorRunning is null||string.IsNullOrWhiteSpace(agentHealth)||string.IsNullOrWhiteSpace(auditStatus))return null;
        if(deployedItems is <0 or >1000||configuredItems is <0 or >1000||deployedItems>configuredItems)throw new ArgumentOutOfRangeException(nameof(deployedItems));
        var state=configuredItems==0?"not-configured"
            :!monitorRunning.Value?"stopped"
            :!inventoryHealthy.Value||agentHealth!="Canary monitoring configured"||!EndpointHealthSummary.AuditReady(auditStatus)?"degraded"
            :"active";
        return new(deployedItems.Value,state);
    }
}
