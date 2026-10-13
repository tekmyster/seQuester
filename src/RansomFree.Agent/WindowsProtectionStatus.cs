using RansomFree.Contracts;

namespace RansomFree;

internal static class WindowsProtectionStatus
{
    public static EndpointProtectionReport? Build((int DeployedItems,bool IntegrityHealthy)? evidence,int configuredItems,bool auditConnected,bool watchersHealthy,string health)
    {
        if(evidence is null||configuredItems is <0 or >1000||evidence.Value.DeployedItems<0||evidence.Value.DeployedItems>configuredItems)return null;
        var state=configuredItems==0?"not-configured"
            :!auditConnected?"stopped"
            :!watchersHealthy||!evidence.Value.IntegrityHealthy||health!="Monitoring"?"degraded"
            :"active";
        return new(evidence.Value.DeployedItems,state);
    }
}
