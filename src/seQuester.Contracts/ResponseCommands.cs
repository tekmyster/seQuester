namespace RansomFree.Contracts;

public sealed record ResponseCommand(string Id,string EventId,string Action,string RequestedBy,string Reason,DateTimeOffset CreatedUtc,DateTimeOffset ExpiresUtc)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ActiveResponseTarget? Target {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PolicyDigest {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public long? PolicyRevision {get;init;}
}
public sealed record ResponseReceipt(string Id,string Outcome,string Message);
public sealed record ResponseCommandStatus(string EndpointId,ResponseCommand Command,string Status,string? Result,DateTimeOffset? ReportedUtc);
public sealed record NativeResponseCapabilities(int Version,string OperatingSystem,int ProcessTerminationVersion)
{
    public bool IsValid()=>Version==1&&OperatingSystem is "windows" or "linux"&&ProcessTerminationVersion is 0 or 1&&(OperatingSystem=="windows"||ProcessTerminationVersion==0);
}

public static class ResponseCommandPolicy
{
    public static string Digest(AssignedPolicy policy)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(policy)));
    public static bool Permits(ResponseCommand command,AssignedPolicy? policy,string? sensor,bool automatic=false)
    {
        if(command.Target is not {} target||!target.IsValid()||target.SensorId!=sensor||command.EventId!=target.EventId||
            policy?.GroupId==null||!policy.Settings.IsValid()||command.PolicyRevision!=policy.Revision||
            !EvidenceTransferLimits.Hash(command.PolicyDigest)||!string.Equals(command.PolicyDigest,Digest(policy),StringComparison.OrdinalIgnoreCase))return false;
        var response=policy.Settings.ActiveResponse;
        return response?.IsValid()==true&&response.Mode==(automatic?"automatic":"manual")&&response.Actions.Contains(command.Action)&&target.AccountPrincipal==response.AccountPrincipal;
    }
}
