namespace RansomFree.Contracts;

public sealed record AgentConsoleRequest(string Operation,string? EventId=null,string? Password=null);
public sealed record AgentConsoleEvent(string EventId,DateTime Time,string Operation,string Path,string Process,string User,string Source,bool Allowlisted,bool CanEndProcess)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public int? ProcessId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public bool SuppressPopup {get;init;}
}
public sealed record AgentConsoleStatus(string Version,string Health,int CanaryCount,bool AuditConnected,long PolicyRevision,int PendingEvents,int PendingSyslog,AgentConsoleEvent[] Events)
{
    public int QueueCapacity {get;init;}
    public long QueuePayloadBytes {get;init;}
    public long QueuePayloadLimitBytes {get;init;}
}
public sealed record AgentConsoleReply(bool Success,string Message,AgentConsoleStatus? Status=null);
