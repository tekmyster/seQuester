namespace RansomFree.Contracts;

public sealed record EnrollmentRequest(string Code,string MachineName,string AgentVersion);
public sealed record EnrollmentResponse(string EndpointId,string Credential);
public sealed record EnrollmentCodeResponse(string Code,DateTimeOffset ExpiresUtc);
public sealed record EndpointProtectionReport(int DeployedCanaryAndHoneypotFiles,string MonitoringState)
{
    public static readonly string[] MonitoringStates=["active","degraded","stopped","not-configured"];
    public bool IsValid()=>DeployedCanaryAndHoneypotFiles is >=0 and <=100000&&MonitoringStates.Contains(MonitoringState,StringComparer.Ordinal);
}
public sealed record HeartbeatRequest(string AgentVersion,string Health)
{
    public string? OperatingSystem {get;init;}
    public EndpointProtectionReport? Protection {get;init;}
}
public sealed record EndpointSummary(string EndpointId,string MachineName,string AgentVersion,string Health,DateTimeOffset LastSeenUtc,bool Revoked)
{
    public string? OperatingSystem {get;init;}
    public EndpointProtectionReport? Protection {get;init;}
}
public sealed record AgentEvent(string EventId,DateTimeOffset ObservedUtc,string Operation,string Path,string? User,string? Process,int? ProcessId,string Source)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ServiceHitContext? ServiceContext {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public EventAttribution? Attribution {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public EventTrust? Trust {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ForensicEvidence? Forensics {get;init;}
}
public sealed record EventBatch(AgentEvent[] Events);
public sealed record ServiceHitContext(string ServiceId,long Revision,string Name,string Description,string SourceAddress,string Method){public string Location {get;init;}="";public string Note {get;init;}="";}
public sealed record BatchReceipt(int Accepted,int Duplicates){[System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)] public int LinuxPermissionPairVersion {get;init;} [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)] public int LinuxNativeHashTrustVersion {get;init;} public int AttributionVersion {get;init;} public int TrustVersion {get;init;} public int WhitelistVersion {get;init;} public int LinuxKernelTrustVersion {get;init;} public int ForensicsVersion {get;init;} public int WindowsKernelVersion {get;init;} public int WindowsSyscallVersion {get;init;} public int WindowsShareVersion {get;init;} public int ActorAcquisitionVersion {get;init;} public int WindowsAcquisitionObservationVersion {get;init;} public int WindowsAcquisitionRecoveryVersion {get;init;} public int ProcessCreationVersion {get;init;} public int LinuxKernelVersion {get;init;} public int LinuxKernelTargetIdentityVersion {get;init;} public int LinuxPermissionObservationVersion {get;init;} [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)] public int LinuxIoObservationVersion {get;init;} public int LinuxActorAcquisitionVersion {get;init;} public int LinuxNativeWorkVersion {get;init;}}
public sealed record StoredEvent(long Sequence,string EndpointId,DateTimeOffset ReceivedUtc,AgentEvent Event);
