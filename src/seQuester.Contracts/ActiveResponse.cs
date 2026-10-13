namespace RansomFree.Contracts;

public sealed record ActiveResponsePolicy
{
    public int Version {get;init;}=1;
    public string Mode {get;init;}="observe";
    public string[] Actions {get;init;}=[];
    public string AccountPrincipal {get;init;}="effective-user";
    public int MaximumActionsPerMinute {get;init;}=3;
    public bool RequirePreservedActor {get;init;}=true;
    public string[] ExcludedAccountIds {get;init;}=[];
    public string[] RecoveryAddresses {get;init;}=[];
    public bool IsValid()=>Version==1&&Mode is "observe" or "manual" or "automatic"&&Actions is {Length:<=5}&&(Mode=="observe"||Actions.Length>0)&&Actions.Distinct().Count()==Actions.Length&&Actions.All(ActiveResponseActions.All.Contains)&&
        AccountPrincipal is "process-owner" or "effective-user"&&MaximumActionsPerMinute is >=1 and <=10&&ExcludedAccountIds is {Length:<=100}&&ExcludedAccountIds.All(id=>id is {Length:>0 and <=256}&&!id.Any(char.IsControl))&&
        RecoveryAddresses is {Length:<=32}&&RecoveryAddresses.All(ip=>System.Net.IPAddress.TryParse(ip,out _));
    public bool SameContent(ActiveResponsePolicy other)=>Version==other.Version&&Mode==other.Mode&&AccountPrincipal==other.AccountPrincipal&&MaximumActionsPerMinute==other.MaximumActionsPerMinute&&RequirePreservedActor==other.RequirePreservedActor&&Actions.SequenceEqual(other.Actions)&&ExcludedAccountIds.SequenceEqual(other.ExcludedAccountIds)&&RecoveryAddresses.SequenceEqual(other.RecoveryAddresses);
}
public static class ActiveResponseActions
{
    public static readonly string[] All=["block-resource","end-process","disable-account","revoke-sessions","isolate-host"];
}
public sealed record ActiveResponseTarget(string SensorId,string EventId,string OperatingSystem,TrustProcessSelector Process,
    string ActorSha256,string? Executable,string? TargetPath,TrustActor? Account,string AccountPrincipal)
{
    public string? TargetStableId {get;init;}
    public bool IsValid()=>EvidenceTransferLimits.Id(SensorId)&&EvidenceTransferLimits.Id(EventId)&&OperatingSystem is "windows" or "linux"&&Process?.IsValid()==true&&Process.SensorId==SensorId&&
        EvidenceTransferLimits.Hash(ActorSha256)&&Executable is null or {Length:<=32768}&&TargetPath is null or {Length:<=4096}&&TargetStableId is null or {Length:>0 and <=256}&&AccountPrincipal is "process-owner" or "effective-user";
}
public sealed record ActiveResponsePreview(string SensorId,string EventId,string Mode,string[] Actions,ActiveResponseTarget? Target,
    string[] Reasons,bool ActorPreserved,bool AutomaticResponseSuppressed)
{
    public bool Eligible=>Target!=null&&Reasons.Length==0;
}
public static class ActiveResponseEvidence
{
    // Enrichment may finish after the operation. Import only the verified artifact
    // receipt; the original process and accessing-thread snapshot remain authoritative.
    public static AgentEvent AttachPreservation(AgentEvent original,AgentEvent completion)
    {
        var source=original.Forensics;var collected=completion.Forensics;
        var hash=source?.ActorExecutable.Sha256??source?.ActorExecutable.Acquisition?.SnapshotSha256??source?.ActorExecutable.LinuxAcquisition?.SnapshotSha256;
        if(source?.IsValid()!=true||source.EventId!=original.EventId||source.RelatedEventId!=null||
            completion.Source!="Forensic enrichment"||collected?.IsValid()!=true||collected.SensorId!=source.SensorId||
            collected.EventId!=completion.EventId||collected.RelatedEventId!=original.EventId||
            collected.Process.InstanceId!=source.Process.InstanceId||collected.ActorExecutable.BindingSourceEventId!=original.EventId||
            collected.Preservation.Status.State!="captured"||collected.Preservation.HashMatched!=true||
            collected.Preservation.SourceEventId!=original.EventId||collected.Preservation.ProcessInstanceId!=source.Process.InstanceId||
            !EvidenceTransferLimits.Id(collected.Preservation.EvidenceId)||!EvidenceTransferLimits.Hash(hash)||
            collected.ActorExecutable.Sha256!=hash||collected.Preservation.Sha256!=hash)return original;
        return original with{Forensics=source with{Preservation=collected.Preservation}};
    }
    public static ActiveResponsePreview Preview(string sensor,AgentEvent e,ActiveResponsePolicy policy,DateTimeOffset now)
    {
        if(!policy.IsValid())throw new ArgumentException("Invalid active response policy");
        var reasons=new List<string>();var context=TrustIdentityContext.Bind(new("server",null,sensor,e.Source=="Windows minifilter"?"windows":e.Source=="Linux kernel"?"linux":"unknown",e.Path,EventTrust.PolicyActions(e),e.ObservedUtc,e.Trust?.Actor??new()),e);
        var os=context.OperatingSystem;var p=context.ProcessInstance;var f=e.Forensics;
        var hash=f?.ActorExecutable.Sha256??f?.ActorExecutable.LinuxAcquisition?.SnapshotSha256??f?.ActorExecutable.Acquisition?.SnapshotSha256;
        var principal=policy.AccountPrincipal=="process-owner"?context.ProcessOwner:context.EffectiveUser;
        if(os is not ("windows" or "linux")||p?.IsValid()!=true)reasons.Add("RESPONSE_PROCESS_INSTANCE_UNAVAILABLE");
        if(f?.IsValid()!=true||f.SensorId!=sensor||f.EventId!=e.EventId||f.RelatedEventId!=null||
            !EvidenceTransferLimits.Hash(hash)||f.ActorExecutable.BindingStatus.State!="captured"||f.ActorExecutable.BindingSourceEventId!=e.EventId||
            os=="linux"&&LinuxNativeHashBinding.ActorHash(e)!=hash)reasons.Add("RESPONSE_EXECUTABLE_EVIDENCE_UNAVAILABLE");
        if(policy.Mode=="observe")reasons.Add("RESPONSE_OBSERVE_ONLY");
        if(policy.Actions.Length==0)reasons.Add("RESPONSE_NO_ACTION_SELECTED");
        if(e.ObservedUtc<now.AddMinutes(-2)||e.ObservedUtc>now.AddSeconds(30))reasons.Add("RESPONSE_EVENT_EXPIRED");
        if(e.Source.Contains("health",StringComparison.OrdinalIgnoreCase)||e.Source.Contains("response",StringComparison.OrdinalIgnoreCase)||e.Source is "Forensic enrichment" or "Evidence transfer")reasons.Add("RESPONSE_EVENT_NOT_ACTIONABLE");
        if(policy.Actions.Any(a=>a is "disable-account" or "revoke-sessions" or "block-resource")&&principal is not {Verified:true})reasons.Add("RESPONSE_PRINCIPAL_UNAVAILABLE");
        if(principal is {} user&&(user.AccountId is "0" or "S-1-5-18" or "S-1-5-19" or "S-1-5-20"||policy.ExcludedAccountIds.Contains(user.AccountId)))reasons.Add("RESPONSE_PROTECTED_ACCOUNT");
        if(p?.Pid is <=4)reasons.Add("RESPONSE_PROTECTED_PROCESS");
        var preserved=EvidenceTransferLimits.Hash(hash)&&f?.Preservation is {Status.State:"captured",HashMatched:true} preservation&&
            preservation.Sha256==hash&&preservation.SourceEventId==e.EventId&&preservation.ProcessInstanceId==f.Process.InstanceId&&
            EvidenceTransferLimits.Id(preservation.EvidenceId);
        if(policy.RequirePreservedActor&&!preserved)reasons.Add("RESPONSE_ACTOR_PRESERVATION_REQUIRED");
        if(policy.Actions.Contains("block-resource")&&(e.Attribution?.LinuxKernel!=null||string.IsNullOrWhiteSpace(e.Path)||e.Path.StartsWith('[')))reasons.Add("RESPONSE_RESOURCE_PATH_UNAVAILABLE");
        if(policy.Actions.Contains("block-resource")&&(f?.Observation.File.Status.State!="captured"||string.IsNullOrWhiteSpace(f.Observation.File.StableId)))reasons.Add("RESPONSE_RESOURCE_IDENTITY_UNAVAILABLE");
        var suppressed=e.Trust?.Result.Decision.SuppressResponse==true;
        if(policy.Mode=="automatic"&&suppressed)reasons.Add("RESPONSE_SUPPRESSED_BY_TRUST_POLICY");
        ActiveResponseTarget? target=p?.IsValid()==true&&EvidenceTransferLimits.Hash(hash)?new ActiveResponseTarget(sensor,e.EventId,os,p,hash!,f?.Process.ExecutablePath,e.Path,principal,policy.AccountPrincipal){TargetStableId=f?.Observation.File.StableId}:null;
        if(target?.IsValid()!=true)target=null;
        return new(sensor,e.EventId,policy.Mode,policy.Actions,target,reasons.Distinct().ToArray(),preserved,suppressed);
    }
}
