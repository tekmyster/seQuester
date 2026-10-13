namespace RansomFree.Contracts;

// Links a permission-hook result to its own entry snapshot. A permission result
// is not a completed syscall and never grants a second executable-copy lease.
public sealed record LinuxPermissionPairEvidence
{
    public int Version {get;init;}=1;
    public string Status {get;init;}="unavailable";
    public string Reason {get;init;}="PERMISSION_PAIR_NOT_AVAILABLE";
    public string? EntryEventId {get;init;}
    public string ReturnEventId {get;init;}="";
    public LinuxKernelEvidence? EntryKernel {get;init;}
    public string? ActorCompletionEventId {get;init;}
    public string? ActorSha256 {get;init;}
    public string? ActorEvidenceId {get;init;}
    public EvidenceStatus ActorStatus {get;init;}=EvidenceStatus.Unavailable("PERMISSION_ENTRY_ACTOR_NOT_AVAILABLE");
    public bool Matches(LinuxKernelEvidence result,string eventId,string? relatedEventId)
    {
        if(Version!=1||result.PermissionObservation is not {Schema:1,Stage:2}||!EvidenceTransferLimits.Id(ReturnEventId)||ReturnEventId!=(relatedEventId??eventId)||
            EntryEventId!=null&&(!EvidenceTransferLimits.Id(EntryEventId)||EntryEventId==ReturnEventId)||Reason is not {Length:>0 and <=128}||ActorStatus.Reason is not {Length:>0 and <=256})return false;
        if(Status=="unavailable")return EntryKernel==null&&ActorSha256==null&&ActorCompletionEventId==null&&ActorEvidenceId==null&&ActorStatus.State=="unavailable";
        if(Status!="paired"||EntryEventId==null||EntryKernel==null||!LinuxKernelEvidence.SamePermissionOperation(EntryKernel,result))return false;
        if(ActorStatus.State=="unavailable")return ActorSha256==null&&ActorCompletionEventId==null&&ActorEvidenceId==null;
        return ActorStatus.State=="captured"&&EvidenceTransferLimits.Hash(ActorSha256)&&EvidenceTransferLimits.Id(ActorCompletionEventId)&&(ActorEvidenceId==null||EvidenceTransferLimits.Id(ActorEvidenceId));
    }
}
