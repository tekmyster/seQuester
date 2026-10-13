namespace RansomFree.Contracts;

// A return observation references the executable captured for its exact entry.
// This is evidence linkage, never another lease or a command to reopen a PID.
public sealed record LinuxIoPairEvidence
{
    public int Version {get;init;}=1;
    public string Status {get;init;}="unavailable";
    public string Reason {get;init;}="IO_PAIR_NOT_AVAILABLE";
    public string? EntryEventId {get;init;}
    public string ReturnEventId {get;init;}="";
    public LinuxKernelEvidence? EntryKernel {get;init;}
    public string? ActorCompletionEventId {get;init;}
    public string? ActorSha256 {get;init;}
    public string? ActorEvidenceId {get;init;}
    public EvidenceStatus ActorStatus {get;init;}=EvidenceStatus.Unavailable("IO_ENTRY_ACTOR_NOT_AVAILABLE");
    public bool Matches(LinuxKernelEvidence result,string eventId,string? relatedEventId)
    {
        if(Version!=1||result.IoObservation is not {Schema:3,Stage:2}||
            !EvidenceTransferLimits.Id(ReturnEventId)||ReturnEventId!=(relatedEventId??eventId)||
            EntryEventId!=null&&(!EvidenceTransferLimits.Id(EntryEventId)||EntryEventId==ReturnEventId)||
            Reason is not {Length:>0 and <=128}||ActorStatus.Reason is not {Length:>0 and <=256})return false;
        if(Status=="unavailable")return EntryKernel==null&&ActorSha256==null&&ActorCompletionEventId==null&&ActorEvidenceId==null&&ActorStatus.State=="unavailable";
        if(Status!="paired"||EntryEventId==null||EntryKernel==null||!LinuxKernelEvidence.SameIoOperation(EntryKernel,result))return false;
        if(ActorStatus.State=="unavailable")return ActorSha256==null&&ActorCompletionEventId==null&&ActorEvidenceId==null;
        return ActorStatus.State=="captured"&&EvidenceTransferLimits.Hash(ActorSha256)&&EvidenceTransferLimits.Id(ActorCompletionEventId)&&
            (ActorEvidenceId==null||EvidenceTransferLimits.Id(ActorEvidenceId));
    }
}
