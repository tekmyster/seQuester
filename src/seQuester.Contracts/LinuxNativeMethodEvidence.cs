namespace RansomFree.Contracts;

// Userspace method observations, not a reconstructed kernel-I/O trace. A
// returned method never implies the kernel worker stopped or controller closed.
public sealed record LinuxNativeMethodEvidence
{
    public int Version {get;init;}=1;
    public string PinId {get;init;}="";
    public bool ControllerMethodAttempted {get;init;}
    public string LastStep {get;init;}="";
    public LinuxActorLeaseEvidence? LatestStatus {get;init;}
    public bool DropMethodAttempted {get;init;}
    public bool DropMethodReturned {get;init;}
    public bool DropReceiptCommitObserved {get;init;}
    public string? ErrorKind {get;init;}
    public string? ErrorDomain {get;init;}
    public string? ErrorCode {get;init;}
    public string? ErrorDetail {get;init;}
    public bool IsValid(string pin)
    {
        if(Version!=1||PinId!=pin||!Guid.TryParseExact(PinId,"N",out _)||
            LastStep is not ("WORK_CONTEXT" or "NO_NATIVE_LEASE" or "ATOMIC_START_METHOD" or "STATUS_METHOD" or "ACTOR_CAPTURE" or "PRE_DROP_STATUS_METHOD" or "DROP_METHOD" or "DROP_RECEIPT_COMMIT")||
            !ControllerMethodAttempted&&(LastStep is not ("WORK_CONTEXT" or "NO_NATIVE_LEASE")||LatestStatus!=null||DropMethodAttempted)||
            ControllerMethodAttempted&&LastStep is "WORK_CONTEXT" or "NO_NATIVE_LEASE"||LatestStatus!=null&&!LatestStatus.IsValid()||
            DropMethodReturned&&!DropMethodAttempted||DropReceiptCommitObserved&&!DropMethodReturned||
            DropMethodAttempted&&LastStep is not ("DROP_METHOD" or "DROP_RECEIPT_COMMIT")||
            LastStep=="DROP_RECEIPT_COMMIT"&&!DropMethodReturned)return false;
        if(ErrorKind==null)return ErrorDomain==null&&ErrorCode==null&&ErrorDetail==null;
        return ErrorKind.Length is >0 and <=200&&ErrorDomain is "posix" or "sqlite" or "dotnet"&&ErrorCode is {Length:>0 and <=32}&&ErrorDetail is {Length:<=256};
    }
}
