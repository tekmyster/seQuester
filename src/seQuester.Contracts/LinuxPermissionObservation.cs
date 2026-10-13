using System.Text.Json.Serialization;

namespace RansomFree.Contracts;

// A permission-hook result is not the result of the caller's final syscall.
public sealed record LinuxPermissionObservation
{
    public uint Schema {get;init;}
    public uint Stage {get;init;}
    public string OperationNonce {get;init;}="";
    public string ObservedLease {get;init;}="";
    public string EntryNs {get;init;}="";
    public string ObservedNs {get;init;}="";
    public int AccessMask {get;init;}
    public int? PermissionResult {get;init;}
    public uint IdentityFields {get;init;}
    public int IdentityError {get;init;}
    public int ActorMetadataError {get;init;}
    public string ResultMeaning {get;init;}="PERMISSION_HOOK_RETURN_NOT_FINAL_SYSCALL_RESULT";
    public string PairingStatus {get;init;}="NOT_YET_CORRELATED";
    [JsonIgnore] public bool Diagnostic=>Schema==2&&Stage==3;
    public bool IsValid()=> (Schema==1&&Stage is 1 or 2||Diagnostic)&&
        LinuxKernelEvidence.Decimal(OperationNonce)&&(Diagnostic?OperationNonce=="0":OperationNonce!="0")&&
        LinuxKernelEvidence.Decimal(ObservedLease)&&(!Diagnostic||ObservedLease=="0")&&
        LinuxKernelEvidence.Decimal(EntryNs)&&EntryNs!="0"&&LinuxKernelEvidence.Decimal(ObservedNs)&&
        ulong.Parse(ObservedNs,System.Globalization.CultureInfo.InvariantCulture)>=ulong.Parse(EntryNs,System.Globalization.CultureInfo.InvariantCulture)&&
        IdentityFields<=7&&(Stage==2?PermissionResult.HasValue:PermissionResult==null)&&
        ResultMeaning=="PERMISSION_HOOK_RETURN_NOT_FINAL_SYSCALL_RESULT"&&PairingStatus=="NOT_YET_CORRELATED";
}
