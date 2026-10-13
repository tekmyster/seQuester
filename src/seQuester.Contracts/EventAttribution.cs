namespace RansomFree.Contracts;

// Additive versioned evidence. Historical audit PIDs are never response handles.
public sealed record EventAttribution
{
    public int Version {get;init;}=1;
    public string Provider {get;init;}="";
    public string Level {get;init;}="Detection only";
    public string Basis {get;init;}="";
    public string? EvidenceId {get;init;}
    public string? Syscall {get;init;}
    public string? Outcome {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? UserSid {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? LogonId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public uint? GroupId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public uint? EffectiveGroupId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public uint? FileSystemGroupId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? AccessMask {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? OsStatus {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetStableId {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RenameSource {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RenameDestination {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public long? BytesTransferred {get;init;}
    public uint? UserId {get;init;}
    public uint? EffectiveUserId {get;init;}
    public uint? FileSystemUserId {get;init;}
    public uint? LoginUserId {get;init;}
    public string? UserName {get;init;}
    public string? EffectiveUserName {get;init;}
    public string? LoginUserName {get;init;}
    public string? AccountNameSource {get;init;}
    public uint? SessionId {get;init;}
    public int? ParentProcessId {get;init;}
    public string? ProcessName {get;init;}
    public string? ProcessStartTicks {get;init;}
    public string? ExecutableSha256 {get;init;}
    public string? CommandLine {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public bool? CommandLineTruncated {get;init;}
    public string? PathRole {get;init;}
    public bool EventTimeCredentials {get;init;}
    public bool CompleteRecordSet {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsKernelEvidence? WindowsKernel {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxKernelEvidence? LinuxKernel {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsShareEvidence? WindowsShare {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsSyscallObservation? WindowsSyscall {get;init;}
    public bool IsValid()
    {
        static bool Text(string? s,int max)=>s==null||s.Length<=max&&!s.Any(char.IsControl);
        return Version==1&&(WindowsSyscall==null||WindowsSyscall.IsValid()&&WindowsKernel==null&&LinuxKernel==null&&WindowsShare==null)&&(WindowsShare==null||WindowsShare.IsValid()&&WindowsKernel==null&&LinuxKernel==null)&&(WindowsKernel==null||WindowsKernel.IsValid())&&(LinuxKernel==null||LinuxKernel.IsValid())&&(WindowsKernel==null||LinuxKernel==null)&&(Level is "Full attribution" or "Partial attribution" or "Detection only")
            &&Text(Provider,64)&&!string.IsNullOrEmpty(Provider)&&Text(Basis,512)&&Text(EvidenceId,160)&&Text(Syscall,100)&&Text(Outcome,32)
            &&Text(UserName,256)&&Text(EffectiveUserName,256)&&Text(LoginUserName,256)&&Text(AccountNameSource,256)&&ParentProcessId is not <0&&Text(ProcessName,256)&&Text(ProcessStartTicks,LinuxKernel==null?32:64)
            &&Text(CommandLine,2048)&&Text(PathRole,32)&&Text(UserSid,184)&&Text(LogonId,64)&&Text(AccessMask,64)&&Text(OsStatus,64)&&Text(TargetStableId,256)&&Text(RenameSource,2048)&&Text(RenameDestination,2048)&&BytesTransferred is not <0
            &&(ExecutableSha256==null||ExecutableSha256.Length==64&&ExecutableSha256.All(Uri.IsHexDigit));
    }
}
