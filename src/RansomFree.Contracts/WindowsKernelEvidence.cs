namespace RansomFree.Contracts;

// Operation-time observations, not live token handles or authorization credentials.
// CREATE authorization, request-thread effective context and process primary context
// must stay separate: a handle can be used after its opener reverts impersonation.
public sealed record WindowsTokenSnapshot
{
    public uint Captured {get;init;}
    public string? Sid {get;init;}
    public string? TokenId {get;init;}
    public string? AuthenticationId {get;init;}
    public string? ModifiedId {get;init;}
    public uint? Type {get;init;}
    public uint? ImpersonationLevel {get;init;}
    public uint? SessionId {get;init;}
    public uint? IntegrityRid {get;init;}
    public bool? Elevated {get;init;}
    public string[] QueryStatus {get;init;}=[];
    public string SnapshotConsistency {get;init;}="separate-field-queries; modification-checked; not-atomic";
    public bool IsValid()=>Captured<=31&&Sid is null or {Length:<=184}&&
        new[]{TokenId,AuthenticationId,ModifiedId}.All(x=>x==null||x.Length==16&&x.All(Uri.IsHexDigit))&&
        Type is null or 1 or 2&&ImpersonationLevel is null or <=3&&QueryStatus is {Length:5}&&QueryStatus.All(x=>x is {Length:10}&&x.StartsWith("0x")&&x[2..].All(Uri.IsHexDigit))&&
        SnapshotConsistency=="separate-field-queries; modification-checked; not-atomic"&&((Captured&1)!=0)==(Sid!=null)&&
        ((Captured&2)!=0)==(TokenId!=null&&AuthenticationId!=null&&ModifiedId!=null&&Type!=null)&&
        ((Captured&4)!=0)==SessionId.HasValue&&((Captured&8)!=0)==IntegrityRid.HasValue&&((Captured&16)!=0)==Elevated.HasValue;
    public PrincipalEvidence Principal(string reason)=>new(){Sid=Sid,TokenId=TokenId,AuthenticationId=AuthenticationId,LogonId=AuthenticationId,SessionId=SessionId,
        IntegritySid=IntegrityRid is {} rid?"S-1-16-"+rid:null,Elevated=Elevated,TokenType=Type switch{1=>"primary",2=>"impersonation",_=>null},
        Status=new(Captured==31?"captured":Captured==0?"unavailable":"partial",reason,string.Join(",",QueryStatus))};
}
public sealed record WindowsKernelEvidence
{
    public int Version {get;init;}=4;
    public string Instance {get;init;}="";
    public long Sequence {get;init;}
    public int? ProcessId {get;init;}
    public uint? ThreadId {get;init;}
    public uint? ThreadProcessId {get;init;}
    public long? ProcessCreatedFileTime {get;init;}
    public DateTimeOffset CompletedUtc {get;init;}
    public long MonotonicTicks {get;init;}
    public long MonotonicFrequency {get;init;}
    public uint Flags {get;init;}
    public uint Major {get;init;}
    public uint OperationClass {get;init;}
    public string NativePath {get;init;}="";
    public string? FileIoBoundary {get;init;}
    public string? RemoteProviderStatus {get;init;}
    public string NameSource {get;init;}="unavailable";
    public string NormalizedNameStatus {get;init;}="";
    public uint DesiredAccess {get;init;}
    public uint CreateOptions {get;init;}
    public uint CaptureIrql {get;init;}
    public string SubjectSource {get;init;}="unavailable";
    public bool? ThreadImpersonating {get;init;}
    public bool? CopyOnOpen {get;init;}
    public bool? EffectiveOnly {get;init;}
    public WindowsTokenSnapshot CreateAuthorization {get;init;}=new();
    public WindowsTokenSnapshot ThreadEffective {get;init;}=new();
    public WindowsTokenSnapshot RequestorPrimary {get;init;}=new();
    public WindowsTokenSnapshot? ThreadOwnerPrimary {get;init;}
    public long? ThreadProcessCreatedFileTime {get;init;}
    public uint? CallbackDataFlags {get;init;}
    public uint? RequestorMode {get;init;}
    public string ThreadOwnerStatus {get;init;}="legacy-provider-unavailable";
    public string? BaseRecordSha256 {get;init;}
    public string? ThreadContextSha256 {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsDeferredTokenEvidence? DeferredTokenContext {get;init;}
    // Omit only the additive container for historical records, preserving their
    // immutable serialization. New legacy observations explicitly carry V0.
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public WindowsAcquisitionObservation? AcquisitionObservation {get;init;}
    public bool IsValid()=>Version is 4 or 5 or 6 or 7 or 8&&
        (Version>=7?DeferredTokenContext?.IsValid(this)==true:DeferredTokenContext==null)&&
        (AcquisitionObservation==null||AcquisitionObservation.IsValid(this))&&
        (Version is 6 or 8? (Flags&1024)!=0&&FileIoBoundary=="client-network-filesystem"&&RemoteProviderStatus=="unavailable: MUP provider not verified"&&NativePath.StartsWith("\\Device\\Mup\\",StringComparison.OrdinalIgnoreCase):
            (Flags&1024)==0&&FileIoBoundary==null&&RemoteProviderStatus==null)&&
        (Version==4?ThreadOwnerPrimary==null&&ThreadProcessCreatedFileTime==null&&CallbackDataFlags==null&&BaseRecordSha256==null&&ThreadContextSha256==null&&ThreadOwnerStatus=="legacy-provider-unavailable":
            ThreadOwnerPrimary?.IsValid()==true&&CallbackDataFlags!=null&&RequestorMode is 0 or 1&&ThreadProcessCreatedFileTime is null or >0&&
            BaseRecordSha256 is {Length:64}&&BaseRecordSha256.All(Uri.IsHexDigit)&&ThreadContextSha256 is {Length:64}&&ThreadContextSha256.All(Uri.IsHexDigit)&&
            ThreadOwnerStatus==ExpectedThreadOwnerStatus&&
            (ThreadId!=null||ThreadOwnerPrimary.Captured==0&&ThreadProcessCreatedFileTime==null&&ThreadProcessId==null)&&
            (CaptureIrql==0||ThreadOwnerPrimary.Captured==0&&ThreadProcessCreatedFileTime==null))&&
        Instance is {Length:16}&&Instance.All(Uri.IsHexDigit)&&Sequence>0&&ProcessId is null or >0&&ThreadId is null or >0&&ThreadProcessId is null or >0&&ProcessCreatedFileTime is null or >0&&
        CompletedUtc!=default&&MonotonicTicks>=0&&MonotonicFrequency>0&&NativePath is {Length:<=1536}&&NameSource is "normalized" or "opened"&&NormalizedNameStatus is {Length:10}&&
        (SubjectSource is "create-access-state" or "request-thread-snapshot" or "unavailable"||Version>=7&&SubjectSource==DeferredSubjectSource)&&CreateAuthorization?.IsValid()==true&&ThreadEffective?.IsValid()==true&&RequestorPrimary?.IsValid()==true;
    public static bool Matches(AgentEvent e)=>e.Attribution?.WindowsKernel is not {} k||k.IsValid()&&
        e.Source is "Windows minifilter" or "Forensic enrichment" or "Evidence transfer"&&e.Attribution.Provider=="Windows minifilter"&&e.ProcessId==k.ProcessId&&e.Attribution.UserSid==k.Subject.Sid&&
        (e.Forensics?.ActorExecutable.Acquisition is not {} a||a.EventInstance==k.Instance&&a.EventSequence==k.Sequence&&(a.ProcessGeneration==null||a.ProcessId==k.ProcessId&&a.ProcessCreatedFileTime==k.ProcessCreatedFileTime));
    public static int RequiredVersion(IEnumerable<AgentEvent> events)=>events.Select(e=>e.Attribution?.WindowsKernel?.Version??0).DefaultIfEmpty(0).Max();
    [System.Text.Json.Serialization.JsonIgnore]
    private string ExpectedThreadOwnerStatus=>ThreadId==null?"thread-unavailable":CaptureIrql!=0?"irql-not-passive":ThreadOwnerPrimary?.Captured==31?"captured":ThreadOwnerPrimary?.Captured>0?"partial":"token-unavailable";
    [System.Text.Json.Serialization.JsonIgnore]
    public WindowsTokenSnapshot Subject=>SubjectSource switch{
        "create-access-state"=>CreateAuthorization,
        "callback-referenced-thread-token"=>DeferredTokenContext?.ThreadEffective??ThreadEffective,
        "later-thread-owner-primary"=>DeferredTokenContext?.ThreadOwnerPrimary??ThreadEffective,
        _=>ThreadEffective};
    [System.Text.Json.Serialization.JsonIgnore]
    private string DeferredSubjectSource=>DeferredTokenContext?.ThreadImpersonating switch{true=>"callback-referenced-thread-token",false=>"later-thread-owner-primary",_=>"unavailable"};
}
