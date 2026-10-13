using System.Globalization;

namespace RansomFree.Contracts;

// Additive, versioned timeline evidence. Native method return, verified actor
// availability, and source continuity are different facts. This is no safety
// verdict and does not authorize replaying historical kernel identifiers.
public sealed record LinuxNativeWorkEvidence
{
    public int Version {get;init;}=1;
    public string PinId {get;init;}="";
    public string SourceSessionId {get;init;}="";
    public string SourceEventId {get;init;}="";
    public string CompletionEventId {get;init;}="";
    public string NativeObservationSha256 {get;init;}="";
    public string PolicySha256 {get;init;}="";
    public string CollectorInstance {get;init;}="";
    public long CollectorSequence {get;init;}
    public string ProviderEpoch {get;init;}="";
    public string Cookie {get;init;}="";
    public long Lease {get;init;}
    public string State {get;init;}="";
    public long IssuedGeneration {get;init;}
    public DateTimeOffset IssuedUtc {get;init;}
    public DateTimeOffset PinCommittedUtc {get;init;}
    public string? AuthorizationId {get;init;}
    public long? AuthorizationGeneration {get;init;}
    public DateTimeOffset? AuthorizationCommittedUtc {get;init;}
    public long? StartingGeneration {get;init;}
    public string? StartingState {get;init;}
    public string? StartingReason {get;init;}
    public string? StartOrdering {get;init;}
    public DateTimeOffset? StartRecordedUtc {get;init;}
    public DateTimeOffset? ActualReturnUtc {get;init;}
    public string? ReturnOutcome {get;init;}
    public string? ReturnReason {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxNativeMethodEvidence? Method {get;init;}
    public static int RequiredVersion(IEnumerable<AgentEvent> events)=>events.Select(e=>e.Forensics?.ActorExecutable.LinuxNativeWork?.Version??0).DefaultIfEmpty(0).Max();
    public static bool Supports(int required,int reported)=>required==0||required is 1 or 2&&reported is 1 or 2&&reported>=required;
    public bool IsValid(string eventId,string? relatedEventId)
    {
        static bool Id(string? x)=>Guid.TryParseExact(x,"N",out _);
        static bool Hash(string? x)=>x is {Length:64}&&x.All(Uri.IsHexDigit);
        static bool Counter(string? x)=>ulong.TryParse(x,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n.ToString(CultureInfo.InvariantCulture)==x;
        if(Version is not (1 or 2)||Version==1&&Method!=null||Version==2&&(Method==null||!Method.IsValid(PinId)||ActualReturnUtc==null)||!Id(PinId)||!Id(SourceSessionId)||!Id(SourceEventId)||SourceEventId!=eventId&&SourceEventId!=relatedEventId||
            !Id(CompletionEventId)||CompletionEventId==SourceEventId||!Hash(NativeObservationSha256)||!Hash(PolicySha256)||!Id(CollectorInstance)||CollectorSequence<=0||
            !Counter(ProviderEpoch)||ProviderEpoch=="0"||!Counter(Cookie)||IssuedGeneration<1||IssuedUtc==default||PinCommittedUtc==default||
            State is not ("PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED" or "NATIVE_RETURNED_RECEIPT_COMMITTED" or "NATIVE_RETURNED_UNAVAILABLE_COMMITTED" or "PIN_INTERRUPTED_PRESELECT" or "PIN_INTERRUPTED_UNKNOWN"))return false;
        if(AuthorizationId==null)
        {if(AuthorizationGeneration!=null||AuthorizationCommittedUtc!=null||StartRecordedUtc!=null)return false;}
        else if(!Id(AuthorizationId)||AuthorizationGeneration!=IssuedGeneration||AuthorizationCommittedUtc==null||AuthorizationCommittedUtc==default(DateTimeOffset))return false;
        if(StartRecordedUtc==null)
        {if(StartingGeneration!=null||StartingState!=null||StartingReason!=null||StartOrdering!=null||ActualReturnUtc!=null)return false;}
        else if(StartRecordedUtc==default(DateTimeOffset)||StartingGeneration<AuthorizationGeneration||StartingGeneration==null||
            StartingState is not ("Active" or "Faulted" or "StopRequested" or "Closing")||StartingReason?.Length>128||
            StartOrdering is not ("SAME_GENERATION_START" or "AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT" or "AUTHORIZED_BEFORE_STOP_SELECT_STARTING_AFTER_STOP"))return false;
        if(StartRecordedUtc!=null)
        {
            if(StartOrdering=="SAME_GENERATION_START")
            {if(StartingGeneration!=AuthorizationGeneration||StartingState!="Active"||StartingReason!=null)return false;}
            else if(StartingGeneration<=AuthorizationGeneration||StartingState=="Active"||string.IsNullOrWhiteSpace(StartingReason)||
                StartOrdering=="AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT"&&StartingState=="StopRequested"||
                StartOrdering=="AUTHORIZED_BEFORE_STOP_SELECT_STARTING_AFTER_STOP"&&StartingState=="Faulted")return false;
        }
        if(ActualReturnUtc==null)
        {if(ReturnOutcome!=null||ReturnReason!=null)return false;}
        else if(ActualReturnUtc==default(DateTimeOffset)||ReturnOutcome is not ("committed" or "unresolved")||ReturnReason is not {Length:>0 and <=128})return false;
        if(Method!=null&&(Method.ControllerMethodAttempted&&Lease<=0||Method.ErrorKind!=null&&ReturnReason!="NATIVE_OPERATION_FAILED"||
            Method.LastStep=="NO_NATIVE_LEASE"&&(Lease>0||ReturnReason!=(Method.ErrorKind==null?"NATIVE_METHOD_NOT_CALLED_NO_LEASE":"NATIVE_OPERATION_FAILED"))||Method.LastStep=="WORK_CONTEXT"&&(Method.ErrorKind==null||ReturnReason!="NATIVE_OPERATION_FAILED")||
            Method.DropReceiptCommitObserved&&ReturnOutcome!="committed"))return false;
        return State switch
        {
            "PIN_COMMITTED"=>AuthorizationId==null,
            "SELECTION_AUTHORIZED"=>AuthorizationId!=null&&StartRecordedUtc==null,
            "NATIVE_STARTED"=>StartRecordedUtc!=null&&ActualReturnUtc==null,
            "PIN_INTERRUPTED_PRESELECT"=>StartRecordedUtc==null,
            "PIN_INTERRUPTED_UNKNOWN"=>ReturnOutcome is null or "unresolved",
            _=>StartRecordedUtc!=null&&ActualReturnUtc!=null&&ReturnOutcome=="committed"
        };
    }
    public bool Matches(LinuxKernelEvidence k)=>k.IsValid()&&CollectorInstance==k.CollectorInstance&&CollectorSequence==k.CollectorSequence&&
        ProviderEpoch==k.ProviderEpoch&&Cookie==k.Cookie&&Lease==k.Lease&&string.Equals(NativeObservationSha256,k.NativeObservationSha256,StringComparison.OrdinalIgnoreCase)&&
        (Method?.LatestStatus==null||Method.LatestStatus.Matches(k));
}
