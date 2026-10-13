namespace RansomFree.Contracts;

// Separate notification/automatic-response decisions; never an instruction to discard an event.
public sealed record TrustRuntimeDecision(long? Revision, string? Digest, string Mode, TrustDecision Decision);

public sealed record EventTrust(int Version, string OperatingSystem, string? Group, TrustActor Actor, TrustRuntimeDecision Result)
{
    public DateTimeOffset EvaluatedUtc {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ProcessBasis {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ProcessCreatedUtc {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? ImageCheckedUtc {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxKernelTrustBinding? LinuxKernelBinding {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public LinuxNativeHashBinding? LinuxNativeHashBinding {get;init;}
    public bool IsLogOnlyFor(AgentEvent value)=>Version is 2 or 3 or 4&&IsValid()&&Result.Mode=="enforce"&&Result.Decision.LogOnly&&
        (Version==2||Version==3&&LinuxKernelBinding?.Matches(value)==true||Version==4&&LinuxNativeHashBinding?.Matches(value)==true);
    public bool IsValid()
    {
        static bool Text(string? value,int bound)=>value==null||value.Length<=bound&&!value.Any(char.IsControl);
        static bool Hash(string? value)=>value is {Length:64}&&value.All(Uri.IsHexDigit);
        if(Version is not (1 or 2 or 3 or 4)||EvaluatedUtc==default||OperatingSystem is not ("windows" or "linux" or "macos")||Group!=null&&!Guid.TryParseExact(Group,"N",out _)||Actor==null||Result?.Decision==null)return false;
        var a=Actor;var r=Result;var d=r.Decision;
        if(Version==4)
        {
            if(OperatingSystem!="linux"||ProcessBasis!=RansomFree.Contracts.LinuxNativeHashBinding.Basis||ProcessCreatedUtc!=null||ImageCheckedUtc!=null||LinuxKernelBinding!=null||
                LinuxNativeHashBinding is not {Version:1,Source.Health:not null} native||!EvidenceTransferLimits.Id(native.SensorId)||!EvidenceTransferLimits.Id(native.SourceSessionId)||
                !Hash(native.ActorSha256)||!Hash(native.PolicyInputSha256)||!native.Source.Health.IsValid(native.SourceGeneration)||a.Executable!=null||a.Sha256!=native.ActorSha256||!a.Verified||a.AccountKind!="uid"||a.Authority!=native.SensorId)return false;
        }
        else if(LinuxNativeHashBinding!=null)return false;
        else if(Version==3)
        {
            if(OperatingSystem!="linux"||ProcessBasis!=LinuxKernelTrustBinding.Basis||ProcessCreatedUtc!=null||ImageCheckedUtc!=null||
                LinuxKernelBinding is not {Version:1,Actor:not null,Source.Health:not null} binding||!Hash(binding.PolicyInputSha256)||
                !Guid.TryParseExact(binding.SensorId,"N",out _)||!binding.Source.Health.IsValid(binding.Actor.SourceGeneration)||a!=binding.TrustActor())return false;
        }
        else if(LinuxKernelBinding!=null)return false;
        else if(ProcessBasis is "windows-handle-locked-image-v1" or "windows-operation-bound-snapshot-v1")
        {if(OperatingSystem!="windows"||ProcessCreatedUtc==null||ImageCheckedUtc==null||ProcessBasis=="windows-operation-bound-snapshot-v1"&&(Version!=2||!Hash(a.Sha256)||!a.Verified))return false;}
        else if(ProcessCreatedUtc!=null||ImageCheckedUtc!=null||ProcessBasis!=null&&(Version!=2||ProcessBasis!="audit-executable-path-v1"||OperatingSystem is not ("windows" or "linux")))return false;
        if(Version==1&&d.Disposition=="log-only")return false;
        if(!Text(a.Authority,256)||!Text(a.AccountId,184)||!Text(a.AccountKind,8)||!Text(a.Executable,1024)||!Text(a.Signer,256)||!Text(a.Publisher,256)||!Text(a.ParentExecutable,1024)||a.Sha256!=null&&!Hash(a.Sha256))return false;
        if(r.Mode is not ("legacy" or "pending" or "enforce")||r.Revision is <0||r.Digest!=null&&!Hash(r.Digest)||r.Mode!="pending"&&(r.Revision==null||r.Digest==null)||d.Version!=1||!TrustEvaluation.Dispositions.Contains(d.Disposition)||d.Severity is not ("normal" or "informational")||d.MatchedRules is not {Length:<=64}||d.MatchedRuleCount<d.MatchedRules.Length||d.MatchedRuleCount>1000||d.MatchedRules.Any(x=>!Guid.TryParseExact(x,"N",out _))||d.MatchedRules.Distinct().Count()!=d.MatchedRules.Length||!Text(d.Reason,512))return false;
        if(r.Mode=="pending")return d.Disposition=="normal"&&!d.SuppressPopup&&d.SuppressResponse&&d.Severity=="normal"&&d.MatchedRules.Length==0;
        if(r.Mode=="legacy")return d.Disposition=="normal"&&!d.SuppressPopup&&!d.SuppressResponse&&d.Severity=="normal"&&d.MatchedRules.Length==0;
        return d.SuppressPopup==(d.Disposition is "popup-only" or "popup-and-response" or "log-only")&&d.SuppressResponse==(d.Disposition is "response-only" or "popup-and-response" or "log-only")&&d.Severity==(d.Disposition is "informational" or "log-only"?"informational":"normal");
    }
    public TrustContext Context(string endpoint,AgentEvent value)
    {
        var actor=Version==3&&(LinuxKernelBinding?.SensorId!=endpoint||!LinuxKernelBinding.Matches(value))||Version==4&&(LinuxNativeHashBinding?.SensorId!=endpoint||!LinuxNativeHashBinding.Matches(value))?new TrustActor():Actor;
        if(Version==4&&actor.Verified&&actor!=RansomFree.Contracts.LinuxNativeHashBinding.ActorFor(endpoint,value,LinuxNativeHashBinding!.ActorSha256))actor=new();
        return TrustIdentityContext.Bind(new("server",Group,endpoint,OperatingSystem,value.Path,Version==3?["open"]:Version is 2 or 4?PolicyActions(value):EventActivity.From(value).Actions,value.ObservedUtc,actor,
            value.Source.Contains("health",StringComparison.OrdinalIgnoreCase)||value.Source.Contains("integrity",StringComparison.OrdinalIgnoreCase)||value.Source.Contains("response",StringComparison.OrdinalIgnoreCase))
            {ProcessBasis=Version is 3 or 4?ProcessBasis:null},value);
    }
    public static string[] PolicyActions(AgentEvent value)=>EventActivity.From(value).Actions.SelectMany(action=>action switch
    {
        "permissions-or-ownership"=>new[]{"permissions","ownership"},
        "create-or-truncate"=>new[]{"create","truncate"},
        "write-request"=>new[]{"write"},
        "append-request"=>new[]{"append"},
        _=>new[]{action}
    }).Distinct().ToArray();
}
