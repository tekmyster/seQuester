namespace RansomFree.Contracts;

public sealed record TrustActor(string? Authority=null,string? AccountId=null,string? Executable=null,string? Sha256=null,string? Signer=null,string? Publisher=null,string? ParentExecutable=null,bool SignatureVerified=false,bool Verified=false,string? AccountKind=null);
public sealed record TrustContext(string Organization,string? Group,string Host,string OperatingSystem,string Path,string[] Actions,DateTimeOffset ObservedUtc,TrustActor Actor,bool ProtectedEvent=false)
{
    public string? ProcessBasis {get;init;}
    public TrustActor? ProcessOwner {get;init;}
    public TrustActor? EffectiveUser {get;init;}
    public TrustProcessSelector? ProcessInstance {get;init;}
}
public sealed record TrustProcessSelector(string SensorId,int Pid,string StartKey,string SourceEpoch)
{
    public bool IsValid()=>Guid.TryParseExact(SensorId,"N",out _)&&Pid>0&&StartKey is {Length:>0 and <=128}&&SourceEpoch is {Length:>0 and <=128}&&
        !StartKey.Any(char.IsControl)&&!SourceEpoch.Any(char.IsControl)&&StartKey!="0";
}
public sealed record TrustRule(string Id,string Scope,string ScopeId,string Subject,string[] Actions,string Disposition,DateTimeOffset StartsUtc,DateTimeOffset ExpiresUtc)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? Name {get;init;}
    // Null preserves the original exact path + hash contract. Path-only matching is explicit.
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ProcessMatch {get;init;}
    public bool Enabled {get;init;}
    public string? ParentRuleId {get;init;}
    public string? Authority {get;init;}
    public string? AccountId {get;init;}
    public string? AccountKind {get;init;}
    public string? Executable {get;init;}
    public string? Sha256 {get;init;}
    public string? Signer {get;init;}
    public string? Publisher {get;init;}
    public string? ParentExecutable {get;init;}
    public string? Path {get;init;}
    public string? OperatingSystem {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? PathMatch {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? AccountPrincipal {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public TrustProcessSelector? ProcessInstance {get;init;}
}
public sealed record TrustDecision(int Version,string Disposition,bool SuppressPopup,bool SuppressResponse,string Severity,string[] MatchedRules,string Reason)
{
    [System.Text.Json.Serialization.JsonIgnore]
    public bool LogOnly=>Disposition=="log-only"&&SuppressPopup&&SuppressResponse;
    // All dispositions retain the original telemetry. No rule can discard evidence.
    public bool RetainEvidence=>true;
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    public int MatchedRuleCount {get;init;}
}
public static class TrustEvaluation
{
    public const string LinuxKernelProcessMatch="linux-task-root-path-sha256-v1";
    public const string LinuxNativeHashProcessMatch="linux-native-operation-sha256-v1";
    public static readonly string[] Dispositions=["normal","informational","log-only","popup-only","response-only","popup-and-response"];
    public static readonly string[] Actions=["open","read","write","append","truncate","rename","move","delete","permissions","ownership","create","replace","callback"];
    static bool Text(string? s,int max=1024)=>s is {Length:>0}&&s.Length<=max&&!s.Any(char.IsControl);
    static bool Hash(string? s)=>s is {Length:64}&&s.All(Uri.IsHexDigit);
    static bool Account(string? kind,string? id)=>kind switch
    {
        "uid"=>uint.TryParse(id,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var uid)&&uid!=uint.MaxValue&&id==uid.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "sid"=>id is {Length:>=7 and <=184}&&System.Text.RegularExpressions.Regex.IsMatch(id,@"\AS-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}\z",System.Text.RegularExpressions.RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(100)),
        _=>false
    };
    static int Level(string scope)=>scope switch{"organization"=>0,"group"=>1,"host"=>2,_=>-1};
    public static void Validate(IReadOnlyList<TrustRule> rules)
    {
        if(rules.Count>1000)throw new ArgumentException("Too many trust rules.");
        var ids=new HashSet<string>(StringComparer.Ordinal);
        foreach(var r in rules)
        {
            if(r==null||!Guid.TryParseExact(r.Id,"N",out _)||!ids.Add(r.Id)||Level(r.Scope)<0||!Text(r.ScopeId,128)||r.Subject is not ("account" or "process" or "account-and-process" or "account-or-process")||!Dispositions.Contains(r.Disposition)
                ||r.Actions is not {Length:>0 and <=14}||r.Actions.Any(x=>!Actions.Contains(x))||r.Actions.Distinct().Count()!=r.Actions.Length||r.ExpiresUtc<=r.StartsUtc||r.ExpiresUtc-r.StartsUtc>TimeSpan.FromDays(90))throw new ArgumentException("Invalid trust rule.");
            if(r.Subject is "account" or "account-and-process" or "account-or-process"&&(!Text(r.Authority,256)||!Account(r.AccountKind,r.AccountId)))throw new ArgumentException("Stable scoped SID or UID required.");
            if(r.Name!=null&&!Text(r.Name,128)||r.ProcessMatch is not (null or "event-path" or LinuxKernelProcessMatch or LinuxNativeHashProcessMatch))throw new ArgumentException("Invalid rule name or process match.");
            if(r.Subject is "process" or "account-and-process" or "account-or-process"&&((r.ProcessMatch==LinuxNativeHashProcessMatch?r.Executable!=null:!Absolute(r.Executable))||(r.ProcessMatch=="event-path"?r.Sha256!=null||r.Signer!=null||r.Publisher!=null||r.ParentExecutable!=null:!Hash(r.Sha256))))throw new ArgumentException("Choose a supported executable identity and SHA-256.");
            if(r.Subject=="account"&&r.ProcessMatch!=null)throw new ArgumentException("Account rules cannot select process matching.");
            if(r.Subject=="account"&&(r.Executable!=null||r.Sha256!=null||r.Signer!=null||r.Publisher!=null||r.ParentExecutable!=null)||r.Subject=="process"&&(r.Authority!=null||r.AccountId!=null||r.AccountKind!=null))throw new ArgumentException("Subject fields do not match subject type.");
            if(r.Path!=null&&!Absolute(r.Path)||r.ParentExecutable!=null&&!Absolute(r.ParentExecutable)||r.Signer!=null&&!Text(r.Signer,256)||r.Publisher!=null&&!Text(r.Publisher,256)||r.OperatingSystem!=null&&r.OperatingSystem is not ("windows" or "linux" or "macos"))throw new ArgumentException("Invalid trust predicate.");
            if(r.PathMatch is not (null or "directory")||r.PathMatch!=null&&r.Path==null||r.AccountPrincipal is not (null or "process-owner" or "effective-user")||r.AccountPrincipal!=null&&r.Subject=="process")throw new ArgumentException("Invalid directory scope or user principal.");
            if(r.ProcessInstance is {} instance&&(!instance.IsValid()||r.Scope!="host"||r.ScopeId!=instance.SensorId||r.Subject=="account"||r.ProcessMatch=="event-path"||r.ExpiresUtc-r.StartsUtc>TimeSpan.FromHours(24)))throw new ArgumentException("Temporary process rules require sensor, process lifetime, capture session and executable hash; maximum duration is 24 hours.");
            if(r.ProcessMatch==LinuxKernelProcessMatch&&(r.OperatingSystem!="linux"||r.Subject is not ("process" or "account-and-process")||
                !r.Executable!.StartsWith('/')||r.Executable.EndsWith(" (deleted)",StringComparison.Ordinal)||r.Path!=null||r.ParentExecutable!=null||r.Signer!=null||r.Publisher!=null||
                r.Subject=="account-and-process"&&(r.AccountKind!="uid"||!Guid.TryParseExact(r.Authority,"N",out _))))
                throw new ArgumentException("Linux kernel matching requires task-root path plus SHA-256, optional sensor-scoped filesystem UID, and no target-path or signature predicates.");
            if(r.ProcessMatch==LinuxNativeHashProcessMatch&&(r.OperatingSystem!="linux"||r.Executable!=null||r.Path!=null||r.ParentExecutable!=null||r.Signer!=null||r.Publisher!=null||r.Actions.Any(a=>a is not ("read" or "write" or "append"))||
                r.Subject is "account-and-process" or "account-or-process"&&(r.AccountKind!="uid"||!Guid.TryParseExact(r.Authority,"N",out _))))throw new ArgumentException("Linux native hash matching requires SHA-256 and read/write/append operations, with optional sensor-scoped UID.");
        }
        foreach(var r in rules.Where(x=>x.ParentRuleId!=null))
        {
            var parent=rules.SingleOrDefault(x=>x.Id==r.ParentRuleId);
            if(parent==null||Level(parent.Scope)>=Level(r.Scope))throw new ArgumentException("Override must refer to a broader-scope rule.");
        }
    }
    static bool Absolute(string? s)
    {
        if(s==null||!Text(s)||s.Any(c=>"*?\"<>|".Contains(c)))return false;
        return (s.StartsWith('/')&&!s.Contains('\\')||s.Length>3&&char.IsAsciiLetter(s[0])&&s[1]==':'&&s[2]=='\\'&&!s.Contains('/')&&!s[2..].Contains(':'))&&!s.Split(['/','\\']).Any(x=>x is "." or "..");
    }
    static bool Equal(string? a,string? b)=>a!=null&&b!=null&&StringComparer.Ordinal.Equals(a,b);
    static bool PathEqual(string? a,string? b,string os)=>a!=null&&b!=null&&(os=="windows"?StringComparer.OrdinalIgnoreCase:StringComparer.Ordinal).Equals(a,b);
    public static bool PathMatches(string? expected,string actual,string os,string? mode)
    {
        if(expected==null)return true;
        if(!Absolute(expected)||!Absolute(actual))return false;
        if(mode==null)return PathEqual(expected,actual,os);
        if(mode!="directory")return false;
        var separator=os=="windows"?'\\':'/';var root=expected.TrimEnd(separator)+separator;
        return actual.StartsWith(root,os=="windows"?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal);
    }
    public static bool Narrows(TrustRule child,TrustRule parent)
    {
        bool SameOrAdded(string? p,string? c)=>p==null||Equal(p,c);
        var subjects=parent.Subject==child.Subject||child.Subject=="account-and-process";
        return subjects&&child.Actions.All(parent.Actions.Contains)&&child.StartsUtc>=parent.StartsUtc&&child.ExpiresUtc<=parent.ExpiresUtc
            &&SameOrAdded(parent.Authority,child.Authority)&&SameOrAdded(parent.AccountId,child.AccountId)&&SameOrAdded(parent.AccountKind,child.AccountKind)&&SameOrAdded(parent.Executable,child.Executable)&&SameOrAdded(parent.Sha256,child.Sha256)
            &&(parent.ProcessMatch is LinuxKernelProcessMatch or LinuxNativeHashProcessMatch||child.ProcessMatch is LinuxKernelProcessMatch or LinuxNativeHashProcessMatch?parent.ProcessMatch==child.ProcessMatch:
                parent.Subject=="account"||parent.ProcessMatch=="event-path"||child.ProcessMatch==null)
            &&SameOrAdded(parent.Signer,child.Signer)&&SameOrAdded(parent.Publisher,child.Publisher)&&SameOrAdded(parent.ParentExecutable,child.ParentExecutable)&&
            (parent.Path==null||child.Path!=null&&(parent.PathMatch=="directory"?PathMatches(parent.Path,child.Path,parent.OperatingSystem??child.OperatingSystem??"linux","directory")||PathEqual(parent.Path,child.Path,parent.OperatingSystem??child.OperatingSystem??"linux"):
                child.PathMatch==null&&Equal(parent.Path,child.Path)))&&SameOrAdded(parent.OperatingSystem,child.OperatingSystem)&&(parent.Subject=="process"||parent.AccountPrincipal==child.AccountPrincipal)&&
            (parent.ProcessInstance==null||parent.ProcessInstance==child.ProcessInstance)
            &&Restrictions(child.Disposition).Popup<=Restrictions(parent.Disposition).Popup&&Restrictions(child.Disposition).Response<=Restrictions(parent.Disposition).Response
            &&(parent.Disposition=="informational"||child.Disposition!="informational");
    }
    static (int Popup,int Response) Restrictions(string disposition)=>disposition switch{"popup-only"=>(1,0),"response-only"=>(0,1),"popup-and-response" or "log-only"=>(1,1),_=>(0,0)};
    public static TrustDecision Evaluate(IReadOnlyList<TrustRule> rules,TrustContext context,DateTimeOffset now,IReadOnlySet<string>? approvedBroadening=null)
    {
        Validate(rules);
        TrustDecision Normal(string reason,string[]? matches=null)=>new(1,"normal",false,false,"normal",matches?.Take(64).ToArray()??[],reason){MatchedRuleCount=matches?.Length??0};
        var kernel=context.ProcessBasis==LinuxKernelTrustBinding.Basis;var nativeHash=context.ProcessBasis==LinuxNativeHashBinding.Basis;
        if(context.Actor==null||!context.Actor.Verified||context.Actions is not {Length:>0}||context.Actions.Any(x=>!Actions.Contains(x))||context.OperatingSystem is not ("windows" or "linux" or "macos")||!Text(context.Host,128)||!Text(context.Organization,128)||
            (kernel?context.OperatingSystem!="linux"||!Hash(context.Actor.Sha256)||!Absolute(context.Actor.Executable)||!context.Actions.SequenceEqual(["open"]):nativeHash?context.OperatingSystem!="linux"||!Hash(context.Actor.Sha256)||context.Actor.Executable!=null||context.Actions.Any(a=>a is not ("read" or "write" or "append")):!Absolute(context.Path)))return Normal("Unverified or unsupported event evidence.");
        if(context.ProtectedEvent)return Normal("Protected security event.");
        if(context.ObservedUtc>now.AddMinutes(5))return Normal("Event timestamp is not trusted.");
        bool Scope(TrustRule r)=>r.Scope switch{"organization"=>r.ScopeId==context.Organization,"group"=>r.ScopeId==context.Group,"host"=>r.ScopeId==context.Host,_=>false};
        var candidates=rules.Where(r=>r.Enabled&&Scope(r)&&r.StartsUtc<=now).ToList();
        // Caller supplies separately stored administrator approvals; rule payload cannot self-approve.
        var eligible=new List<TrustRule>();
        foreach(var r in candidates.OrderBy(r=>Level(r.Scope)))
        {
            if(r.Scope=="organization"||r.Disposition=="normal"){eligible.Add(r);continue;}
            var parent=eligible.SingleOrDefault(x=>x.Id==r.ParentRuleId);
            if(parent!=null&&Narrows(r,parent)||approvedBroadening?.Contains(r.Id)==true)eligible.Add(r);
        }
        var overridden=eligible.Where(r=>r.ParentRuleId!=null).Select(r=>r.ParentRuleId!).ToHashSet(StringComparer.Ordinal);
        // Explicit normal-alert rules always win, including an overridden ancestor.
        // An expired narrowing override cannot silently reactivate a broader ancestor grant.
        var matches=eligible.Where(r=>r.ExpiresUtc>now&&r.StartsUtc<=context.ObservedUtc&&r.ExpiresUtc>context.ObservedUtc&&(!overridden.Contains(r.Id)||r.Disposition=="normal")&&(!context.Actions.Contains("delete")||r.Disposition is "normal" or "log-only")&&Matches(r,context)).ToArray();
        var ids=matches.Select(r=>r.Id).Order(StringComparer.Ordinal).ToArray();
        if(matches.Length==0)return Normal("No approved rule matched.");
        if(matches.Any(r=>r.Disposition=="normal"))return Normal("Normal-alert rule takes precedence.",ids);
        if(matches.All(r=>r.Disposition=="log-only"))return new(1,"log-only",true,true,"informational",ids.Take(64).ToArray(),"Whitelisted actions: evidence retained; alerts and automatic response suppressed."){MatchedRuleCount=ids.Length};
        // Historical suppression dispositions remain readable, but cannot mute alerts or response.
        // Any conflict with a severity-only exception therefore retains normal alerting.
        var informational=matches.All(r=>r.Disposition=="informational");
        return new(1,informational?"informational":"normal",false,false,informational?"informational":"normal",ids.Take(64).ToArray(),"Approved scoped severity evaluation; full evidence and response retained."){MatchedRuleCount=ids.Length};
    }
    static bool Matches(TrustRule r,TrustContext c)
    {
        var a=c.Actor;
        // Never reinterpret an old host-path/Audit rule as a task-root rule.
        if((r.ProcessMatch==LinuxKernelProcessMatch)!=(c.ProcessBasis==LinuxKernelTrustBinding.Basis))return false;
        if((r.ProcessMatch==LinuxNativeHashProcessMatch)!=(c.ProcessBasis==LinuxNativeHashBinding.Basis)&&!(c.ProcessBasis==LinuxNativeHashBinding.Basis&&r.Subject=="account"&&r.AccountPrincipal!=null))return false;
        if(!c.Actions.All(r.Actions.Contains)||r.OperatingSystem!=null&&r.OperatingSystem!=c.OperatingSystem||!PathMatches(r.Path,c.Path,c.OperatingSystem,r.PathMatch)||r.ProcessInstance!=null&&(c.ProcessInstance?.IsValid()!=true||r.ProcessInstance!=c.ProcessInstance))return false;
        var user=r.AccountPrincipal switch{"process-owner"=>c.ProcessOwner,"effective-user"=>c.EffectiveUser,_=>a};
        var account=user is {Verified:true}&&Account(user.AccountKind,user.AccountId)&&Equal(r.AccountKind,user.AccountKind)&&Equal(r.Authority,user.Authority)&&Equal(r.AccountId,user.AccountId);
        var process=(r.ProcessMatch==LinuxNativeHashProcessMatch||PathEqual(r.Executable,a.Executable,c.OperatingSystem))&&(r.ProcessMatch=="event-path"||a.Sha256!=null&&r.Sha256!.Equals(a.Sha256,StringComparison.OrdinalIgnoreCase))&&
            ((r.Signer==null&&r.Publisher==null)||a.SignatureVerified)&&(r.Signer==null||Equal(r.Signer,a.Signer))&&(r.Publisher==null||Equal(r.Publisher,a.Publisher))&&(r.ParentExecutable==null||PathEqual(r.ParentExecutable,a.ParentExecutable,c.OperatingSystem));
        if(r.Subject switch{"account"=>!account,"process"=>!process,"account-and-process"=>!account||!process,"account-or-process"=>!account&&!process,_=>true})return false;
        return true;
    }
}
