using RansomFree.Contracts;
internal static class TrustChecks
{
    public static void Run(Action<bool,string> check)
    {
        var now=DateTimeOffset.UtcNow;var hash=new string('a',64);
        var context=new TrustContext("org","finance","host","linux","/decoy/payroll",["read"],now,new("host","1000","/usr/bin/reader",hash,Verified:true,AccountKind:"uid"));
        var global=new TrustRule(Guid.NewGuid().ToString("N"),"organization","org","process",["read"],"informational",now.AddDays(-1),now.AddDays(5)){Enabled=true,Executable="/usr/bin/reader",Sha256=hash};
        TrustDecision Run(TrustRule[] rules,TrustContext? e=null,IReadOnlySet<string>? approvals=null)=>TrustEvaluation.Evaluate(rules,e??context,now,approvals);
        check(Run([global]) is {Severity:"informational",SuppressPopup:false,SuppressResponse:false},"exact global read exception matches");
        check(Run([global],context with{Actions=["write"]}).Disposition=="normal","read trust does not suppress write");
        check(Run([global],context with{Actor=context.Actor with{Verified=false}}).Disposition=="normal","unknown actor never trusted");
        check(Run([global],context with{Actor=context.Actor with{Sha256=null}}).Disposition=="normal","missing hash never falls back to filename");
        check(Run([global],context with{ProtectedEvent=true}).Disposition=="normal","health and integrity evidence protected");
        check(Run([global with{Actions=["delete"]}],context with{Actions=["delete"]}).Disposition=="normal","deletion security event cannot be suppressed");
        check(Run([global with{Enabled=false}]).Disposition=="normal","rules disabled by default and explicitly disabled fail closed");
        var child=global with{Id=Guid.NewGuid().ToString("N"),Scope="group",ScopeId="finance",ParentRuleId=global.Id,Subject="account-and-process",AccountKind="uid",Authority="host",AccountId="1000",Disposition="informational"};
        check(TrustEvaluation.Narrows(child,global)&&Run([global,child]).Severity=="informational","group narrows actor and response disposition");
        check(Run([global,child],context with{Actor=context.Actor with{AccountId="1001"}}).Disposition=="normal","group narrowing replaces broad ancestor for unmatched actor");
        check(Run([global,child],context with{Group="engineering"}).Severity=="informational","unrelated group inherits its global rule");
        check(Run([global,child with{ExpiresUtc=now.AddMinutes(-1)}]).Disposition=="normal","expired narrowing cannot reactivate broad suppression");
        var broad=child with{Subject="process",AccountKind=null,Authority=null,AccountId=null,Executable="/usr/bin/other"};
        check(Run([global,broad],context with{Actor=context.Actor with{Executable="/usr/bin/other"}}).Disposition=="normal","unapproved broadening rejected");
        check(Run([global,broad],context with{Actor=context.Actor with{Executable="/usr/bin/other"}},new HashSet<string>{broad.Id}).Severity=="informational","separate privileged broadening approval required");
        var normal=global with{Id=Guid.NewGuid().ToString("N"),Disposition="normal"};
        check(Run([global,normal]).Disposition=="normal","normal alert wins conflicting exception");
        check(Run([global,global with{Id=Guid.NewGuid().ToString("N"),Disposition="response-only"}]).Disposition=="normal","obsolete suppression conflicts retain normal alerting");
        check(Run([global with{Signer="Publisher"}]).Disposition=="normal","missing verified signature is not trusted");
        var invalid=false;try{Run([child]);}catch(ArgumentException){invalid=true;}check(invalid,"orphaned override rejected");
        invalid=false;try{Run([child with{ParentRuleId=null,AccountId="friendly-name"}]);}catch(ArgumentException){invalid=true;}check(invalid,"display-name-only account rule rejected");
        foreach(var old in new[]{"popup-only","response-only","popup-and-response"})check(Run([global with{Disposition=old}]) is {Disposition:"normal",SuppressPopup:false,SuppressResponse:false,RetainEvidence:true},"historical suppression setting fails toward alerting: "+old);
        check(Run([global]).RetainEvidence,"every disposition retains evidence");
    }
}
