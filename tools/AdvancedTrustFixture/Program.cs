using RansomFree.Contracts;
var n=0;void Check(bool ok,string label){if(!ok)throw new Exception(label);Console.WriteLine("PASS: "+label);n++;}
var now=DateTimeOffset.UtcNow;var host=Guid.NewGuid().ToString("N");var sha=new string('A',64);
var rule=new TrustRule(Guid.NewGuid().ToString("N"),"organization","server","process",["read"],"log-only",now.AddMinutes(-1),now.AddHours(1)){Enabled=true,Executable="C:\\QA\\Reader.exe",Sha256=sha,Path="C:\\QA\\Protected",PathMatch="directory",OperatingSystem="windows"};
var actor=new TrustActor(Authority:"QA",AccountId:"S-1-5-21-1-2-3-1000",Executable:rule.Executable,Sha256:sha,Verified:true,AccountKind:"sid");
var context=new TrustContext("server",null,host,"windows","C:\\QA\\Protected\\document.txt",["read"],now,actor);
bool Allows(TrustRule r,TrustContext? c=null)=>TrustEvaluation.Evaluate([r],c??context,now,new HashSet<string>{r.Id}).LogOnly;
Check(Allows(rule),"directory includes a direct child");Check(Allows(rule,context with{Path="c:\\qa\\protected\\sub\\child.txt"}),"Windows directory comparison respects case and descendant boundaries");
foreach(var path in new[]{"C:\\QA\\Protected-other\\document.txt","C:\\QA\\Protected\\..\\escape.txt","C:\\QA\\Protected","C:\\QA\\Elsewhere\\document.txt"})Check(!Allows(rule,context with{Path=path}),"directory rejects sibling, traversal and root-file ambiguity: "+path);
var linux=rule with{OperatingSystem="linux",Executable="/usr/bin/reader",Path="/protected"};var lc=context with{OperatingSystem="linux",Path="/protected/a",Actor=actor with{Executable="/usr/bin/reader"}};
Check(Allows(linux,lc),"Linux directory direct child matches");Check(!Allows(linux,lc with{Path="/Protected/a"}),"Linux remains case sensitive");Check(!Allows(linux,lc with{Path="/protectedness/a"}),"Linux directory prefix collision rejects");
var both=rule with{Subject="account-or-process",Path=null,PathMatch=null,Authority=actor.Authority,AccountId=actor.AccountId,AccountKind="sid"};
Check(Allows(both,context with{Actor=actor with{Sha256=new string('B',64)}}),"OR permits the selected user despite another binary");
Check(Allows(both,context with{Actor=actor with{AccountId="S-1-5-21-1-2-3-2000"}}),"OR permits verified executable despite another user");
Check(!Allows(both,context with{Actor=actor with{AccountId="S-1-5-21-1-2-3-2000",Sha256=new string('B',64)}}),"OR rejects when neither identity matches");
var owner=actor with{Authority=TrustIdentityContext.SidAuthority(actor.AccountId!),AccountId="S-1-5-21-1-2-3-1000"};var effective=owner with{AccountId="S-1-5-21-1-2-3-2000"};
var user=both with{Subject="account",Executable=null,Sha256=null,Authority=owner.Authority,AccountPrincipal="process-owner"};var uc=context with{ProcessOwner=owner,EffectiveUser=effective};
Check(Allows(user,uc),"explicit process owner matches independently of impersonation");Check(!Allows(user with{AccountPrincipal="effective-user"},uc),"effective-user selection cannot fall back to process owner");Check(!Allows(user,uc with{ProcessOwner=null}),"missing owner remains alerting");
var selector=new TrustProcessSelector(host,4242,"134000000000000000","windows:0123456789ABCDEF");var temporary=rule with{Scope="host",ScopeId=host,ProcessInstance=selector};
Check(Allows(temporary,context with{ProcessInstance=selector}),"temporary exception binds exact sensor/PID/start/capture epoch");
foreach(var changed in new[]{selector with{Pid=4243},selector with{StartKey="134000000000000001"},selector with{SourceEpoch="windows:FEDCBA9876543210"},selector with{SensorId=Guid.NewGuid().ToString("N")}})Check(!Allows(temporary,context with{ProcessInstance=changed}),"temporary exception rejects changed process identity: "+changed);
Check(!Allows(temporary),"missing process lifetime cannot match temporary rule");
void Invalid(TrustRule r,string text){try{TrustEvaluation.Validate([r]);throw new Exception("Accepted invalid rule: "+text);}catch(ArgumentException){Check(true,text);}}
Invalid(temporary with{ExpiresUtc=now.AddDays(2)},"temporary exception cannot exceed 24 hours");Invalid(temporary with{Scope="organization",ScopeId="server"},"temporary exception cannot apply to another sensor");Invalid(temporary with{ProcessMatch="event-path",Sha256=null},"temporary exception cannot weaken binary verification");
var policy=new TrustPolicy(1,"enforce",[rule],[],"qa",now){Version=4};policy.Validate();Check(true,"version 4 policy accepts advanced controls");try{(policy with{Version=3}).Validate();throw new Exception("Old parser accepted advanced rule");}catch(ArgumentException){Check(true,"version 3 explicitly rejects advanced controls");}
Check(!TrustEvaluation.Narrows(user with{Scope="host",ScopeId=host},user with{Scope="organization",AccountPrincipal=null}),"changing principal meaning requires fresh broader-scope approval");
var nativeHashRule=linux with{ProcessMatch=TrustEvaluation.LinuxNativeHashProcessMatch,Executable=null,Path=null,PathMatch=null,Actions=["write"]};var nativeContext=lc with{Path="[Path unavailable]",Actions=["write"],ProcessBasis=LinuxNativeHashBinding.Basis,Actor=new(Authority:host,AccountId:"1000",Sha256:sha,AccountKind:"uid",Verified:true)};
Check(Allows(nativeHashRule,nativeContext),"explicit Linux native SHA-256 matches without inventing a pathname");Check(!Allows(nativeHashRule,nativeContext with{Actor=nativeContext.Actor with{Sha256=new string('B',64)}}),"Linux native hash rejects changed executable bytes");
Check(!Allows(nativeHashRule,nativeContext with{ProcessBasis=null}),"claimed hash from another source cannot acquire native matching semantics");Check(!Allows(nativeHashRule,nativeContext with{Actions=["append"]}),"write whitelist does not implicitly permit append");
Invalid(nativeHashRule with{Executable="/usr/bin/reader"},"hash-only Linux mode cannot claim an unverified pathname");Invalid(nativeHashRule with{Actions=["delete"]},"unsupported Linux operation remains excluded");
Check(TrustIdentityContext.SidAuthority("malformed")==null,"malformed token SID cannot throw or create an identity authority");
StoreChecks.Run(Check);
ResponsePolicyChecks.Run(Check);
Console.WriteLine($"PASS: {n} advanced trust checks");
