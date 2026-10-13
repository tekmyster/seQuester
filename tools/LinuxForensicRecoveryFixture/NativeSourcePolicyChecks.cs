using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativeSourcePolicyChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh source policy fixture required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is InvalidDataException or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        const string sensor="11111111111111111111111111111111",origin="https://qualification.invalid/";var now=DateTimeOffset.UtcNow;long ticks=100000;
        using var key=RSA.Create(3072);using var journal=new LinuxForensicJournal(root,sensor);using var owner=new LinuxNativePolicyAdmission(journal,origin,sensor,key.ExportSubjectPublicKeyInfo(),()=>now,()=>ticks,1000);
        SignedNativePolicy Make(long revision=1,long monitoring=1,string? group=null)
        {
            var policy=new TrustPolicy(revision,"enforce",[],[],"signed source",now.AddMinutes(-1)){Version=3};
            return SignedNativePolicy.Sign(new(origin,sensor,owner.Request(),now,now.AddMinutes(2),new(sensor,group,policy,policy.Digest(),now,now.AddMinutes(2)),new(group,monitoring,MonitoringPolicy.Default)),key);
        }
        var initial=owner.AcceptLease(Make());var binding=new LinuxNativeSourcePolicy(owner,initial,sensor,new());
        var observed=binding.Observe()!;Check(binding.StillCurrent(observed),"live signed source observation matches exact current admitted lease");
        binding.RequireSource(sensor,new());Check(true,"source identity and forensic policy match signed monitoring assignment");
        Reject(()=>binding.RequireSource(Guid.NewGuid().ToString("N"),new()),"different sensor cannot consume binding");
        Reject(()=>binding.RequireSource(sensor,new(PreserveActorOnAlert:false)),"different forensic preservation policy cannot consume binding");
        using(var secondJournal=new LinuxForensicJournal(Path.Combine(root,"other-owner"),sensor))
        using(var other=new LinuxNativePolicyAdmission(secondJournal,origin,sensor,key.ExportSubjectPublicKeyInfo()))
            Reject(()=>new LinuxNativeSourcePolicy(other,initial,sensor,new()),"foreign policy owner cannot adopt a current lease");
        var context=new TrustContext("server",null,sensor,"linux","/srv/canary",["open"],now,new());
        Check(LinuxNativeSourcePolicy.Evaluate(observed,context,now).Mode=="enforce","signed assignment evaluates through existing trust rule engine");
        Check(LinuxNativeSourcePolicy.Evaluate(observed,context with{Host=Guid.NewGuid().ToString("N")},now).Mode=="pending","context mismatch retains alerts in pending policy state");
        var renewed=binding.AcceptReplacement(Make(2));Check(renewed.IsCurrent&&!initial.IsCurrent&&binding.UnavailableReason==null,"same monitoring assignment refreshes trust policy without stopping source");
        Check(!binding.StillCurrent(observed),"observation from prior lease cannot be sealed after signed refresh");
        var latest=binding.Observe()!;Check(latest.Snapshot.Trust.Policy.Revision==2&&binding.StillCurrent(latest),"new event observes exact refreshed revision");
        var invalid=Make(2) with{SignatureBase64=Convert.ToBase64String(new byte[384])};Reject(()=>binding.AcceptReplacement(invalid),"invalid signature cannot replace bound policy");
        Check(binding.StillCurrent(latest),"invalid signature leaves current signed observation usable");
        Reject(()=>binding.AcceptReplacement(Make(3,2)),"changed monitoring revision requires source stop and target revalidation");
        Check(binding.UnavailableReason=="LINUX_NATIVE_MONITORING_ASSIGNMENT_CHANGED"&&!binding.StillCurrent(latest)&&binding.Observe()==null,"changed monitoring assignment latches unavailable and cannot seal old exception");
        Reject(()=>binding.AcceptReplacement(Make(3,2)),"stopped binding cannot revive through refresh");
        var newLease=owner.AcceptLease(Make(3,2));binding=new(owner,newLease,sensor,new());observed=binding.Observe()!;
        ticks+=120000;Check(binding.UnavailableReason=="LINUX_NATIVE_POLICY_EXPIRED_OR_REVOKED"&&!binding.StillCurrent(observed),"monotonic expiry stops source even with frozen wall clock");ticks-=120000;
        Check(binding.Observe()==null,"stopped expiry state cannot revive when clock returns");
        newLease=owner.AcceptLease(Make(3,2));binding=new(owner,newLease,sensor,new());observed=binding.Observe()!;
        binding.Invalidate();Check(binding.UnavailableReason=="LINUX_NATIVE_POLICY_SOURCE_STOPPED"&&!newLease.IsCurrent&&!binding.StillCurrent(observed),"explicit source stop revokes its policy and historical seal");
        Reject(()=>binding.RequireSource(sensor,new()),"stopped source binding cannot be reused at startup");
        newLease=owner.AcceptLease(Make(3,2));binding=new(owner,newLease,sensor,new());observed=binding.Observe()!;
        Reject(()=>binding.AcceptReplacement(Make(2,2)),"signed lower revision rejected during replacement admission");
        Check(!newLease.IsCurrent&&binding.Observe()==null,"verified conflicting replacement leaves old exception revoked after failed commit");
        newLease=owner.AcceptLease(Make(3,2));binding=new(owner,newLease,sensor,new());
        Reject(()=>binding.AcceptReplacement(Make(4,1,Guid.NewGuid().ToString("N"))),"new group requires a separately validated source session");
        Check(binding.UnavailableReason=="LINUX_NATIVE_MONITORING_ASSIGNMENT_CHANGED","group replacement reports explicit assignment-change reason");
        // Exercise replacement during the actual signed-lease evaluation
        // boundary; old decisions cannot survive revocation or repeated churn.
        using(var raceJournal=new LinuxForensicJournal(Path.Combine(root,"refresh-races"),sensor))
        using(var raceOwner=new LinuxNativePolicyAdmission(raceJournal,origin,sensor,key.ExportSubjectPublicKeyInfo(),()=>now,()=>ticks,1000))
        {
            SignedNativePolicy RacePolicy(long revision)
            {
                var policy=new TrustPolicy(revision,"enforce",[],[],"refresh race",now.AddSeconds(-1)){Version=3};
                return SignedNativePolicy.Sign(new(origin,sensor,raceOwner.Request(),now,now.AddMinutes(2),new(sensor,null,policy,policy.Digest(),now,now.AddMinutes(2)),new(null,1,MonitoringPolicy.Default)),key);
            }
            var race=new LinuxNativeSourcePolicy(raceOwner,raceOwner.AcceptLease(RacePolicy(1)),sensor,new());var calls=0;
            var result=race.EvaluateCurrent(sample=>{calls++;if(calls==1)race.AcceptReplacement(RacePolicy(2));return sample.Snapshot.Trust.Policy.Revision.ToString();});
            Check(result=="2"&&calls==2,"refresh during evaluation discards old decision and evaluates newly admitted revision");
            calls=0;result=race.EvaluateCurrent(sample=>{calls++;if(calls==1)race.AcceptReplacement(RacePolicy(2));return "same-policy";});
            Check(result=="same-policy"&&calls==2,"identical-policy renewal is reevaluated under its new exact lease");
            calls=0;result=race.EvaluateCurrent(sample=>{calls++;race.AcceptReplacement(RacePolicy(2+calls));return "must-not-escape";});
            Check(result==null&&calls==2,"continuous replacement has a bounded retry and cannot return superseded decision");
            calls=0;result=race.EvaluateCurrent<string>(sample=>{calls++;return null;});
            Check(result==null&&calls==1,"unavailable evidence on unchanged current lease is not retried or fabricated");
            calls=0;result=race.EvaluateCurrent(sample=>{calls++;race.Invalidate();return "revoked";});
            Check(result==null&&calls==1,"stop during evaluation revokes result and prevents retry on stopped source");
            race=new(raceOwner,raceOwner.AcceptLease(RacePolicy(4)),sensor,new());calls=0;
            result=race.EvaluateCurrent(sample=>{calls++;ticks+=120000;return "expired";});
            Check(result==null&&calls==1,"monotonic expiry during evaluation never returns stale result");ticks-=120000;
            race=new(raceOwner,raceOwner.AcceptLease(RacePolicy(4)),sensor,new());calls=0;
            Reject(()=>race.EvaluateCurrent<string>(sample=>{calls++;throw new InvalidDataException("actual evidence failure");}),"evidence failure propagates for explicit collection diagnostics");
            Check(calls==1,"evidence exception is not replayed as a refresh retry");
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Actual signed SQLite policy admission, fixed source monitoring assignment and volatile observation lifetime; native runtime qualification remains separate"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count}));
    }
}
