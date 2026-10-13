using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativePolicyLeaseChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh native policy lease fixture required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception e)when(e is InvalidDataException or IOException or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        var now=DateTimeOffset.UtcNow;long ticks=100000,revision=0;var sensor=Guid.NewGuid().ToString("N");var group=Guid.NewGuid().ToString("N");
        using var key=RSA.Create(3072);using var journal=new LinuxForensicJournal(root,sensor);
        using var owner=new LinuxNativePolicyAdmission(journal,"https://qualification.invalid/",sensor,key.ExportSubjectPublicKeyInfo(),()=>now,()=>ticks,1000);
        SignedNativePolicy Response(string challenge,DateTimeOffset? issued=null)
        {
            var issue=issued??now;var policy=new TrustPolicy(++revision,"enforce",[],[],"lease-fixture",issue){Version=3};
            return SignedNativePolicy.Sign(new("https://qualification.invalid/",sensor,challenge,issue,issue.AddMinutes(2),
                new(sensor,group,policy,policy.Digest(),issue,issue.AddMinutes(2)),new(group,1,new(15){Allowlist=[new("/usr/bin/qa",new string('A',64))]})),key);
        }
        LinuxNativePolicyLease Fresh(){now=now.AddMinutes(3);ticks+=180000;return owner.AcceptLease(Response(owner.Request()));}
        var active=Fresh();Check(active.IsCurrent&&active.Current().SensorId==sensor,"actual admitted snapshot creates a live policy lease");
        var copy=active.Current();copy.Monitoring.Settings.Allowlist[0]=new("/usr/bin/untrusted",new string('B',64));
        Check(active.Current().Monitoring.Settings.Allowlist[0].Executable=="/usr/bin/qa","caller mutation cannot change retained signed policy bytes");
        ticks+=120000;Check(!active.IsCurrent,"monotonic expiry ends policy while wall time is frozen");ticks-=120000;
        Check(!active.IsCurrent,"expired policy cannot revive when clocks return");Reject(()=>active.Current(),"expired snapshot read refuses authority");
        active=Fresh();now=now.AddMinutes(2);Check(!active.IsCurrent,"forward wall-clock expiry revokes policy early");now=now.AddMinutes(-2);
        Check(!active.IsCurrent,"wall-clock rollback does not revive revoked policy");
        active=Fresh();ticks--;Check(!active.IsCurrent,"monotonic regression invalidates policy");ticks++;
        active=Fresh();now=now.AddSeconds(-31);Check(!active.IsCurrent,"wall-clock regression beyond issue tolerance invalidates policy");now=now.AddSeconds(31);
        active=Fresh();var old=active;active=owner.AcceptLease(Response(owner.Request()));Check(!old.IsCurrent&&active.IsCurrent,"new accepted signed policy revokes prior live policy instance");
        Reject(()=>owner.AcceptLease(Response(owner.Request()),p=>{if(p=="native-policy-before-commit")throw new IOException("Injected rollback");}),"verified replacement commit failure returns no new policy lease");
        Check(!active.IsCurrent,"verified failed replacement cannot leave prior whitelist active");active=Fresh();
        Reject(()=>owner.AcceptLease(Response(owner.Request()),p=>{if(p=="native-policy-after-commit")ticks+=30001;}),"commit crossing challenge deadline returns no policy lease");
        Check(!active.IsCurrent,"unknown slow replacement cannot leave prior whitelist active");active=Fresh();
        owner.Dispose();Check(!active.IsCurrent,"owner disposal invalidates its policy lease");
        Reject(()=>owner.AcceptLease(Response(new string('A',64))),"disposed owner cannot create a new lease");
        // A tolerated future issue time must not lengthen the monotonic maximum
        // beyond the lifetime signed by the server.
        using(var renewed=new LinuxNativePolicyAdmission(journal,"https://qualification.invalid/",sensor,key.ExportSubjectPublicKeyInfo(),()=>now,()=>ticks,1000))
        {
            active=renewed.AcceptLease(Response(renewed.Request(),now.AddSeconds(20)));Check(active.IsCurrent,"within-tolerance future-issued policy can be admitted");
            ticks+=120000;Check(!active.IsCurrent,"future-issued tolerance does not extend the signed monotonic lifetime");
        }
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Actual RSA/SQLite admission with deterministic monotonic and wall-clock lifetime tests; not yet attached to installed runtime"}));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count}));
    }
}
