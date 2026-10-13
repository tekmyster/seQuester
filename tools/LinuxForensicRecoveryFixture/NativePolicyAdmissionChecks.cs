using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativePolicyAdmissionChecks
{
    internal static void Run(string root)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh root required");Directory.CreateDirectory(root);
        var checks=new List<string>();void Check(bool value,string label){if(!value)throw new Exception(label);checks.Add(label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is InvalidDataException or IOException or ArgumentException or InvalidOperationException){Check(true,label);return;}throw new Exception("Accepted: "+label);}
        const string server="https://qualification.invalid/";var sensor=Guid.NewGuid().ToString("N");using var key=RSA.Create(3072);var pub=key.ExportSubjectPublicKeyInfo();
        var now=DateTimeOffset.UtcNow;long ticks=100000;var journal=new LinuxForensicJournal(root,sensor);
        LinuxNativePolicyAdmission Owner()=>new(journal,server,sensor,pub,()=>now,()=>ticks,1000);
        var owner=Owner();
        SignedNativePolicy Make(string challenge,long revision=1,long monitoringRevision=1,string? group=null,int interval=15,string actor="qa")
        {
            var policy=new TrustPolicy(revision,"enforce",[],[],actor,now.AddMinutes(-1)){Version=3};
            return SignedNativePolicy.Sign(new(server,sensor,challenge,now,now.AddMinutes(2),new(sensor,group,policy,policy.Digest(),now,now.AddMinutes(2)),new(group,monitoringRevision,new(interval))),key);
        }
        try
        {
            Reject(()=>Owner(),"same-process second policy owner is rejected");
            Reject(()=>journal.Dispose(),"journal lock cannot close while a policy owner exists");
            journal.AdmitOwnedRuntime();Reject(()=>owner.Dispose(),"policy owner cannot release while native runtime ownership is admitted");
            Reject(()=>Owner(),"failed owner release retains exclusive admission");journal.ReleaseOwnedRuntime(null);
            Reject(()=>owner.Accept(Make(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)))),"unsolicited signed policy has no live root challenge");
            var challenge=owner.Request();var response=Make(challenge);Check(owner.Accept(response).SensorId==sensor,"signed policy committed through existing owned intake journal");
            Reject(()=>owner.Accept(response),"consumed in-memory challenge cannot accept a second policy");
            challenge=owner.Request();var abandoned=Make(challenge);var replacement=owner.Request();Reject(()=>owner.Accept(abandoned),"new request invalidates prior unconsumed challenge");
            response=Make(replacement,revision:2,monitoringRevision:2);Check(owner.Accept(response).Trust.Policy.Revision==2,"higher exact trust and monitoring revisions accepted");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:1,monitoringRevision:2)),"signed but lower trust revision refused");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:2,monitoringRevision:2,actor:"changed")),"same trust revision with different content refused");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:2,monitoringRevision:1)),"signed lower monitoring revision within group refused");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:2,monitoringRevision:2,interval:30)),"same monitoring revision with changed content refused");
            challenge=owner.Request();response=Make(challenge,revision:2,monitoringRevision:2);ticks+=30001;Reject(()=>owner.Accept(response),"monotonic challenge deadline bounds a still-valid signature");
            challenge=owner.Request();response=Make(challenge,revision:2,monitoringRevision:2);ticks--;Reject(()=>owner.Accept(response),"monotonic clock regression refuses admission");ticks+=100;
            challenge=owner.Request();response=Make(challenge,revision:3,monitoringRevision:3);
            Reject(()=>owner.Accept(response,point=>{if(point=="native-policy-before-commit")throw new IOException("Injected commit failure");}),"failed durable write returns no admitted snapshot");
            Check(owner.Accept(response).Trust.Policy.Revision==3,"exact response can retry after transaction rollback");
            challenge=owner.Request();response=Make(challenge,revision:4,monitoringRevision:4);
            Reject(()=>owner.Accept(response,point=>{if(point=="native-policy-after-commit")throw new IOException("Injected return failure");}),"failure after commit does not return activation authority");
            Reject(()=>owner.Accept(response),"durably consumed challenge is refused after unknown commit return");
            challenge=owner.Request();Check(owner.Accept(Make(challenge,revision:4,monitoringRevision:4)).Trust.Policy.Revision==4,"new challenge recovers after unknown commit outcome without rollback");
            challenge=owner.Request();var beforeRestart=Make(challenge,revision:4,monitoringRevision:4);owner.Dispose();
            Reject(()=>owner.Request(),"disposed policy owner cannot create challenges");
            Reject(()=>owner.Accept(beforeRestart),"disposed policy owner cannot accept a policy");owner.Dispose();
            journal.Dispose();journal=new(root,sensor);owner=Owner();
            Reject(()=>owner.Accept(beforeRestart),"process restart cannot recover volatile challenge authority from persisted policy");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:3,monitoringRevision:4)),"trust revision floor survives journal restart");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:4,monitoringRevision:3)),"monitoring floor survives journal restart");
            var group=Guid.NewGuid().ToString("N");challenge=owner.Request();Check(owner.Accept(Make(challenge,revision:4,monitoringRevision:1,group:group)).Monitoring.GroupId==group,"new server-assigned group has its own monitoring revision floor");
            challenge=owner.Request();Reject(()=>owner.Accept(Make(challenge,revision:4,monitoringRevision:3)),"returning to earlier group cannot reset its remembered floor");
            owner.Dispose();using var different=RSA.Create(3072);Reject(()=>new LinuxNativePolicyAdmission(journal,server,sensor,different.ExportSubjectPublicKeyInfo()),"pinned key change requires explicit migration of root policy history");
            Reject(()=>new LinuxNativePolicyAdmission(journal,"https://different.invalid/",sensor,pub),"server identity change cannot reuse root policy history");
            owner=Owner();Check(owner.Request().Length==64,"failed constructor did not retain admission lease");
            challenge=owner.Request();response=Make(challenge,revision:5,monitoringRevision:5);
            Reject(()=>owner.Accept(response,point=>{if(point=="native-policy-after-commit")ticks+=30001;}),"slow durable commit cannot return authority after monotonic challenge deadline");
            challenge=owner.Request();response=Make(challenge,revision:6,monitoringRevision:6);
            Reject(()=>owner.Accept(response,point=>{if(point=="native-policy-after-commit")now=now.AddMinutes(3);}),"expired policy after durable commit cannot activate a source");
            File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count,Details=checks,Scope="Local owned SQLite admission component, real RSA signatures, monotonic/replay and transaction faults; no installed service or native activation"}));Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks.Count}));
        }
        finally{owner.Dispose();journal.Dispose();}
    }
}
