using RansomFree.Contracts;
using RansomFree.Server;
internal static class UiSeed
{
    public static void Run(string root)
    {
        var path=Path.GetFullPath(root);
        if(!new[]{@"D:\Codex\RansomFree\whitelist-20260924\preview-",@"D:\Codex\RansomFree\forensics-20260924\preview-",@"D:\Codex\RansomFree\forensics-20260925\preview-",@"D:\Codex\RansomFree\forensic-gaps-20260925\preview-",Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","sequester-whitelist-20261011","preview-")}.Any(prefix=>path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))||!File.Exists(Path.Combine(path,"management.db")))throw new ArgumentException("Only an existing isolated feature preview is allowed.");
        var store=new Store(path);store.InitializeTrustStorage();var policy=store.ReadTrustPolicy();
        if(policy.Rules.Length==0)throw new InvalidOperationException("Create rules through the UI before replaying test events.");
        foreach(var os in new[]{"windows","linux"})
        {
            var endpoint=store.Enroll(new(store.CreateCode().Code,"Whitelist-"+os,"QA"))!;
            var rule=policy.Rules.Single(r=>r.OperatingSystem==os&&r.Enabled&&r.Subject=="process"&&r.Disposition=="log-only");
            var actor=new TrustActor(rule.Authority,rule.AccountId,os=="windows"?@"C:\QA\Reader.exe":"/usr/bin/qa-reader",Verified:true,AccountKind:rule.AccountKind);
            foreach(var scenario in os=="windows"?new[]{"read","write","wrong-hash","missing-hash","always-alert"}:new[]{"read","write"})
            {
                var action=scenario=="write"?"write":"read";
                var now=DateTimeOffset.UtcNow;var e=new AgentEvent(Guid.NewGuid().ToString("N"),now,action=="read"?"Content read (copy possible)":"Content written",os=="windows"?@"C:\QA\whitelist.txt":"/qa/whitelist.txt",os=="windows"?@"QA\alex":"uid:1000",actor.Executable,4242,os=="windows"?"Windows audit 4663":"Linux Audit")
                {Attribution=new(){Provider=os=="linux"?"Linux Audit":"Windows Security Audit",Level="Full attribution",Basis="Isolated UI fixture",Syscall=os=="linux"?action:null,UserId=os=="linux"?1000u:null,EventTimeCredentials=true,CompleteRecordSet=true}};
                if(scenario=="always-alert")e=e with{Path=@"C:\QA\block-override.txt"};
                // The UI process rules do not depend on account authority; the Linux evidence still binds UID to this sensor.
                if(os=="linux")actor=actor with{Authority=endpoint.EndpointId,AccountId="1000",AccountKind="uid"};
                else actor=actor with{Sha256=scenario=="wrong-hash"?new string('b',64):scenario=="missing-hash"?null:rule.Sha256};
                var context=new TrustContext("server",null,endpoint.EndpointId,os,e.Path,[action],now,actor);
                var verifiedHash=os=="windows"&&actor.Sha256!=null;
                e=e with{Trust=new EventTrust(2,os,null,actor,new(policy.Revision,policy.Digest(),"enforce",TrustEvaluation.Evaluate(policy.Rules,context,now,policy.ApprovedRules()))){EvaluatedUtc=now,ProcessBasis=verifiedHash?"windows-handle-locked-image-v1":"audit-executable-path-v1",ProcessCreatedUtc=verifiedHash?now.AddSeconds(-1):null,ImageCheckedUtc=verifiedHash?now:null}};
                store.Ingest(endpoint.EndpointId,new([e]));
            }
        }
        Console.WriteLine("Seeded isolated synthetic allowed reads, disallowed writes and same-path wrong/missing-hash controls under UI-published policy.");
    }
}
