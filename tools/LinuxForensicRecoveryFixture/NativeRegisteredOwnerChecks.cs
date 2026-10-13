using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class NativeRegisteredOwnerChecks
{
    internal static async Task Run(string configFile)
    {
        if(!OperatingSystem.IsLinux())throw new PlatformNotSupportedException();
        var input=JsonSerializer.Deserialize<OwnedRuntimeNativeChecks.Config>(File.ReadAllBytes(configFile))!;
        var checks=new List<string>();var cases=new List<object>();
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
        const string sensor="11111111111111111111111111111111";
        foreach(var scenario in new[]{"registration","submission","closure"})
        {
            var parent=Path.Combine(Path.GetDirectoryName(input.Root)!,"owner-failure-"+scenario);
            if(Directory.Exists(parent))throw new IOException("Fresh failure case required");Directory.CreateDirectory(parent,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            var config=input with{Root=Path.Combine(parent,"evidence")};using var key=RSA.Create(3072);
            Directory.CreateDirectory(config.Root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            using var journal=new LinuxForensicJournal(config.Root,sensor);var spool=new EventSpool(Path.Combine(config.Root,"spool"),sensor);
            await using var pipeline=new ForensicPipeline(sensor,config.Root,Console.Error.WriteLine);
            using var policyOwner=new LinuxNativePolicyAdmission(journal,"https://qualification.invalid/",sensor,key.ExportSubjectPublicKeyInfo());
            var now=DateTimeOffset.UtcNow;var trust=input.Trust!;
            var envelope=SignedNativePolicy.Sign(new("https://qualification.invalid/",sensor,policyOwner.Request(),now,now.AddMinutes(5),
                new(sensor,null,trust,trust.Digest(),now,now.AddMinutes(5)),new(null,1,MonitoringPolicy.Default)),key);
            var policy=new LinuxNativeSourcePolicy(policyOwner,policyOwner.AcceptLease(envelope),sensor,new());
            var faults=new HashSet<string>();
            using var module=new NativeRuntimeModuleFixture(config,key.ExportSubjectPublicKeyInfo(),point=>
            {
                if((scenario=="registration"&&point.StartsWith("RECEIPT:")&&point.EndsWith("-source-registered.json")||
                    scenario!="registration"&&point=="RUNTIME_SUBMISSION"||scenario=="closure"&&point.StartsWith("PUBLISHED:")&&point.EndsWith("-source-closed.json"))&&faults.Add(point))
                    throw new IOException("Owned registration qualification fault");
            });
            bool registrationFailed=false;
            try{module.Owner.StartRegisteredSource(journal,pipeline,spool,new(),policy,Console.Error.WriteLine);}
            catch(IOException)when(scenario=="registration"){registrationFailed=true;}
            var source=module.Owner.RegisteredSource??throw new Exception("Source registration was lost");
            Check(registrationFailed==(scenario=="registration"),scenario+": actual registration boundary result");
            Check(module.Owner.State=="LoadedOwned"&&Directory.Exists("/sys/module/sq_actor_lease"),scenario+": failed or unstarted source retains loaded module owner");
            bool refused=false;try{module.Owner.UnloadBeforeSource();}catch(InvalidOperationException){refused=true;}
            Check(refused,scenario+": pre-source unload forbidden after registration");
            bool closeFailed=false;
            try{await module.Owner.StopSourceAndUnloadAsync();}catch(IOException)when(scenario=="closure"){closeFailed=true;}
            Check(closeFailed==(scenario=="closure"),scenario+": actual post-publication failure result");
            if(closeFailed)
            {
                Check(module.Owner.State=="LoadedOwned"&&module.Owner.UnloadReturn==null,scenario+": failed close receipt preserves module before native unload");
                module.Owner.RetryReceipt();
            }
            await module.Close();var outcome=await source.Completion;
            Check(source.Completion.IsCompletedSuccessfully&&ReferenceEquals(outcome.NativeClosure,source.NativeClosure)&&source.NativeClosure?.RuntimeId==source.RuntimeId,scenario+": exact registered source owns positive closure");
            Check(outcome.RawRecords==0&&outcome.Child==null&&outcome.Session==null&&spool.Count==0,scenario+": no child, native records, source session or events created");
            Check(source.NativeClosure!.NoRunEntered==(scenario!="registration"),scenario+": scheduling failure distinguished from actual stop-before-launch drain");
            Check(module.Owner.State=="UnloadVerifiedAbsent"&&module.Owner.UnloadReturn is {Result:0,Error:0}&&!Directory.Exists("/sys/module/sq_actor_lease"),scenario+": normal unload completed after exact source closure");
            var documents=Directory.GetFiles(module.Owner.EvidenceDirectory,"*.json").Select(p=>JsonDocument.Parse(File.ReadAllBytes(p))).ToArray();
            try{Check(documents.Count(x=>x.RootElement.GetProperty("Step").GetString()=="source-closed")==1&&documents.Count(x=>x.RootElement.GetProperty("Step").GetString()=="unload-return")==1,scenario+": one close receipt and one actual unload across retry");}
            finally{foreach(var document in documents)document.Dispose();}
            try{await source.Started;throw new Exception("Unexpected native activation");}catch(Exception e)when(e is IOException or InvalidOperationException){}
            cases.Add(new{Scenario=scenario,Root=parent,module.Owner.OwnerId,module.Owner.EvidenceDirectory,source.RuntimeId,Outcome=outcome,Faults=faults});
        }
        var result=new{Passed=true,Checks=checks.Count,Details=checks,Cases=cases};
        File.WriteAllBytes(Path.Combine(Path.GetDirectoryName(input.Root)!,"REGISTERED-FAILURES.json"),JsonSerializer.SerializeToUtf8Bytes(result));
        Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
