using System.Text.Json;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

// Actual controlled-source composition probe. The external qualification
// harness supplies independently observed actor identities and hashes.
internal static class OwnedRuntimeNativeChecks
{
    internal sealed record Config(string Root,LinuxControlledSourceRuntime.Qualification Runtime)
    {public TrustPolicy? Trust {get;init;}}
    internal static async Task Run(string configPath,bool inspectActorMatching=false,bool observeSourceHealth=false,bool evaluateKernelTrust=false,bool signedKernelTrust=false,bool ownedModule=false,bool ioOperations=false)
    {
        var config=JsonSerializer.Deserialize<Config>(File.ReadAllBytes(configPath))!;
        if(!OperatingSystem.IsLinux()||Directory.Exists(config.Root)||!config.Root.StartsWith(ownedModule?"/var/lib/sequester-owned-runtime-":"/var/tmp/sequester-owned-runtime-",StringComparison.Ordinal)||
            Path.GetDirectoryName(config.Runtime.Directory)!=config.Root)throw new ArgumentException("Fresh owned native qualification root required");
        const string sensor="11111111111111111111111111111111";
        var startupWatch=Stopwatch.StartNew();var startupStages=new List<object>();void Stage(string name)=>startupStages.Add(new{Name=name,ElapsedMilliseconds=startupWatch.Elapsed.TotalMilliseconds});
        if(ownedModule)Directory.CreateDirectory(config.Root,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        using var journal=new LinuxForensicJournal(config.Root,sensor);
        Stage("journal-opened");
        var spool=new EventSpool(Path.Combine(config.Root,"spool"),sensor);
        await using var pipeline=new ForensicPipeline(sensor,config.Root,Console.Error.WriteLine);
        Stage("spool-pipeline-opened");
        using var policyKey=signedKernelTrust?RSA.Create(3072):null;
        using var policyOwner=signedKernelTrust?new LinuxNativePolicyAdmission(journal,"https://qualification.invalid/",sensor,policyKey!.ExportSubjectPublicKeyInfo()):null;
        Stage("policy-owner-opened");
        LinuxNativeSourcePolicy? signedPolicy=null;
        TrustPolicyCache? trustCache=null;
        if(evaluateKernelTrust)
        {
            if(config.Trust is not {Version:3,Mode:"enforce"} trusted)throw new InvalidDataException("Explicit qualification policy v3 required");trusted.Validate();
            var now=DateTimeOffset.UtcNow;
            if(signedKernelTrust)
            {
                var envelope=SignedNativePolicy.Sign(new("https://qualification.invalid/",sensor,policyOwner!.Request(),now,now.AddMinutes(5),
                    new(sensor,null,trusted,trusted.Digest(),now,now.AddMinutes(5)),new(null,1,MonitoringPolicy.Default)),policyKey!);
                signedPolicy=new(policyOwner,policyOwner.AcceptLease(envelope),sensor,new());
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"signed-policy-public-key.der"),policyKey!.ExportSubjectPublicKeyInfo());
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"signed-policy-envelope.json"),JsonSerializer.SerializeToUtf8Bytes(envelope));
            }
            else
            {
                var directory=Path.Combine(config.Root,"trust-cache");Directory.CreateDirectory(directory);EvidenceStore.EnsurePrivate(directory);
                trustCache=new(directory,sensor,"https://qualification.invalid");trustCache.Save(new(sensor,null,trusted,trusted.Digest(),now,now.AddHours(1)),now);
            }
        }
        else if(config.Trust!=null)throw new InvalidDataException("Policy requires explicit kernel trust qualification mode");
        Stage("policy-prepared");
        using var module=ownedModule?new NativeRuntimeModuleFixture(config,policyKey!.ExportSubjectPublicKeyInfo()):null;
        var runtime=module==null?LinuxControlledSourceRuntime.StartForQualification(config.Runtime,journal,pipeline,spool,sensor,new(),Console.Error.WriteLine,trustCache:trustCache,signedPolicy:signedPolicy):
            module.Owner.StartRegisteredSource(journal,pipeline,spool,new(),signedPolicy!,Console.Error.WriteLine);
        void Reply(object value){Console.WriteLine(JsonSerializer.Serialize(value));Console.Out.Flush();}
        try{await runtime.Started;Stage("native-source-active");Reply(new{Ready=true,runtime.Phase,runtime.Session,StartupStages=startupStages,RuntimeDirectory=runtime.EvidenceDirectory,ModuleOwnerId=module?.Owner.OwnerId,ServiceHealth=ownedModule?runtime.ObserveServiceHealth():null});}
        catch(Exception e){Reply(new{Ready=false,Error=e.GetType().Name,Message=e.Message});}
        var aborted=false;
        while(true)
        {
            var command=await Console.In.ReadLineAsync();
            if(command=="abort-qualification"){aborted=true;break;}
            if(command is null or "stop")break;
            if(command=="retry"){runtime.RetryReceipts();Reply(new{RetryRequested=true});continue;}
            if(command=="expire-signed-policy"&&signedKernelTrust)
            {
                // Qualification-only signer/control channel. The installed
                // source never creates a private key or accepts this command.
                var now=DateTimeOffset.UtcNow;var trusted=config.Trust!;
                var replacement=SignedNativePolicy.Sign(new("https://qualification.invalid/",sensor,policyOwner!.Request(),now,now.AddSeconds(2),
                    new(sensor,null,trusted,trusted.Digest(),now,now.AddSeconds(2)),new(null,1,MonitoringPolicy.Default)),policyKey!);
                var next=signedPolicy!.AcceptReplacement(replacement);var admittedExpiry=next.Current().ExpiresUtc;
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"expiry-policy-envelope.json"),JsonSerializer.SerializeToUtf8Bytes(replacement));
                Reply(new{ExpiryAdmitted=true,ExpiresUtc=admittedExpiry});continue;
            }
            if(command=="request-stop"){runtime.RequestStop("QUALIFICATION_STOP_REQUESTED");Reply(new{StopRequested=true});continue;}
            if(command=="match-source"&&observeSourceHealth)
            {
                var captured=new List<AgentEvent>();
                using(var read=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(config.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString()))
                {
                    read.Open();using var query=read.CreateCommand();query.CommandText="SELECT original FROM work WHERE done=1 ORDER BY rowid";using var result=query.ExecuteReader();
                    while(result.Read())captured.Add(JsonSerializer.Deserialize<AgentEvent>((byte[])result[0])!);
                }
                var health=new List<object>();
                foreach(var original in captured)
                {
                    using var actor=journal.RestoreActor(original.EventId);var result=runtime.ObserveMatchSource(original,actor);
                    if(result.Evidence==null)throw new InvalidDataException("Actual owned source sample failed: "+result.Reason);
                    health.Add(new{original.EventId,Result=result});
                }
                if(health.Count==0)throw new InvalidDataException("No completed actors for live-source sample");
                EvidenceDurability.SaveNew(Path.Combine(config.Root,"source-health.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=true,Observations=health,
                    Scope="Actual owned source/map/child sampled before stop; historical source facts only, no policy authority or alert suppression."}));
                Reply(new{SourceHealthSampled=true,Observations=health.Count});continue;
            }
            if(command=="check-admission")
            {
                try{journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);Reply(new{AdmissionAllowed=true});}
                catch(InvalidOperationException e){Reply(new{AdmissionAllowed=false,Reason=e.Message});}
                continue;
            }
            if(command!="status")throw new InvalidDataException("Unknown owned qualification command");
            using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(config.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());c.Open();
            using var q=c.CreateCommand();q.CommandText="SELECT event_id,observation,done FROM work ORDER BY rowid";using var rows=q.ExecuteReader();
            var work=new List<object>();while(rows.Read())
            {
                var e=JsonSerializer.Deserialize<AgentEvent>((byte[])rows[1])!;
                work.Add(new{e.EventId,e.User,e.Process,e.ProcessId,Done=rows.GetInt64(2)==1});
            }
            Reply(new{runtime.Phase,runtime.Session,Completed=runtime.Completion.IsCompleted,Pending=journal.Pending().Length,Spool=spool.Count,Work=work});
        }
        runtime.RequestStop("QUALIFICATION_STOP_REQUESTED");
        // No timeout substitutes for actual native/controller completion.
        var outcome=await runtime.Completion;
        if(module!=null)await module.Close();
        if(signedPolicy!=null)EvidenceDurability.SaveNew(Path.Combine(config.Root,"signed-policy-final.json"),JsonSerializer.SerializeToUtf8Bytes(new{
            Version=1,UnavailableReason=signedPolicy.UnavailableReason,CanObserve=signedPolicy.Observe()!=null,SourceOutcome=outcome.State,
            Scope="Actual source stopped; retained signature/history do not revive policy authority"}));
        var originals=new List<AgentEvent>();var completions=new List<AgentEvent>();
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(config.Root,"linux-forensic-intake/journal.db"),Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString()))
        {
            c.Open();using var q=c.CreateCommand();q.CommandText="SELECT original,completion FROM work ORDER BY rowid";using var rows=q.ExecuteReader();
            while(rows.Read())
            {
                if(!rows.IsDBNull(0))originals.Add(JsonSerializer.Deserialize<AgentEvent>((byte[])rows[0])!);
                if(!rows.IsDBNull(1))completions.Add(JsonSerializer.Deserialize<AgentEvent>((byte[])rows[1])!);
            }
        }
        File.WriteAllBytes(Path.Combine(config.Root,"events.json"),JsonSerializer.SerializeToUtf8Bytes(new{Originals=originals,Completions=completions}));
        if(ioOperations&&!aborted)
        {
            var returns=originals.Where(e=>e.Attribution?.LinuxKernel?.IoObservation is {Schema:3,Stage:2}).ToArray();
            if(returns.Length==0)throw new InvalidDataException("No completed native I/O observations");
            foreach(var result in returns)
            {
                var pair=journal.ReadIoPair(outcome.Session!,result.Attribution!.LinuxKernel!);
                var completion=completions.Single(e=>e.Forensics!.RelatedEventId==result.EventId);
                var link=completion.Forensics!.LinuxIoPair;
                if(pair.Status!="paired"||link is not {Status:"paired",ActorStatus.State:"captured",ActorSha256:not null}||
                    link.EntryEventId!=pair.EntryEventId||!LinuxKernelEvidence.Matches(completion))
                    throw new InvalidDataException("I/O return lacks exact durable pair and captured actor reference: "+result.EventId);
            }
            File.WriteAllBytes(Path.Combine(config.Root,"io-pairs.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=true,Returns=returns.Length,
                Scope="Actual owned managed runtime, exact immutable entry/result linkage and verified captured actor reference. Central upload is a separate gate."}));
        }
        if(aborted)
        {
            Reply(new{Closed=outcome.Close=="CLOSE_RETURNED_OK",Outcome=outcome,Originals=originals.Count,Completions=completions.Count,Spool=spool.Count,AbortedQualification=true});
            return; // Actual close above is mandatory; abort is never a test pass.
        }
        if(inspectActorMatching)
        {
            if(observeSourceHealth&&!File.Exists(Path.Combine(config.Root,"source-health.json")))throw new InvalidDataException("No actual live-source health samples");
            // After source shutdown, verify private descriptor facts only.
            // Closed-source recovery cannot mint a live whitelist decision.
            var matches=new List<object>();
            foreach(var original in originals)
            {
                using var actor=journal.RestoreActor(original.EventId);
                var match=actor.AcquiredLinuxMatchEvidence(original);
                if(match.Evidence==null)throw new InvalidDataException("Actual Linux private descriptor match failed: "+match.Reason);
                if((evaluateKernelTrust?original.Trust is not {Version:3,LinuxKernelBinding:not null}||original.Trust.LinuxKernelBinding.Matches(original)!=true:original.Trust!=null)||original.Attribution!.LinuxKernel!.WhitelistEligible||original.Forensics!.ActorExecutable.LinuxAcquisition!.WhitelistEligible)
                    throw new InvalidDataException("Matching facts unexpectedly acquired policy authority");
                var saved=actor.SnapshotFile!;actor.SnapshotFile=saved with{ChangeMarker=saved.ChangeMarker+":different"};
                var wrongIdentity=actor.AcquiredLinuxMatchEvidence(original);actor.SnapshotFile=saved;
                if(wrongIdentity.Evidence!=null)throw new InvalidDataException("Wrong private descriptor identity accepted");
                actor.Dispose();var closed=actor.AcquiredLinuxMatchEvidence(original);
                if(closed.Evidence!=null)throw new InvalidDataException("Closed private descriptor accepted");
                var afterStop=observeSourceHealth?runtime.ObserveMatchSource(original,actor):null;
                if(afterStop!=null&&(afterStop.Evidence!=null||afterStop.Reason!="LINUX_SOURCE_NOT_ACTIVE"))throw new InvalidDataException("Closed source created new live health evidence");
                matches.Add(new{original.EventId,Facts=match.Evidence,match.Reason,WrongIdentityReason=wrongIdentity.Reason,ClosedReason=closed.Reason,ClosedSourceReason=afterStop?.Reason});
            }
            if(matches.Count==0)throw new InvalidDataException("No actual actor copies to qualify");
            File.WriteAllBytes(Path.Combine(config.Root,"actor-matching.json"),JsonSerializer.SerializeToUtf8Bytes(new{Passed=true,Matches=matches,
                Scope="Actual Linux verified private descriptors; matching facts after clean stop, not live-source eligibility or policy suppression."}));
        }
        Reply(new{Closed=outcome.Close=="CLOSE_RETURNED_OK",Outcome=outcome,Originals=originals.Count,Completions=completions.Count,Spool=spool.Count,ServiceHealth=ownedModule?runtime.ObserveServiceHealth():null});
    }
}
