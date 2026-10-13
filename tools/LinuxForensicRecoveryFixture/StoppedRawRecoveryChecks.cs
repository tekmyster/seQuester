using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class StoppedRawRecoveryChecks
{
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
    internal static async Task Child(string root,string sensor,byte[] native,string cut)
    {
        var epoch=JsonNode.Parse(native)!["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var journal=new LinuxForensicJournal(root,sensor);journal.AdmitOwnedRuntime();
        using var bank=new LinuxRawIngressReserve(Path.Combine(root,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch,5,true);
        var session=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
        bank.Commit(native,new LinuxSourceWorkBarrier().Current,DateTimeOffset.UtcNow);journal.RecordSourceNoController(session,null,DateTimeOffset.UtcNow);
        File.WriteAllText(Path.Combine(root,"session.txt"),session);
        if(cut=="before-seal")Environment.Exit(73);
        bank.SealInput(DateTimeOffset.UtcNow);if(cut=="sealed")Environment.Exit(73);
        journal.RecoverStoppedRaw(session,bank);if(cut=="indexed")Environment.Exit(73);
        journal.PromoteStoppedCanonicalUnavailable(session,bank,bank.Entries[0]);if(cut=="promoted")Environment.Exit(73);
        var spool=new EventSpool(Path.Combine(root,"spool"),sensor);await using var pipeline=new ForensicPipeline(sensor,root,Console.Error.WriteLine);
        await journal.DeliverStoppedRaw(session,bank,pipeline,spool,p=>{if(p==cut)Environment.Exit(73);});
        throw new Exception("Owned restart cut not reached");
    }
    internal static async Task Run(string root,string sensor,byte[] native,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh recovery fixture directory required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label)
        {try{action();}catch(Exception e)when(e is IOException or InvalidDataException or InvalidOperationException or ArgumentException or SqliteException){Check(true,label);return;}throw new Exception("Expected rejection: "+label);}
        var sample=JsonNode.Parse(native)!;var epoch=sample["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var dir=Path.Combine(root,"unindexed");var path=Path.Combine(dir,"bank");var collector=Guid.NewGuid().ToString("N");string session;string bankHash;string sealHash;
        LinuxRawIngressReserve.Entry[] receipts;var observations=new List<AgentEvent>();
        using(var journal=new LinuxForensicJournal(dir,sensor))
        {
            journal.AdmitOwnedRuntime();using var bank=new LinuxRawIngressReserve(path,sensor,collector,epoch,9,true);
            session=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;var barrier=new LinuxSourceWorkBarrier();
            Sql(dir,"CREATE TRIGGER owned_index_failure BEFORE INSERT ON source_ingress BEGIN SELECT RAISE(FAIL,'owned index failure'); END;");
            for(int i=1;i<=7;i++)
            {
                var n=sample.DeepClone();n["cookie"]=(ulong)i;var raw=JsonSerializer.SerializeToUtf8Bytes(n);
                var entry=bank.Commit(raw,barrier.Current,DateTimeOffset.UtcNow).Entry!;
                observations.Add(LinuxKernelDecoder.Decode(raw,sensor,collector,entry.Sequence,entry.ReceivedUtc));
                if(i==1)Reject(()=>journal.IndexRawIngress(session,bank,entry),"SQL failure occurs after exact raw event commitment");
            }
            bank.Commit("invalid diagnostic"u8.ToArray(),barrier.Current,DateTimeOffset.UtcNow);
            var foreign=sample.DeepClone();foreign["providerEpoch"]=sample["providerEpoch"]!.GetValue<ulong>()^1UL;
            bank.Commit(JsonSerializer.SerializeToUtf8Bytes(foreign),barrier.Current,DateTimeOffset.UtcNow);receipts=bank.Entries;
            Check(journal.CountUnindexedRaw(session,bank)==9&&journal.ReadDeferredCanonical(session,bank).Length==0,"physical inventory sees all nine receipts despite empty canonical index");
            Reject(()=>journal.RecoverStoppedRaw(session,bank),"live source cannot claim historical recovery");
            journal.RecordSourceNoController(session,null,DateTimeOffset.UtcNow);journal.ReleaseOwnedRuntime(session);
            Reject(()=>journal.RecoverStoppedRaw(session,bank),"missing input seal remains explicitly unresolved");
            var seal=bank.SealInput(DateTimeOffset.UtcNow);
            Check(seal.Entries==9&&seal.LastDeliveryId==receipts[^1].DeliveryId&&bank.SealInput(DateTimeOffset.UtcNow)==seal,"seal binds exact final prefix and preserves its first timestamp");
            Reject(()=>bank.Commit(native,barrier.Current,DateTimeOffset.UtcNow),"sealed bank cannot append another receipt");
            Reject(()=>bank.RecordBoundary("LATE",barrier.Current,null,null),"sealed emergency boundary cannot be rewritten");
            bank.Dispose();bankHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(path,"raw-ingress-v3.bin"))));
            sealHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(path,"raw-ingress-v3.bin.sealed.json"))));
            Reject(journal.AdmitOwnedRuntime,"unindexed raw blocks new owned source after exact terminal proof");
            Reject(()=>journal.RecoverStoppedRaw(session),"historical indexing database failure remains visible without writing raw bank");
        }
        // Actual journal and raw handles are closed and reconstructed here.
        using(var journal=new LinuxForensicJournal(dir,sensor))
        {
            Reject(journal.AdmitOwnedRuntime,"restart does not overlook physical raw backlog");
            Sql(dir,"DROP TRIGGER owned_index_failure;");journal.RecoverStoppedRaw(session);
            using(var bank=LinuxRawIngressReserve.OpenReadOnly(path,sensor,collector,epoch,9))
            {
                Check(!bank.PhysicalAllocationEstablished&&bank.Entries.SequenceEqual(receipts)&&bank.SealedInput?.Entries==9,"read-only recovery preserves exact receipts without claiming physical admission");
                Check(journal.CountUnindexedRaw(session,bank)==0,"sealed physical prefix is fully indexed after retry");
                Reject(()=>bank.Commit(native,new LinuxSourceWorkBarrier().Current,DateTimeOffset.UtcNow),"read-only replay grants no append capability");
            }
            Check((long)Sql(dir,"SELECT count(*) FROM canonical_events;")! ==7&&(long)Sql(dir,"SELECT count(*) FROM source_ingress WHERE classification IN ('RAW_INVALID','RAW_FOREIGN_EPOCH');")! ==2,"valid observations and two raw-only diagnostics remain distinct");
            Reject(journal.AdmitOwnedRuntime,"indexed but undelivered canonical observations still block admission");
            var spool=new EventSpool(Path.Combine(dir,"spool"),sensor);var errors=new List<string>();
            await using(var pipeline=new ForensicPipeline(sensor,dir,errors.Add))Check(await journal.DeliverStoppedRaw(session,pipeline,spool),"read-only recovery drains through existing bounded common pipeline");
            Check(errors.Count==0&&journal.Pending().Length==0&&spool.Count==14,"seven original/completion pairs recovered without eviction");
            foreach(var original in observations)
            {
                var work=journal.Read(original.EventId);var completed=JsonSerializer.Deserialize<AgentEvent>(work.Completion!)!;
                Check(EventSpool.Encode(work.Observation).AsSpan().SequenceEqual(EventSpool.Encode(original))&&completed.User==original.User&&completed.Process==original.Process&&completed.ProcessId==original.ProcessId,"original user/process/PID/event context survives recovery: "+original.EventId);
                Check(completed.Forensics!.ActorExecutable.Sha256==null&&completed.Forensics.ActorExecutable.LinuxAcquisition!.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SOURCE_STOPPED_BEFORE_NATIVE_ADMISSION"&&journal.ReadNativePin(original.EventId)==null&&work.DropState=="not-attempted","recovery fabricates no actor copy, hash or native invocation: "+original.EventId);
            }
            journal.AdmitOwnedRuntime();Reject(journal.AdmitOwnedRuntime,"completed inventory still enforces one runtime owner");journal.ReleaseOwnedRuntime(null);
            Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(path,"raw-ingress-v3.bin"))))==bankHash&&Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(path,"raw-ingress-v3.bin.sealed.json"))))==sealHash,"read-only inventory/recovery never changes bank or input seal");
        }
        foreach(var variant in new[]{"missing-seal","corrupt-seal","missing-bank","changed-bank","changed-index","foreign-collector","unknown-classification"})
        {
            var caseRoot=Path.Combine(root,variant);using var journal=new LinuxForensicJournal(caseRoot,sensor);journal.AdmitOwnedRuntime();
            var bankDir=Path.Combine(caseRoot,"bank");using(var bank=new LinuxRawIngressReserve(bankDir,sensor,Guid.NewGuid().ToString("N"),epoch,5,true))
            {
                var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);var entry=bank.Commit("raw diagnostic"u8.ToArray(),new LinuxSourceWorkBarrier().Current,DateTimeOffset.UtcNow).Entry!;
                journal.IndexRawIngress(source.Id,bank,entry);journal.RecordSourceNoController(source.Id,null,DateTimeOffset.UtcNow);bank.SealInput(DateTimeOffset.UtcNow);journal.ReleaseOwnedRuntime(source.Id);
            }
            var rawPath=Path.Combine(bankDir,"raw-ingress-v3.bin");var sealPath=rawPath+".sealed.json";
            if(variant=="missing-seal")File.Move(sealPath,sealPath+".retained");
            if(variant=="corrupt-seal")File.WriteAllText(sealPath,"{}");
            if(variant=="missing-bank")File.Move(rawPath,rawPath+".retained");
            if(variant=="changed-bank"){using var stream=new FileStream(rawPath,FileMode.Open,FileAccess.Write);stream.Position=4096;stream.WriteByte(0);stream.Flush(true);}
            if(variant=="changed-index")Sql(caseRoot,"UPDATE source_ingress SET entry=X'7B7D';");
            if(variant=="foreign-collector")Sql(caseRoot,"UPDATE source_lifecycle SET collector='22222222222222222222222222222222';");
            if(variant=="unknown-classification")
            {
                Reject(()=>Sql(caseRoot,"UPDATE source_ingress SET classification='INDEX_PREDECESSOR_PENDING';"),"transient predecessor result is not a persistable index classification");
                Sql(caseRoot,"PRAGMA ignore_check_constraints=ON; UPDATE source_ingress SET classification='FUTURE_PENDING'; PRAGMA ignore_check_constraints=OFF;");
            }
            Reject(journal.AdmitOwnedRuntime,"unavailable or changed historical evidence cannot admit source: "+variant);
            Reject(journal.AdmitOwnedRuntime,"failed inventory releases admission check and remains rejected: "+variant);
        }
        foreach(var mode in new[]{"capacity","callback","delivery-failure"})
        {
            var caseRoot=Path.Combine(root,mode);using var journal=new LinuxForensicJournal(caseRoot,sensor);journal.AdmitOwnedRuntime();string id;
            using(var bank=new LinuxRawIngressReserve(Path.Combine(caseRoot,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch,5,true))
            {
                id=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
                bank.Commit(native,new LinuxSourceWorkBarrier().Current,DateTimeOffset.UtcNow);journal.RecordSourceNoController(id,null,DateTimeOffset.UtcNow);bank.SealInput(DateTimeOffset.UtcNow);journal.ReleaseOwnedRuntime(id);
            }
            var spool=new EventSpool(Path.Combine(caseRoot,"spool"),sensor);var errors=new List<string>();
            using var blocked=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            await using var pipeline=new ForensicPipeline(sensor,caseRoot,errors.Add);
            if(mode=="capacity")
            {
                for(int i=0;i<32;i++)
                {
                    var item=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"read","/owned/canary","fixture-user","/owned/actor",321,"Unrelated producer");
                    pipeline.Submit(item,new(PreserveActorOnAlert:false),_=>{},_=>{blocked.Set();if(!release.Wait(TimeSpan.FromSeconds(30)))throw new TimeoutException("Owned unrelated release missing");},ActorLease.Unavailable(item,"fixture"));
                }
                try
                {
                    Check(blocked.Wait(TimeSpan.FromSeconds(10)),"unrelated producer actually holds all shared permits");
                    Check(!await journal.DeliverStoppedRaw(id,pipeline,spool).WaitAsync(TimeSpan.FromSeconds(10)),"recovery returns pending without waiting on unrelated shared capacity");
                    Check(journal.Pending().Length==1&&spool.Count==0,"full common pipeline retains original durable work");Reject(journal.AdmitOwnedRuntime,"pending delivery cannot be bypassed by new source");
                }
                finally{release.Set();}
                // Disposal waits only this test pipeline's actual jobs.
                await pipeline.DisposeAsync();await using var retryPipeline=new ForensicPipeline(sensor,caseRoot,errors.Add);
                Check(await journal.DeliverStoppedRaw(id,retryPipeline,spool)&&spool.Count==2,"delivery resumes after shared capacity returns");
            }
            else if(mode=="callback")
            {
                var delivery=journal.DeliverStoppedRaw(id,pipeline,spool,p=>{if(p=="work-finished"){blocked.Set();if(!release.Wait(TimeSpan.FromSeconds(30)))throw new TimeoutException("Owned callback release missing");}});
                try{Check(blocked.Wait(TimeSpan.FromSeconds(10)),"owned delivery reached persisted work before actual callback return");Check(!delivery.IsCompleted&&journal.Pending().Length==0,"durable done row does not substitute for submitted callback completion");}
                finally{release.Set();}
                Check(await delivery&&spool.Count==2,"recovery finishes after actual owned callback returns");
            }
            else
            {
                Check(!await journal.DeliverStoppedRaw(id,pipeline,spool,p=>{if(p=="completion-spooled")throw new IOException("Owned recovery delivery interruption");}),"delivery failure remains pending after callback return");
                Check(errors.Count==1&&journal.Pending().Length==1,"actual delivery error is retained with durable work");
                Check(await journal.DeliverStoppedRaw(id,pipeline,spool)&&spool.Count==2,"retry uses exact existing original/completion pair");
            }
        }
        {
            var caseRoot=Path.Combine(root,"source-ownership");using var journal=new LinuxForensicJournal(caseRoot,sensor);journal.AdmitOwnedRuntime();
            var ids=new List<string>();var events=new List<string>();
            for(int i=0;i<2;i++)
            {
                using var bank=new LinuxRawIngressReserve(Path.Combine(caseRoot,"bank-"+i),sensor,Guid.NewGuid().ToString("N"),epoch,5,true);
                var id=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;ids.Add(id);
                var entry=bank.Commit(native,new LinuxSourceWorkBarrier().Current,DateTimeOffset.UtcNow).Entry!;
                events.Add(journal.IndexRawIngress(id,bank,entry).CanonicalEventId!);journal.RecordSourceNoController(id,null,DateTimeOffset.UtcNow);bank.SealInput(DateTimeOffset.UtcNow);
                if(i==1)journal.PromoteStoppedCanonicalUnavailable(id,bank,entry);
            }
            journal.ReleaseOwnedRuntime(null);
            var spoolA=new EventSpool(Path.Combine(caseRoot,"spool-a"),sensor);var spoolB=new EventSpool(Path.Combine(caseRoot,"spool-b"),sensor);var errors=new List<string>();
            using var blocked=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            await using var pipelineA=new ForensicPipeline(sensor,caseRoot,errors.Add);await using var pipelineB=new ForensicPipeline(sensor,caseRoot,errors.Add);
            var deliveryA=journal.DeliverStoppedRaw(ids[0],pipelineA,spoolA,p=>{if(p=="work-finished"){blocked.Set();if(!release.Wait(TimeSpan.FromSeconds(30)))throw new TimeoutException("Owned session callback release missing");}});
            try
            {
                Check(blocked.Wait(TimeSpan.FromSeconds(10)),"source A holds its actual submitted callback while B has independent pending work");
                Check(!journal.Read(events[1]).Done&&spoolB.Count==0,"A recovery never submits B pending work");
                Reject(()=>journal.RecoverStoppedRaw(ids[0]),"second recovery handle for same source rejected while first callback is pending");
                try{await journal.DeliverStoppedRaw(ids[0],pipelineB,spoolB);throw new Exception("Duplicate source delivery admitted");}
                catch(InvalidOperationException){Check(true,"second same-source delivery cannot double-submit prepared event");}
                Check(await journal.DeliverStoppedRaw(ids[1],pipelineB,spoolB).WaitAsync(TimeSpan.FromSeconds(10)),"B recovery completes independently without awaiting A callback");
                Check(journal.Read(events[1]).Done&&spoolB.Count==2&&!deliveryA.IsCompleted,"concurrent recovery has separate source-specific completions");
                Reject(journal.AdmitOwnedRuntime,"all durable rows done still cannot bypass retained recovery callback owner");
            }
            finally{release.Set();}
            Check(await deliveryA&&spoolA.Count==2&&errors.Count==0,"A returns only after its actual callback; each source delivered one pair");
            Check(spoolA.Peek().Events.All(e=>(e.Forensics!.RelatedEventId??e.EventId)==events[0])&&spoolB.Peek().Events.All(e=>(e.Forensics!.RelatedEventId??e.EventId)==events[1]),"event output never crosses recovery source ownership");
            journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
        }
        foreach(var cut in new[]{"before-seal","sealed","indexed","promoted","completion-spooled"})
        {
            var caseRoot=Path.Combine(root,"cut-"+cut);var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(StoppedRawRecoveryChecks).Assembly.Location);
            foreach(var arg in new[]{"stopped-raw-child",seedPath,caseRoot,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual process exit at recovery cut: "+cut+" "+await stdout+await stderr);
            using var journal=new LinuxForensicJournal(caseRoot,sensor);var id=File.ReadAllText(Path.Combine(caseRoot,"session.txt"));
            Reject(journal.AdmitOwnedRuntime,"restarted source stays disabled before reconciliation: "+cut);
            if(cut=="before-seal"){Reject(()=>journal.RecoverStoppedRaw(id),"restart cannot invent missing historical input seal");continue;}
            var spool=new EventSpool(Path.Combine(caseRoot,"spool"),sensor);var errors=new List<string>();
            await using(var pipeline=new ForensicPipeline(sensor,caseRoot,errors.Add))Check(await journal.DeliverStoppedRaw(id,pipeline,spool),"actual restart recovers original raw evidence: "+cut);
            Check(errors.Count==0&&spool.Count==2&&journal.Pending().Length==0,"restart delivers exactly one pair: "+cut);
            journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
        }
        var result=new{Passed=true,Checks=checks,Events=7,RawOnly=2,CrashCuts=5,Schema=12,Scope="Injected database failure after physical record commit; seal/read-only recovery, actual process exits, shared-capacity and owned-callback delivery gates; no native method or production activation."};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
