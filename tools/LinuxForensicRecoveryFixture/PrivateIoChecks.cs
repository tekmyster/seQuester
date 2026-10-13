using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;

static class PrivateIoChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,LinuxActorSnapshot snapshot)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh private I/O fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        foreach(var stage in new[]{"allocation-intent-committed","private-allocation-complete","admitted-private-verified","admitted-receipt-committed","prepared-original","prepared-completion"})
        {
            var directory=Path.Combine(root,stage);var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
            using var journal=new LinuxForensicJournal(directory,sensor);
            using var bank=new LinuxRawIngressReserve(Path.Combine(directory,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch,5,true);
            var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);var barrier=new LinuxSourceWorkBarrier();
            var entry=bank.Commit(raw,barrier.Current,DateTimeOffset.UtcNow).Entry!;var observation=journal.IndexRawIngress(source.Id,bank,entry).CanonicalEvent!;
            journal.CommitObservation(raw,observation,new());var id=observation.EventId;
            using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            var bound=OperatingSystem.IsLinux()?45:5;
            void Pause(string point){if(point!=stage)return;entered.Set();if(!release.Wait(TimeSpan.FromSeconds(bound+15)))throw new TimeoutException("Owned private I/O pause was not released");}
            LinuxSnapshotAdmission? admission=null;var prepared=stage.StartsWith("prepared-",StringComparison.Ordinal);
            if(!stage.StartsWith("allocation-",StringComparison.Ordinal)&&stage!="private-allocation-complete")
            {
                admission=journal.AdmitSnapshot(id,snapshot.NativeStatus);
                admission.BeginRead(observation,snapshot.NativeStatus);admission.Append(snapshot.Bytes.Span);admission.Finish(snapshot.NativeStatus);
                if(prepared)journal.CommitAdmittedSnapshot(admission);
            }
            var collector=new ForensicCollector(sensor,Path.Combine(directory,"prepared"));
            RansomFree.Contracts.AgentEvent Original(LinuxForensicJournal.Work work)
            {using var actor=journal.RestoreActor(id);return work.Observation with{Forensics=collector.Begin(work.Observation,actor)};}
            if(stage=="prepared-completion")journal.PrepareOriginal(id,Original);
            var worker=Task.Run(()=>
            {
                if(stage is "allocation-intent-committed" or "private-allocation-complete")admission=journal.AdmitSnapshot(id,snapshot.NativeStatus,Pause);
                else if(stage=="prepared-original")journal.PrepareOriginal(id,work=>{Pause(stage);return Original(work);});
                else if(stage=="prepared-completion")journal.PrepareCompletion(id,work=>
                {
                    Pause(stage);var original=JsonSerializer.Deserialize<RansomFree.Contracts.AgentEvent>(work.Original!)!;
                    using var actor=journal.RestoreActor(id);var completed=collector.Complete(original,actor,original.Forensics!,work.Policy);
                    return original with{EventId=work.CompletionId,Forensics=collector.LinkCompletion(completed,work.CompletionId)};
                });
                else journal.CommitAdmittedSnapshot(admission!,Pause);
            });
            Task? concurrent=null;
            try
            {
                Check(entered.Wait(TimeSpan.FromSeconds(bound)),"private phase paused: "+stage);
                concurrent=Task.Run(()=>
                {
                    var next=bank.Commit(raw,barrier.Current,DateTimeOffset.UtcNow).Entry!;
                    var indexed=journal.IndexRawIngress(source.Id,bank,next);
                    if(indexed.Status!="DUPLICATE"||indexed.CanonicalEventId!=id)throw new Exception("Concurrent raw indexing failed");
                    barrier.Fault("OWNED_PRIVATE_IO_PAUSE",DateTimeOffset.UtcNow);
                    journal.TransitionSource(source.Id,"CONTINUITY_FAULTED",new("OWNED_PRIVATE_IO_PAUSE",DateTimeOffset.UtcNow,null,"0",null,null,null,[]));
                    journal.FinalizeSourceWorkUnavailable(source.Id,"OWNED_UNRELATED_FINALIZER");
                    try{journal.Dispose();throw new Exception("Owner lock released while private work remains active");}catch(InvalidOperationException){}
                });
                await concurrent.WaitAsync(TimeSpan.FromSeconds(bound));
                Check(!worker.IsCompleted&&bank.Entries.Length==2&&journal.ReadSource(source.Id).State=="CONTINUITY_FAULTED","raw intake/index/fault progress while private operation remains blocked: "+stage);
                Check(prepared?journal.Read(id).Acquisition?.Status.State=="captured":journal.Read(id).Acquisition==null,"unrelated finalizer cannot overwrite the owned capture: "+stage);
            }
            finally
            {
                release.Set();await worker;if(concurrent!=null)await concurrent;admission?.Dispose();
            }
            if(stage is "allocation-intent-committed" or "private-allocation-complete")
                Check(journal.ReadSnapshotIntent(id)?.State=="write-intent"&&journal.Read(id).Acquisition==null,"private allocation returns against same intent without invented acquisition: "+stage);
            else
            {
                using var actor=journal.RestoreActor(id);
                Check(actor.Image!=null&&actor.LinuxAcquisition?.SnapshotSha256==snapshot.Sha256.ToUpperInvariant(),"returned private copy still verifies exact original actor bytes: "+stage);
            }
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Real private file allocation/hash with paused tasks and concurrent raw/index/fault work; native actor bytes use immutable fixture seed, no kernel controller or runtime activation"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
