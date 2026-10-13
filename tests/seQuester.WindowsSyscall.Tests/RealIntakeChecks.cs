using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using System.Text.Json;

internal static class RealIntakeChecks
{
    internal static int Run(byte[] raw,byte[] intake)
    {
        if(intake.Length!=9*3584)throw new InvalidDataException("Expected nine actual source/retained-target/record transport frames");
        var checks=0;void Check(bool ok,string message){if(!ok)throw new Exception(message);checks++;}
        var sensor=Guid.NewGuid().ToString("N");var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","actual-syscall-intake-"+Guid.NewGuid().ToString("N"));
        var journal=new WindowsSyscallJournal(directory,sensor);using var spool=new EventSpool(directory,sensor);var instances=new HashSet<Guid>();
        for(var i=0;i<9;i++){
            var frame=intake.AsSpan(i*3584,3584);var source=WindowsSyscallSource.SourceInfo(frame[..56].ToArray());instances.Add(source.Instance);
            var target=frame.Slice(56,3120).ToArray();var record=frame.Slice(3176,408).ToArray();Check(record.AsSpan().SequenceEqual(raw.AsSpan(i*696,408)),"actual peek equals independent native/truth record");
            var o=WindowsSyscallSource.Observation(record,source,target);Check(o.IsValid()&&o.LostRecords==0,"actual driver intake decodes with no loss");
            Check(o.NativeTargetPath?.Contains("owned-files",StringComparison.OrdinalIgnoreCase)==true&&o.TargetStatus.State=="captured","actual retained target name comes from owned files");
            var e=journal.Put(record,o);using var actor=ActorLease.Capture(e,sensor);var collector=new ForensicCollector(sensor,directory);
            var f=collector.Complete(e,actor,collector.Begin(e,actor),new());var id=Guid.NewGuid().ToString("N");var pair=new PreparedForensicPublication(e with{Forensics=f},e with{EventId=id,ObservedUtc=DateTimeOffset.UtcNow,Source="Forensic enrichment",Operation="Actor forensic evidence partially collected",Forensics=collector.LinkCompletion(f,id)});
            journal.Prepare(pair);spool.Enqueue(pair.Original);spool.Enqueue(pair.Completion);journal.Complete(e.EventId);
            Check(f.Process.Owner.Sid=="S-1-5-18"&&f.Process.EffectiveThreadContext?.Sid==(i<8?"S-1-5-19":"S-1-5-18"),"actual intake owner/effective identities survive durable reporting");
            Check(f.Observation.Outcome==(i<8?"failed":"success")&&f.Observation.OsStatus==o.Native.ReturnStatus,"actual failed return survives forensic report");
            Check(f.ActorExecutable.Sha256==null&&f.ActorExecutable.HashStatus.State=="unavailable","without acquisition provider no executable is fabricated");
        }
        Check(instances.Count==1&&spool.Count==18,"single native lifetime and all nine original/completion pairs persisted");
        Console.WriteLine(JsonSerializer.Serialize(new{ActualIntakeChecks=checks,ActualNativeTransportRecords=9,TargetReplies="actual native retained-file-object queries",ManagedReplayVerified=true,Artifacts=directory}));return checks;
    }
}
