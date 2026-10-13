using System.Text.Json;
using System.Text.Json.Nodes;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;
using Microsoft.Data.Sqlite;

static class DeferredWorkChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh deferred fixture root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        var sample=JsonNode.Parse(raw)!;var epoch=sample["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var journal=new LinuxForensicJournal(root,sensor);
        using var bank=new LinuxRawIngressReserve(Path.Combine(root,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch,9,true);
        var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);var barrier=new LinuxSourceWorkBarrier();var observations=new List<AgentEvent>();
        var next=journal.ReadDeferredCanonical(source.Id,bank,()=>
        {
          for(var i=1;i<=7;i++)
          {
            var node=sample.DeepClone();node["cookie"]=(ulong)i;var bytes=JsonSerializer.SerializeToUtf8Bytes(node);
            var entry=bank.Commit(bytes,barrier.Current,DateTimeOffset.UtcNow).Entry!;observations.Add(journal.IndexRawIngress(source.Id,bank,entry).CanonicalEvent!);
          }
        });
        Check(next.Length==4&&next.SequenceEqual(bank.Entries.Take(4)),"raw commits indexed between source verification and SQL query remain visible in deferred snapshot");
        Check(journal.ReadDeferredCanonical(source.Id,bank).SequenceEqual(next),"durable backlog returns bounded four-item prefix");
        try{journal.PromoteStoppedCanonicalUnavailable(source.Id,bank,next[0]);throw new Exception("Live admission bypass accepted");}
        catch(InvalidOperationException){Check(true,"live source cannot use historical unavailable shortcut");}
        Check(journal.Pending().Length==0&&observations.All(e=>journal.ReadNativePin(e.EventId)==null),"reading backlog grants no work or native authority");
        barrier.Fault("OWNED_DEFERRED_STOP",DateTimeOffset.UtcNow);
        journal.TransitionSource(source.Id,"CONTINUITY_FAULTED",new("OWNED_DEFERRED_STOP",DateTimeOffset.UtcNow,null,"0",null,null,null,[]));
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString()))
        {
            c.Open();using var q=c.CreateCommand();q.CommandText="CREATE TRIGGER owned_deferred_failure BEFORE UPDATE ON work WHEN NEW.acquisition IS NOT NULL BEGIN SELECT RAISE(FAIL,'owned outcome failure'); END;";q.ExecuteNonQuery();
            try{journal.PromoteStoppedCanonicalUnavailable(source.Id,bank,next[0]);throw new Exception("Failed outcome transaction accepted");}
            catch(SqliteException){Check(true,"deferred outcome transaction failure is visible");}
            Check(journal.Pending().Length==0&&journal.ReadDeferredCanonical(source.Id,bank).SequenceEqual(next),"failed outcome rolls back work admission and retains exact deferred prefix");
            q.CommandText="DROP TRIGGER owned_deferred_failure;";q.ExecuteNonQuery();
        }
        var spool=new EventSpool(Path.Combine(root,"spool"),sensor);var errors=new List<string>();int rounds=0;
        while((next=journal.ReadDeferredCanonical(source.Id,bank)).Length!=0)
        {
            rounds++;var ids=next.Select(entry=>journal.PromoteStoppedCanonicalUnavailable(source.Id,bank,entry)).ToArray();
            Check(journal.Pending().Length==ids.Length&&ids.Length<=4,"historical promotion obeys existing bounded work admission");
            if(rounds==1)
            {
                var fifth=bank.Entries[4];
                try{journal.PromoteStoppedCanonicalUnavailable(source.Id,bank,fifth);throw new Exception("Fifth pending work admitted");}
                catch(IOException){Check(true,"full forensic work capacity leaves later raw event durable");}
            }
            await using(var pipeline=new ForensicPipeline(sensor,root,errors.Add))foreach(var id in ids)Check(pipeline.TrySubmitPrepared(journal,id,spool),"deferred event enters common pipeline: "+id);
            Check(errors.Count==0&&journal.Pending().Length==0,"common completion frees bounded work for later durable backlog");
        }
        Check(rounds==2&&spool.Count==14,"seven stopped-before-admission events all produce original/completion pairs");
        foreach(var e in spool.Peek().Events)
        {
            var original=observations.Single(x=>x.EventId==(e.Forensics!.RelatedEventId??e.EventId));
            Check(e.User==original.User&&e.Process==original.Process&&e.ProcessId==original.ProcessId&&e.Attribution==original.Attribution&&LinuxKernelEvidence.Matches(e),"deferred evidence retains exact raw actor identity: "+e.EventId);
            Check(e.Forensics!.ActorExecutable.LinuxNativeWork==null&&e.Forensics.ActorExecutable.LinuxAcquisition!.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SOURCE_STOPPED_BEFORE_NATIVE_ADMISSION"&&e.Forensics.ActorExecutable.Sha256==null,"historical delivery fabricates no pin/native completion/hash: "+e.EventId);
        }
        Check(observations.All(e=>journal.Read(e.EventId).DropState=="not-attempted"&&journal.ReadNativePin(e.EventId)==null),"historical delivery never claims native release or new capability");
        var result=new{Passed=true,Checks=checks,Events=7,SpoolEvents=14,Scope="Durable deferred canonical metadata and common event delivery after source stop; no native device or source activation"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
}
