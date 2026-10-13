using System.Text.Json;
using RansomFree.Client;
using RansomFree.Contracts;
using Microsoft.Data.Sqlite;

internal static class EventQueueChecks
{
    // Prepared acceptance checks; execution remains explicitly deferred.
    public static void Run(string root,Action<bool,string> check)
    {
        check(TrayReaderIdentity.IsSupported("S-1-12-1-1-2-3-4")&&TrayReaderIdentity.IsSupported("S-1-5-21-1-2-3-1001"),"explicit Entra and local/domain SID syntax supported");
        check(!TrayReaderIdentity.IsSupported("S-1-5-32-544")&&!TrayReaderIdentity.IsSupported("S-1-12-1-1-2-3-4294967296")&&!TrayReaderIdentity.IsSupported("S-1-12-1-01-2-3-4"),"broad, overflowing and noncanonical reader SID syntax rejected");
        var folder=Path.Combine(root,"transactional-queue");Directory.CreateDirectory(folder);
        var id=Guid.NewGuid().ToString("N");
        AgentEvent Event()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","Queue QA",null,null,null,"Test");
        var legacy=new[]{Event(),Event()};var path=Path.Combine(folder,"events-"+id+".json");
        var original=JsonSerializer.SerializeToUtf8Bytes(legacy);File.WriteAllBytes(path,original);
        var queue=new EventSpool(folder,id);
        check(queue.Peek().Events.SequenceEqual(legacy),"legacy FIFO imports in order");
        check(File.ReadAllBytes(path).SequenceEqual(original),"legacy evidence retained byte-identical");
        queue.Acknowledge(queue.Peek(),new(2,0));queue=new EventSpool(folder,id);
        check(queue.Count==0,"committed migration does not replay retained legacy JSON");
        queue.Configure(new(2000,32));
        for(var i=0;i<1001;i++)queue.Enqueue(Event());
        queue.Configure(new(1000,32));check(queue.Count==1001,"lower capacity preserves existing backlog");
        var blocked=false;try{queue.Enqueue(Event());}catch(InvalidOperationException){blocked=true;}
        check(blocked&&queue.Count==1001,"capacity blocks new event without evicting evidence");
        var batch=queue.Peek();var invalid=false;try{queue.Acknowledge(batch,new(int.MaxValue,int.MaxValue));}catch(InvalidDataException){invalid=true;}
        check(invalid&&queue.Count==1001,"overflow-sized receipt preserves queue");
        queue.Acknowledge(batch,new(50,50));check(queue.Count==901,"mixed accepted/duplicate receipt drains submitted FIFO batch");
        queue.Enqueue(Event());check(queue.Count==902,"enqueue resumes after draining below lowered limit");
        var status=queue.Status;check(status.MaxEvents==1000&&status.PayloadBytes>0&&status.MaxPayloadBytes==32L*1024*1024,"queue exposes capacity and persisted payload usage");
        var actorFolder=Path.Combine(root,"actor-queue");Directory.CreateDirectory(actorFolder);var actorId=Guid.NewGuid().ToString("N");
        var actorDb=Path.Combine(actorFolder,"events-"+actorId+".db");
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=actorDb}.ToString()))
        {
            c.Open();using var cmd=c.CreateCommand();cmd.CommandText="CREATE TABLE queue(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=24576)); CREATE TABLE quarantine(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,quarantined INTEGER NOT NULL); CREATE TABLE queue_state(id INTEGER PRIMARY KEY CHECK(id=1),pending INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,legacy_imported INTEGER NOT NULL); INSERT INTO queue_state VALUES(1,0,0,1); PRAGMA user_version=2;";cmd.ExecuteNonQuery();
            var incomplete=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"File changed","C:\\bait.txt",null,"Unavailable for change notifications",null,"File watcher");var payload=JsonSerializer.SerializeToUtf8Bytes(incomplete);
            using var insert=c.CreateCommand();insert.CommandText="INSERT INTO quarantine(sequence,event_id,payload,reason,quarantined) VALUES(1,$id,$payload,'prior actor requirement',0)";insert.Parameters.AddWithValue("$id",incomplete.EventId);insert.Parameters.AddWithValue("$payload",payload);insert.ExecuteNonQuery();
        }
        var migrated=new EventSpool(actorFolder,actorId);check(migrated.Count==1&&migrated.RecoveredIncompleteActorEvents==1,"previously quarantined unattributed local event is restored to the delivery FIFO");
        migrated.Enqueue(new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"File changed","C:\\bait.txt",null,null,null,"File watcher"));
        check(migrated.Count==2,"new unattributed local event is retained for delivery");
    }
}
