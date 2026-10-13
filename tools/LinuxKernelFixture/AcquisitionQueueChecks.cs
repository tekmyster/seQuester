using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Contracts;

static class AcquisitionQueueChecks
{
    public static async Task<AgentEvent> Run(AgentEvent sample,AgentEvent longPaths,string root,string sensor,Action<bool,string> check)
    {
        var k=longPaths.Attribution!.LinuxKernel!;var original=sample.Forensics!;var acquisition=original.ActorExecutable.LinuxAcquisition!;
        var f=original with{EventId=Guid.NewGuid().ToString("N"),RelatedEventId=longPaths.EventId,SourceSequence=k.CollectorInstance+":"+k.CollectorSequence,
            Process=original.Process with{ExecutablePath=longPaths.Process},Observation=original.Observation with{Path=longPaths.Path},
            ActorExecutable=original.ActorExecutable with{ObservedPath=longPaths.Process,BindingSourceEventId=longPaths.EventId,LinuxAcquisition=acquisition with{SourceEventId=longPaths.EventId,NativeObservationSha256=k.NativeObservationSha256}},
            // Constructed envelope case: include the preservation fields that
            // a real completed copy adds. This is not a preservation runtime test.
            Preservation=new(){EvidenceId=acquisition.SnapshotId,ArtifactRelativePath="evidence/actors/"+acquisition.SnapshotId+".bin",ManifestRelativePath="evidence/actors/"+acquisition.SnapshotId+".json",SourceEventId=longPaths.EventId,
                ProcessInstanceId=original.Process.InstanceId,OriginalPath=longPaths.Process,Sha256=acquisition.SnapshotSha256,Size=acquisition.SnapshotFile!.Size,PreservedUtc=acquisition.PersistedUtc,HashMatched=true,ManifestSha256=new string('a',64),Status=EvidenceStatus.Captured("constructed-preservation-envelope; not-runtime-capture")},
            Response=original.Response with{RelatedEventId=longPaths.EventId}};
        var large=longPaths with{EventId=f.EventId,Source="Forensic enrichment",Operation="Maximum-path acquisition contract replay",Forensics=f};
        var encoded=JsonSerializer.SerializeToUtf8Bytes(large);
        check(f.IsValid()&&LinuxKernelEvidence.Matches(large)&&encoded.Length>24576&&encoded.Length<=65536,"valid complete path/acquisition/preservation envelope requires more than the old 24 KiB limit: "+encoded.Length);
        foreach(var version in new[]{1,2,3})
        {
            var folder=Path.Combine(root,"queue-migration-v"+version);Directory.CreateDirectory(folder);var db=Path.Combine(folder,"events-"+sensor+".db");
            var ordinary=new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read","Queue migration",null,null,null,"Test");var bytes=JsonSerializer.SerializeToUtf8Bytes(ordinary);
            using(var c=Connection(db))
            {
                using var cmd=c.CreateCommand();cmd.CommandText="CREATE TABLE queue(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=24576)); CREATE TABLE queue_state(id INTEGER PRIMARY KEY,pending INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,legacy_imported INTEGER NOT NULL); INSERT INTO queue_state VALUES(1,1,$length,1); INSERT INTO queue(sequence,event_id,payload) VALUES(7,$id,$bytes); UPDATE sqlite_sequence SET seq=900 WHERE name='queue'; PRAGMA user_version="+version+";";
                if(version>=2)cmd.CommandText+=" CREATE TABLE quarantine(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,quarantined INTEGER NOT NULL);";
                cmd.Parameters.AddWithValue("$id",ordinary.EventId);cmd.Parameters.AddWithValue("$bytes",bytes);cmd.Parameters.AddWithValue("$length",bytes.Length);cmd.ExecuteNonQuery();
            }
            var queue=new EventSpool(folder,sensor);check(queue.Count==1&&queue.Peek().Events.Single()==ordinary,"schema "+version+" migration preserves original FIFO event");
            using(var c=Connection(db))
            {
                using var cmd=c.CreateCommand();cmd.CommandText="SELECT sequence,payload FROM queue";using var row=cmd.ExecuteReader();check(row.Read()&&row.GetInt64(0)==7&&((byte[])row[1]).AsSpan().SequenceEqual(bytes),"schema "+version+" migration preserves exact payload bytes and sequence");
            }
            queue.Enqueue(large);check(queue.Count==2&&queue.Status.PayloadBytes==bytes.Length+encoded.Length,"schema "+version+" expanded evidence keeps exact capacity accounting");
            using(var c=Connection(db))
            {
                using var cmd=c.CreateCommand();cmd.CommandText="SELECT MAX(sequence) FROM queue";check(Convert.ToInt64(cmd.ExecuteScalar())==901,"schema "+version+" migration retains acknowledged high-water mark");cmd.CommandText="PRAGMA user_version";check(Convert.ToInt64(cmd.ExecuteScalar())==4,"schema "+version+" upgrades transactionally to version 4");
            }
            queue=new EventSpool(folder,sensor);var batch=queue.Peek();
            check(batch.Events.Length==2&&JsonSerializer.Serialize(batch.Events[1])==JsonSerializer.Serialize(large),"expanded acquisition survives queue restart with every field intact");
            try{queue.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1});throw new Exception("Legacy acquisition receipt accepted");}catch(InvalidDataException){check(queue.Count==2,"missing Linux acquisition ACK preserves both original and expanded events");}
            queue.Acknowledge(batch,new(2,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=1});check(queue.Count==0,"explicit acquisition ACK drains exact migrated FIFO prefix");
            try{queue.Enqueue(ordinary with{Path=new string('x',25000)});throw new Exception("Old envelope silently expanded");}catch(ArgumentException){check(queue.Count==0,"ordinary events retain existing 24 KiB limit");}
            try{queue.Enqueue(large with{Operation=new string('x',65536)});throw new Exception("Oversize new envelope accepted");}catch(ArgumentException){check(queue.Count==0,"Linux acquisition events have a hard 64 KiB bound");}
        }
        var failedFolder=Path.Combine(root,"queue-migration-rollback");Directory.CreateDirectory(failedFolder);var failedDb=Path.Combine(failedFolder,"events-"+sensor+".db");
        // An old corrupt/oversized row cannot be silently dropped to make a
        // table rebuild succeed. The whole schema change must roll back.
        var badBytes=JsonSerializer.SerializeToUtf8Bytes(new AgentEvent(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"Read",new string('x',66000),null,null,null,"Test"));
        using(var c=Connection(failedDb))
        {
            using var cmd=c.CreateCommand();cmd.CommandText="CREATE TABLE queue(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=24576)); CREATE TABLE queue_state(id INTEGER PRIMARY KEY,pending INTEGER NOT NULL,payload_bytes INTEGER NOT NULL,legacy_imported INTEGER NOT NULL); CREATE TABLE quarantine(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,quarantined INTEGER NOT NULL); INSERT INTO queue_state VALUES(1,1,$length,1); PRAGMA ignore_check_constraints=ON; INSERT INTO queue(sequence,event_id,payload) VALUES(41,'corrupt-fixture',$bytes); PRAGMA user_version=3;";
            cmd.Parameters.AddWithValue("$bytes",badBytes);cmd.Parameters.AddWithValue("$length",badBytes.Length);cmd.ExecuteNonQuery();
        }
        try{_=new EventSpool(failedFolder,sensor);throw new Exception("Corrupt old payload silently discarded");}catch(SqliteException ex)when(ex.SqliteErrorCode==19){check(true,"oversized old evidence aborts migration instead of losing data");}
        using(var c=Connection(failedDb))
        {
            using var cmd=c.CreateCommand();cmd.CommandText="PRAGMA user_version";check(Convert.ToInt64(cmd.ExecuteScalar())==3,"failed migration preserves previous schema version");
            cmd.CommandText="SELECT payload FROM queue WHERE sequence=41";check(cmd.ExecuteScalar() is byte[] old&&old.AsSpan().SequenceEqual(badBytes),"failed migration retains exact original evidence bytes");
            cmd.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE name='queue_v4'";check(Convert.ToInt64(cmd.ExecuteScalar())==0,"failed rebuild leaves no partially migrated table");
            cmd.CommandText="SELECT payload_bytes FROM queue_state";check(Convert.ToInt64(cmd.ExecuteScalar())==badBytes.Length,"failed rebuild retains original capacity counters");
        }
        foreach(var phase in new[]{"capability","receipt"})
        {
            using var handler=new Handler(phase=="receipt");using var client=new ManagementClient(new HttpClient(handler){BaseAddress=new Uri("https://fixture.invalid")},"fixture-token");
            try{await client.SendEventsAsync(new([sample]));throw new Exception("Missing acquisition support accepted");}catch(InvalidDataException){check(handler.EventPosts==(phase=="receipt"?1:0),"missing Linux acquisition "+phase+" blocks acknowledgement without silent field loss");}
        }
        return large;
    }
    private static SqliteConnection Connection(string path){var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString());c.Open();return c;}
    private sealed class Handler(bool capable):HttpMessageHandler
    {
        public int EventPosts;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)
        {
            object result;
            if(request.RequestUri!.AbsolutePath.EndsWith("/capabilities"))result=new{AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1,LinuxActorAcquisitionVersion=capable?1:0};
            else{EventPosts++;result=new BatchReceipt(1,0){AttributionVersion=1,ForensicsVersion=1,LinuxKernelVersion=1};}
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=JsonContent.Create(result)});
        }
    }
}
