using System.Text.Json;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client;

public sealed record EventSpoolWriteProgress(string Stage,string? EventId,DateTimeOffset StartedUtc,long ElapsedMilliseconds);

// Transactional FIFO: one event write per enqueue, not a rewrite of the entire backlog.
public sealed class EventSpool:IDisposable
{
    private readonly object gate=new();
    private readonly string connectionString;
    private SqliteConnection? lifetimeConnection;
    private bool disposed;
    private sealed record WriteProgress(string Stage,string? EventId,DateTimeOffset Utc,long Tick);
    private WriteProgress writeProgress=new("idle",null,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp());
    // Read without the queue mutex so a blocked writer can be diagnosed. This
    // is the last durable-writer stage, not an event receipt or success claim.
    public EventSpoolWriteProgress CaptureWriteDiagnostics(){var p=Volatile.Read(ref writeProgress);return new(p.Stage,p.EventId,p.Utc,(long)Stopwatch.GetElapsedTime(p.Tick).TotalMilliseconds);}
    private void WriteStage(string stage,string id)=>Volatile.Write(ref writeProgress,new(stage,id,DateTimeOffset.UtcNow,Stopwatch.GetTimestamp()));
    private EventQueuePolicy limits=new();
    public int RecoveredIncompleteActorEvents {get;}
    public EventSpool(string directory,string endpointId)
        :this(directory,endpointId,false){}
    // Windows/Linux owners opt in and dispose only after their producers/delivery loops
    // have drained. This unused connection holds WAL/index lifetime; operations
    // still use fresh unpooled connections and retain FULL write durability.
    public EventSpool(string directory,string endpointId,bool retainJournalLifetime)
    {
        if(retainJournalLifetime&&!OperatingSystem.IsLinux()&&!OperatingSystem.IsWindows())throw new PlatformNotSupportedException("Retained queue lifetime requires a Windows or Linux owner.");
        if(!Guid.TryParseExact(endpointId,"N",out _))throw new ArgumentException("Invalid endpoint ID.");
        directory=Path.GetFullPath(directory);Directory.CreateDirectory(directory);
        var file=Path.Combine(directory,"events-"+endpointId+".db");
        foreach(var candidate in new[]{directory,file,file+"-wal",file+"-shm",file+"-journal",Path.Combine(directory,"events-"+endpointId+".json")})
            for(string? parent=candidate;parent!=null;parent=Path.GetDirectoryName(parent))
                if(Path.Exists(parent)&&(File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0)throw new IOException("Queue paths must not traverse links.");
        connectionString=new SqliteConnectionStringBuilder{DataSource=file,Mode=SqliteOpenMode.ReadWriteCreate,Pooling=false,DefaultTimeout=5}.ToString();
        using var c=Open();
        var version=Scalar(c,null,"PRAGMA user_version");
        if(version is <0 or >4)throw new InvalidDataException("Unsupported queue schema; original retained.");
        if(version==0)
        {
            if(Scalar(c,null,"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")!=0)throw new InvalidDataException("Unrecognized queue database; original retained.");
            using var transaction=c.BeginTransaction();
            Execute(c,transaction,"""
                CREATE TABLE queue(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=65536));
                CREATE TABLE quarantine(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,quarantined INTEGER NOT NULL);
                CREATE TABLE queue_state(id INTEGER PRIMARY KEY CHECK(id=1),pending INTEGER NOT NULL CHECK(pending>=0),payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0),legacy_imported INTEGER NOT NULL CHECK(legacy_imported IN (0,1)));
                INSERT INTO queue_state VALUES(1,0,0,0);
                PRAGMA user_version=4;
                """);
            transaction.Commit();
        }
        else if(version==1)
        {
            using var transaction=c.BeginTransaction();
            Execute(c,transaction,"CREATE TABLE quarantine(sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,quarantined INTEGER NOT NULL); PRAGMA user_version=2;");
            transaction.Commit();
        }
        Execute(c,null,"PRAGMA journal_mode=WAL;");
        ImportLegacy(c,Path.Combine(directory,"events-"+endpointId+".json"));
        RecoveredIncompleteActorEvents=RecoverQuarantinedActorEvents(c);
        UpgradePayloadCapacity(c);
        using var check=c.BeginTransaction();
        var status=ReadStatus(c,check);
        if(status.Pending>1000000 || status.PayloadBytes>1024L*1024*1024 ||
            status.Pending!=Scalar(c,check,"SELECT COUNT(*) FROM queue") || status.PayloadBytes!=Scalar(c,check,"SELECT COALESCE(SUM(length(payload)),0) FROM queue"))
            throw new InvalidDataException("Queue counters exceed safety limits or disagree with stored data; original retained.");
        check.Commit();
        if(retainJournalLifetime)lifetimeConnection=Open();
    }
    public EventQueueStatus Status {get {lock(gate){using var c=Open();var status=ReadStatus(c,null);return status with{MaxEvents=limits.MaxEvents,MaxPayloadBytes=limits.MaxPayloadBytes};}}}
    public int Count=>Status.Pending;
    public void Configure(EventQueuePolicy policy)
    {
        if(policy==null || !policy.IsValid())throw new ArgumentException("Invalid queue capacity.");
        // Lower limits do not delete pending evidence; new additions wait for space.
        lock(gate){ObjectDisposedException.ThrowIf(disposed,this);limits=policy;}
    }
    public void Enqueue(AgentEvent item)
    {
        EnqueuePayload(item,Encode(item));
    }
    // Recovery must replay saved bytes without silently changing their schema.
    internal void EnqueueExact(byte[] payload)
    {
        var item=JsonSerializer.Deserialize<AgentEvent>(payload)??throw new InvalidDataException("Empty immutable event");
        if(!Encode(item).AsSpan().SequenceEqual(payload))throw new InvalidDataException("Immutable event serialization changed; migration required, original retained.");
        EnqueuePayload(item,payload);
    }
    private void EnqueuePayload(AgentEvent item,byte[] payload)
    {
        lock(gate)
        {
            try{
                WriteStage("connection-open",item.EventId);
                using(var c=Open()){
                    WriteStage("transaction-begin",item.EventId);
                    using(var t=c.BeginTransaction()){
                        WriteStage("capacity-read",item.EventId);var status=ReadStatus(c,t);
                        using(var prior=c.CreateCommand())
                        {
                            prior.Transaction=t;prior.CommandText="SELECT payload FROM queue WHERE event_id=$id";prior.Parameters.AddWithValue("$id",item.EventId);
                            WriteStage("duplicate-read",item.EventId);
                            if(prior.ExecuteScalar() is byte[] existing){if(!existing.AsSpan().SequenceEqual(payload))throw new InvalidOperationException("Event ID payload conflict; evidence retained.");WriteStage("deduplicated",item.EventId);return;}
                        }
                        if(status.Pending>=limits.MaxEvents || status.PayloadBytes+payload.Length>limits.MaxPayloadBytes)throw new InvalidOperationException("Management queue capacity reached; existing evidence retained. Restore delivery or increase the approved limit.");
                        WriteStage("payload-insert",item.EventId);Insert(c,t,item.EventId,payload);
                        WriteStage("durable-commit",item.EventId);t.Commit();
                    }
                    WriteStage("connection-close",item.EventId);
                }
                WriteStage("committed",item.EventId);
            }catch{WriteStage("failed",item.EventId);throw;}
        }
    }
    public EventBatch Peek(){lock(gate){using var c=Open();return new(ReadBatch(c,null).Select(x=>x.Event).ToArray());}}
    public void Acknowledge(EventBatch batch,BatchReceipt receipt)
    {
        if(batch?.Events is not {Length:>=1 and <=100} || receipt==null || receipt.Accepted<0 || receipt.Duplicates<0 || (long)receipt.Accepted+receipt.Duplicates!=batch.Events.Length)throw new InvalidDataException("Invalid server receipt; queue preserved.");
        if(batch.Events.Any(e=>e.Trust!=null)&&receipt.TrustVersion!=1)throw new InvalidDataException("Trust evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Forensics!=null)&&receipt.ForensicsVersion!=1)throw new InvalidDataException("Forensic evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Forensics?.Process.Creation!=null)&&receipt.ProcessCreationVersion!=1)throw new InvalidDataException("Process creation evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Forensics?.ActorExecutable.Acquisition?.Version==1)&&receipt.ActorAcquisitionVersion!=1)throw new InvalidDataException("Actor acquisition evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Attribution?.WindowsSyscall!=null||e.Forensics?.ActorExecutable.Acquisition?.Version==2)&&receipt.WindowsSyscallVersion!=1)throw new InvalidDataException("Syscall evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Attribution?.WindowsKernel?.AcquisitionObservation!=null)&&receipt.WindowsAcquisitionObservationVersion!=1)throw new InvalidDataException("Windows acquisition observation not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Attribution?.WindowsKernel?.AcquisitionObservation?.Version==2)&&receipt.WindowsAcquisitionRecoveryVersion!=1)throw new InvalidDataException("Windows acquisition recovery not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Forensics?.ActorExecutable.LinuxAcquisition!=null)&&receipt.LinuxActorAcquisitionVersion!=1)throw new InvalidDataException("Linux actor acquisition evidence not acknowledged; queue preserved.");
        if(!LinuxNativeWorkEvidence.Supports(LinuxNativeWorkEvidence.RequiredVersion(batch.Events),receipt.LinuxNativeWorkVersion))throw new InvalidDataException("Linux native work timeline not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Attribution?.WindowsKernel is {} k&&receipt.WindowsKernelVersion<k.Version))throw new InvalidDataException("Windows kernel evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Attribution?.WindowsShare!=null)&&receipt.WindowsShareVersion!=1)throw new InvalidDataException("SMB evidence not acknowledged; queue preserved.");
        if(!LinuxKernelEvidence.Supports(LinuxKernelEvidence.RequiredVersion(batch.Events),receipt.LinuxKernelVersion,receipt.LinuxKernelTargetIdentityVersion,receipt.LinuxPermissionObservationVersion,receipt.LinuxIoObservationVersion))throw new InvalidDataException("Linux kernel evidence or target identity not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Trust?.Version is 2 or 3 or 4)&&receipt.WhitelistVersion!=1)throw new InvalidDataException("Whitelist evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Trust?.Version==3)&&receipt.LinuxKernelTrustVersion!=1)throw new InvalidDataException("Linux kernel trust evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Forensics?.LinuxPermissionPair!=null)&&receipt.LinuxPermissionPairVersion!=1)throw new InvalidDataException("Permission-pair evidence not acknowledged; queue preserved.");
        if(batch.Events.Any(e=>e.Trust?.Version==4)&&receipt.LinuxNativeHashTrustVersion!=1)throw new InvalidDataException("Native hash trust evidence not acknowledged; queue preserved.");
        lock(gate)
        {
            using var c=Open();using var t=c.BeginTransaction();var prefix=ReadBatch(c,t).Take(batch.Events.Length).ToArray();
            if(prefix.Length!=batch.Events.Length||prefix.Where((x,i)=>!Encode(x.Event).AsSpan().SequenceEqual(Encode(batch.Events[i]))).Any())throw new InvalidOperationException("Queue prefix changed; receipt cannot be applied.");
            foreach(var item in prefix)Execute(c,t,"DELETE FROM queue WHERE sequence=$sequence",("$sequence",item.Sequence));
            Execute(c,t,"UPDATE queue_state SET pending=pending-$count,payload_bytes=payload_bytes-$bytes WHERE id=1",("$count",prefix.Length),("$bytes",prefix.Sum(x=>(long)x.Bytes)));
            t.Commit();
        }
    }
    internal static byte[] Encode(AgentEvent? item)
    {
        if(item==null || !Guid.TryParseExact(item.EventId,"N",out _))throw new ArgumentException("Invalid event; not queued.");
        if(item.Attribution!=null&&!item.Attribution.IsValid())throw new ArgumentException("Invalid attribution; not queued.");
        if(!WindowsKernelEvidence.Matches(item))throw new ArgumentException("Kernel actor contradicts event identity; not queued.");
        if(!WindowsSyscallObservation.Matches(item))throw new ArgumentException("Syscall evidence contradicts event identity; not queued.");
        if(!WindowsShareEvidence.Matches(item))throw new ArgumentException("SMB evidence contradicts event identity; not queued.");
        if(!LinuxKernelEvidence.Matches(item))throw new ArgumentException("Linux kernel actor contradicts event identity; not queued.");
        if(item.Forensics!=null&&(!item.Forensics.IsValid()||item.Forensics.EventId!=item.EventId))throw new ArgumentException("Invalid forensic evidence; not queued.");
        if(item.Trust!=null&&!item.Trust.IsValid())throw new ArgumentException("Invalid trust evidence; not queued.");
        var payload=JsonSerializer.SerializeToUtf8Bytes(item);
        if(payload.Length>(item.Forensics?.ActorExecutable.LinuxAcquisition==null&&item.Trust?.LinuxNativeHashBinding?.EntryEvent==null?24:64)*1024)throw new ArgumentException("Oversized event; not queued.");
        return payload;
    }
    // Root companion delivery only: separate from server BatchReceipt. The
    // completed native journal and export ledger remain the canonical evidence.
    internal void AcknowledgeNativeBridgePair(byte[] original,byte[] completion)
    {
        var events=new[]{original,completion}.Select(payload=>(Payload:payload,Event:JsonSerializer.Deserialize<AgentEvent>(payload)!)).ToArray();
        if(events.Any(x=>x.Event.Attribution?.LinuxKernel==null||!Encode(x.Event).AsSpan().SequenceEqual(x.Payload))||
            events[1].Event.Forensics?.RelatedEventId!=events[0].Event.EventId||events[0].Event.EventId==events[1].Event.EventId)
            throw new InvalidDataException("Exact linked native bridge events required");
        lock(gate)
        {
            using var c=Open();using var t=c.BeginTransaction();var count=0;long bytes=0;
            foreach(var item in events)
            {
                using var q=Command(c,t,"SELECT payload FROM queue WHERE event_id=$id",("$id",item.Event.EventId));
                if(q.ExecuteScalar() is not byte[] prior)continue;
                if(!prior.AsSpan().SequenceEqual(item.Payload))throw new InvalidDataException("Native transfer queue identity conflict; retained");
                Execute(c,t,"DELETE FROM queue WHERE event_id=$id",("$id",item.Event.EventId));count++;bytes+=prior.Length;
            }
            Execute(c,t,"UPDATE queue_state SET pending=pending-$count,payload_bytes=payload_bytes-$bytes WHERE id=1",("$count",count),("$bytes",bytes));t.Commit();
        }
    }
    private static void ImportLegacy(SqliteConnection c,string path)
    {
        using var t=c.BeginTransaction();
        if(Scalar(c,t,"SELECT legacy_imported FROM queue_state WHERE id=1")==1){t.Commit();return;}
        if(File.Exists(path))
        {
            if(new FileInfo(path).Length>32*1024*1024)throw new InvalidDataException("Legacy spool exceeds safety limit; original retained.");
            var events=JsonSerializer.Deserialize<List<AgentEvent>>(File.ReadAllBytes(path))??throw new InvalidDataException("Invalid legacy spool; original retained.");
            if(events.Count>1000 || events.Any(x=>x==null) || events.Select(x=>x.EventId).Distinct(StringComparer.Ordinal).Count()!=events.Count)throw new InvalidDataException("Invalid legacy queue; original retained.");
            if(Scalar(c,t,"SELECT COUNT(*) FROM queue")!=0)throw new InvalidDataException("Legacy import would overlap new queue evidence; original retained.");
            foreach(var item in events)Insert(c,t,item.EventId,Encode(item));
        }
        Execute(c,t,"UPDATE queue_state SET legacy_imported=1 WHERE id=1");t.Commit();
        // Original JSON remains untouched for recovery; never imported again after commit.
    }
    private static void Insert(SqliteConnection c,SqliteTransaction t,string id,byte[] payload)
    {
        Execute(c,t,"INSERT INTO queue(event_id,payload) VALUES($id,$payload)",("$id",id),("$payload",payload));
        Execute(c,t,"UPDATE queue_state SET pending=pending+1,payload_bytes=payload_bytes+$bytes WHERE id=1",("$bytes",payload.Length));
    }
    private static int RecoverQuarantinedActorEvents(SqliteConnection c)
    {
        using var t=c.BeginTransaction();using var read=Command(c,t,"SELECT event_id,payload FROM quarantine ORDER BY sequence");using var reader=read.ExecuteReader();
        var recovered=new List<(string Id,byte[] Payload)>();
        while(reader.Read())
        {
            var payload=(byte[])reader[1];_ = JsonSerializer.Deserialize<AgentEvent>(payload)??throw new InvalidDataException("Invalid quarantined event; original retained.");
            recovered.Add((reader.GetString(0),payload));
        }
        reader.Close();
        foreach(var item in recovered)
        {
            using var prior=Command(c,t,"SELECT payload FROM queue WHERE event_id=$id",("$id",item.Id));
            if(prior.ExecuteScalar() is byte[] existing)
            {
                if(!existing.AsSpan().SequenceEqual(item.Payload))throw new InvalidDataException("Quarantined event identity conflict; original retained.");
            }
            else Insert(c,t,item.Id,item.Payload);
            Execute(c,t,"DELETE FROM quarantine WHERE event_id=$id",("$id",item.Id));
        }
        if(Scalar(c,t,"PRAGMA user_version")<3)Execute(c,t,"PRAGMA user_version=3;");
        t.Commit();return recovered.Count;
    }
    private static void UpgradePayloadCapacity(SqliteConnection c)
    {
        // Preserve raw payloads, FIFO sequence and even the high-water mark of
        // already acknowledged events. A failed rebuild rolls back atomically.
        using var t=c.BeginTransaction();
        if(Scalar(c,t,"PRAGMA user_version")==4){t.Commit();return;}
        var highWater=Scalar(c,t,"SELECT COALESCE(MAX(seq),0) FROM sqlite_sequence WHERE name='queue'");
        Execute(c,t,"""
            CREATE TABLE queue_v4(sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,payload BLOB NOT NULL CHECK(length(payload)<=65536));
            INSERT INTO queue_v4(sequence,event_id,payload) SELECT sequence,event_id,payload FROM queue ORDER BY sequence;
            DROP TABLE queue;
            ALTER TABLE queue_v4 RENAME TO queue;
            INSERT INTO sqlite_sequence(name,seq) SELECT 'queue',$water WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='queue');
            UPDATE sqlite_sequence SET seq=MAX(seq,$water) WHERE name='queue';
            PRAGMA user_version=4;
            """,("$water",highWater));
        t.Commit();
    }
    private static (long Sequence,AgentEvent Event,int Bytes)[] ReadBatch(SqliteConnection c,SqliteTransaction? t)
    {
        using var cmd=Command(c,t,"SELECT sequence,event_id,payload FROM queue ORDER BY sequence LIMIT 100");using var reader=cmd.ExecuteReader();var batch=new List<(long,AgentEvent,int)>();var total=0;
        while(reader.Read())
        {
            var bytes=(byte[])reader[2];var item=JsonSerializer.Deserialize<AgentEvent>(bytes)??throw new InvalidDataException("Invalid queued event; original retained.");
            _=Encode(item);
            if(item.EventId!=reader.GetString(1))throw new InvalidDataException("Queue event identity mismatch; original retained.");
            // Leave ample envelope/encoding headroom below the server's 512 KiB body limit.
            if(batch.Count>0&&total+bytes.Length>256*1024)break;
            batch.Add((reader.GetInt64(0),item,bytes.Length));
            total+=bytes.Length;
        }
        return batch.ToArray();
    }
    private static EventQueueStatus ReadStatus(SqliteConnection c,SqliteTransaction? t)
    {
        using var cmd=Command(c,t,"SELECT pending,payload_bytes FROM queue_state WHERE id=1");using var reader=cmd.ExecuteReader();
        if(!reader.Read())throw new InvalidDataException("Queue metadata missing; original retained.");
        return new(reader.GetInt32(0),reader.GetInt64(1),0,0);
    }
    private SqliteConnection Open()
    {
        ObjectDisposedException.ThrowIf(disposed,this);
        var c=new SqliteConnection(connectionString);
        try{c.Open();Execute(c,null,"PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");return c;}catch{c.Dispose();throw;}
    }
    private static SqliteCommand Command(SqliteConnection c,SqliteTransaction? t,string sql,params (string,object)[] values)
    {var cmd=c.CreateCommand();cmd.Transaction=t;cmd.CommandText=sql;foreach(var (name,value) in values)cmd.Parameters.AddWithValue(name,value);return cmd;}
    private static long Scalar(SqliteConnection c,SqliteTransaction? t,string sql,params (string,object)[] values){using var cmd=Command(c,t,sql,values);return Convert.ToInt64(cmd.ExecuteScalar());}
    private static void Execute(SqliteConnection c,SqliteTransaction? t,string sql,params (string,object)[] values){using var cmd=Command(c,t,sql,values);cmd.ExecuteNonQuery();}
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;
            lifetimeConnection?.Dispose();lifetimeConnection=null;disposed=true;
        }
    }
}
public sealed record EventQueueStatus(int Pending,long PayloadBytes,int MaxEvents,long MaxPayloadBytes);
