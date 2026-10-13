using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Opt-in intake/recovery component. No native device or original actor pathname
// is ever opened here. Native DROP is owned by the source, after acquisition is
// committed. This journal is not yet an installed Linux source activation.
internal sealed partial class LinuxForensicJournal:IDisposable
{
    internal sealed record Work(AgentEvent Observation,ForensicPolicy Policy,string CompletionId,
        LinuxActorAcquisitionEvidence? Acquisition,FileIdentityEvidence? SourceFile,
        byte[]? Original,byte[]? Completion,bool Done,string DropState);
    private readonly string root,sensor,connectionString;
    private readonly long quota;
    internal int PendingWorkLimit {get;}
    private readonly object gate=new();
    private readonly FileStream owner;
    private bool disposed;
    // No reads or transactions use this connection. Keep SQLite's WAL/index
    // lifetime attached to this exclusively owned journal, rather than closing
    // the last connection and rebuilding/checkpointing it on every idle poll.
    // Actual operations still obtain fresh unpooled connections with FULL
    // synchronization and foreign-key enforcement.
    private SqliteConnection? lifetimeConnection;
    private sealed record PreparedAttempt(string ContextSha256,byte[] Bytes);
    // At most PendingWorkLimit admitted work items. A failed disk commit must not
    // re-evaluate policy or allocate another Begin sequence in this process.
    // A process crash loses this volatile attempt; stopped recovery has no
    // source authority and may only retain an unsuppressed original.
    private readonly Dictionary<string,PreparedAttempt> originalAttempts=new(StringComparer.Ordinal);
    // Logical admission budget includes raw, original, completion and manifests.
    // It is not a promise that a different process cannot exhaust the disk.
    internal const long PerWorkReservation=4L*1024*1024+3*65536+2*32768;
    internal LinuxForensicJournal(string directory,string sensor,long quota=512L*1024*1024,Action<string>? migrationCheckpoint=null,int pendingWorkLimit=4)
    {
        if(!Guid.TryParseExact(sensor,"N",out _)||quota<PerWorkReservation||pendingWorkLimit is not (4 or 16))throw new ArgumentException("Invalid Linux journal configuration");
        PendingWorkLimit=pendingWorkLimit;
        this.sensor=sensor;this.quota=quota;root=Path.GetFullPath(Path.Combine(directory,"linux-forensic-intake"));EvidenceStore.EnsurePrivate(root);
        var ownerPath=Path.Combine(root,"owner.lock");EvidenceDurability.NoLinks(ownerPath);
        var options=new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None};
        if(!OperatingSystem.IsWindows())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        owner=new FileStream(ownerPath,options);
        try
        {
            var path=Path.Combine(root,"journal.db");
            foreach(var p in new[]{path,path+"-wal",path+"-shm",path+"-journal"})EvidenceDurability.NoLinks(p);
            connectionString=new SqliteConnectionStringBuilder{DataSource=path,Pooling=false,DefaultTimeout=5}.ToString();
            using var c=Open();var version=Scalar(c,null,"PRAGMA user_version");
            if(version is <0 or >13)throw new InvalidDataException("Unknown Linux forensic journal version");
            if(version==0)
            {
                if(Scalar(c,null,"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")!=0)throw new InvalidDataException("Unknown Linux forensic journal; retained");
                using var t=c.BeginTransaction();
                Execute(c,t,"""
                    CREATE TABLE metadata(sensor TEXT NOT NULL);
                    INSERT INTO metadata VALUES($sensor);
                    CREATE TABLE work(event_id TEXT PRIMARY KEY,raw BLOB NOT NULL CHECK(length(raw)<=65536),
                      observation BLOB NOT NULL CHECK(length(observation)<=65536),policy BLOB NOT NULL,
                      completion_id TEXT NOT NULL UNIQUE,acquisition BLOB,source_file BLOB,
                      original BLOB CHECK(length(original)<=65536),completion BLOB CHECK(length(completion)<=65536),
                      done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),drop_state TEXT NOT NULL DEFAULT 'not-attempted');
                    PRAGMA user_version=1;
                    """,("$sensor",sensor));t.Commit();
            }
            using(var cmd=Command(c,null,"SELECT sensor FROM metadata"))if((string?)cmd.ExecuteScalar()!=sensor)throw new InvalidDataException("Linux journal belongs to another sensor");
            if(version<2)
            {
                using var t=c.BeginTransaction();
                Execute(c,t,"""
                    CREATE TABLE snapshot_intents(event_id TEXT PRIMARY KEY REFERENCES work(event_id),
                      snapshot_id TEXT NOT NULL UNIQUE,expected_status BLOB NOT NULL,reserved_file BLOB,
                      verified_hash TEXT,verified_file BLOB,state TEXT NOT NULL DEFAULT 'allocation-intent'
                      CHECK(state IN ('allocation-intent','write-intent','bytes-verified','manifest-committed','unavailable')));
                    PRAGMA user_version=3;
                    """);migrationCheckpoint?.Invoke("migration-before-commit");t.Commit();migrationCheckpoint?.Invoke("migration-after-commit");
            }
            else if(version==2)
            {
                using var t=c.BeginTransaction();
                Execute(c,t,"""
                    CREATE TABLE snapshot_intents_v3(event_id TEXT PRIMARY KEY REFERENCES work(event_id),
                      snapshot_id TEXT NOT NULL UNIQUE,expected_status BLOB NOT NULL,reserved_file BLOB,
                      verified_hash TEXT,verified_file BLOB,state TEXT NOT NULL DEFAULT 'allocation-intent'
                      CHECK(state IN ('allocation-intent','write-intent','bytes-verified','manifest-committed','unavailable')));
                    INSERT INTO snapshot_intents_v3 SELECT * FROM snapshot_intents;
                    DROP TABLE snapshot_intents;
                    ALTER TABLE snapshot_intents_v3 RENAME TO snapshot_intents;
                    PRAGMA user_version=3;
                    """);migrationCheckpoint?.Invoke("migration-before-commit");t.Commit();migrationCheckpoint?.Invoke("migration-after-commit");
            }
            if(version<4)MigrateSourceLifecycle(c,migrationCheckpoint);
            if(version<5)MigrateNativeProgress(c,migrationCheckpoint);
            if(version<6)MigrateSourceControl(c,migrationCheckpoint);
            if(version<7)MigrateSourceReconciliation(c,migrationCheckpoint);
            if(version<8)MigrateSourcePolicy(c,migrationCheckpoint);
            if(version<9)MigrateCanonicalIngress(c,migrationCheckpoint);
            if(version<10)MigrateNativePins(c,migrationCheckpoint);
            if(version<11)MigrateSourceActivation(c,migrationCheckpoint);
            if(version<12)MigrateOwnerMethods(c,migrationCheckpoint);
            if(version<13)MigrateRawRotation(c,migrationCheckpoint);
            Execute(c,null,"PRAGMA journal_mode=WAL;");
            lifetimeConnection=Open();
            if(OperatingSystem.IsLinux())foreach(var p in new[]{path,path+"-wal",path+"-shm"})if(File.Exists(p))File.SetUnixFileMode(p,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            EvidenceDurability.DirectoryCommitted(root);
            RecordInterruptedNativePins();
            RecordUnclosedCollectorRestart(DateTimeOffset.UtcNow);
        }
        catch{try{lifetimeConnection?.Dispose();}finally{owner.Dispose();}throw;}
    }
    private void CheckQuota(long reserve)
    {
        foreach(var path in Directory.EnumerateFiles(root))EvidenceDurability.NoLinks(path);
        if(Directory.EnumerateFiles(root).Sum(p=>new FileInfo(p).Length)+reserve>quota)throw new IOException("Linux forensic journal quota reached; raw intake must stop visibly; no native release authorized");
    }
    internal void CommitObservation(ReadOnlyMemory<byte> raw,AgentEvent observation,ForensicPolicy policy)
    {
        lock(gate)
        {
            using var c=Open();using var t=c.BeginTransaction();
            InsertObservation(c,t,raw,observation,policy);t.Commit();
        }
    }
    private string InsertObservation(SqliteConnection c,SqliteTransaction t,ReadOnlyMemory<byte> raw,AgentEvent observation,ForensicPolicy policy)
    {
        var k=observation.Attribution?.LinuxKernel??throw new InvalidDataException("Linux kernel observation required");
        if(observation.Forensics!=null||observation.Trust!=null||!policy.IsValid())throw new InvalidDataException("Unmodified observation and valid policy required");
        var bytes=EventSpool.Encode(observation);
        var decoded=LinuxKernelDecoder.Decode(raw,sensor,k.CollectorInstance,k.CollectorSequence,observation.ObservedUtc);
        if(!EventSpool.Encode(decoded).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Raw native observation differs from typed event");
        var policyBytes=JsonSerializer.SerializeToUtf8Bytes(policy);
            using(var q=Command(c,t,"SELECT raw,observation,policy,completion_id FROM work WHERE event_id=$id",("$id",observation.EventId)))
            using(var r=q.ExecuteReader())if(r.Read())
            {
                if(!((byte[])r[0]).AsSpan().SequenceEqual(raw.Span)||!((byte[])r[1]).AsSpan().SequenceEqual(bytes)||!((byte[])r[2]).AsSpan().SequenceEqual(policyBytes))throw new InvalidDataException("Linux forensic observation identity conflict");
                return r.GetString(3);
            }
            var pending=Scalar(c,t,"SELECT COUNT(*) FROM work WHERE done=0");
            if(pending>=PendingWorkLimit)throw new IOException("Linux work admission limit reached; raw intake must stop visibly");
            CheckQuota((pending+1)*PerWorkReservation);
            var completion=Guid.NewGuid().ToString("N");
            Execute(c,t,"INSERT INTO work(event_id,raw,observation,policy,completion_id) VALUES($id,$raw,$event,$policy,$completion)",
                ("$id",observation.EventId),("$raw",raw.ToArray()),("$event",bytes),("$policy",policyBytes),("$completion",completion));return completion;
    }
    internal Work Read(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT observation,policy,completion_id,acquisition,source_file,original,completion,done,drop_state,raw FROM work WHERE event_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())throw new InvalidDataException("Linux raw journal entry missing");
            T Decode<T>(int n)=>JsonSerializer.Deserialize<T>((byte[])r[n])??throw new InvalidDataException("Null Linux journal field");
            var work=new Work(Decode<AgentEvent>(0),Decode<ForensicPolicy>(1),r.GetString(2),r.IsDBNull(3)?null:Decode<LinuxActorAcquisitionEvidence>(3),r.IsDBNull(4)?null:Decode<FileIdentityEvidence>(4),r.IsDBNull(5)?null:(byte[])r[5],r.IsDBNull(6)?null:(byte[])r[6],r.GetInt32(7)==1,r.GetString(8));
            var k=work.Observation.Attribution?.LinuxKernel??throw new InvalidDataException("Stored native observation missing");
            var decoded=LinuxKernelDecoder.Decode((byte[])r[9],sensor,k.CollectorInstance,k.CollectorSequence,work.Observation.ObservedUtc);
            if(work.Observation.EventId!=id||!work.Policy.IsValid()||!Guid.TryParseExact(work.CompletionId,"N",out _)||!EventSpool.Encode(decoded).AsSpan().SequenceEqual((byte[])r[0]))throw new InvalidDataException("Stored native observation identity differs from raw journal");
            return work;
        }
    }
    internal string[] Pending()
    {
        lock(gate){using var c=Open();using var q=Command(c,null,"SELECT event_id FROM work WHERE done=0 ORDER BY rowid");using var r=q.ExecuteReader();var ids=new List<string>();while(r.Read())ids.Add(r.GetString(0));return ids.ToArray();}
    }
    internal void CommitSnapshot(string id,LinuxActorSnapshot snapshot)
    {
        lock(gate)
        {
            var work=Read(id);var e=work.Observation;var k=e.Attribution!.LinuxKernel!;var n=snapshot.NativeStatus.ToEvidence();
            if(ReadSnapshotIntent(id)!=null)throw new InvalidOperationException("Admitted snapshot must finish through its existing private intent");
            var hash=Convert.ToHexString(SHA256.HashData(snapshot.Bytes.Span));
            if(!n.Ready||!n.Matches(k)||snapshot.Bytes.Length!=(long)snapshot.NativeStatus.Size||!hash.Equals(snapshot.Sha256,StringComparison.OrdinalIgnoreCase)||snapshot.SizeMatchesEarlierObservation!=(n.Size==k.ActorSize))throw new InvalidDataException("Unbound Linux actor snapshot");
            if(work.Acquisition!=null)
            {
                if(work.Acquisition.Status.State!="captured"||!hash.Equals(work.Acquisition.SnapshotSha256,StringComparison.OrdinalIgnoreCase)||JsonSerializer.Serialize(n)!=JsonSerializer.Serialize(work.Acquisition.NativeStatus))throw new InvalidDataException("Linux acquisition identity conflict");
                using var retained=RestoreActor(id);
                if(retained.Image==null)throw new InvalidDataException("Existing private snapshot is no longer recoverable; native release not authorized");
                return;
            }
            CheckQuota(snapshot.Bytes.Length+65536);
            var snapshotId=Guid.NewGuid().ToString("N");var path=SnapshotPath(snapshotId);EvidenceDurability.SaveNew(path,snapshot.Bytes.Span);
            FileIdentityEvidence file;using(var input=File.OpenRead(path))
            {
                file=NativeFileIdentity.Read(input);
                if(input.Length!=snapshot.Bytes.Length||Convert.ToHexString(SHA256.HashData(input))!=hash||!NativeFileIdentity.Same(file,NativeFileIdentity.Read(input)))throw new IOException("Linux private snapshot readback failed");
            }
            var acquisition=new LinuxActorAcquisitionEvidence{SourceEventId=id,NativeObservationSha256=k.NativeObservationSha256,NativeStatus=n,SnapshotId=snapshotId,SnapshotSha256=hash,SnapshotFile=file,PersistedUtc=DateTimeOffset.UtcNow,SizeMatchesEarlierObservation=snapshot.SizeMatchesEarlierObservation,Status=EvidenceStatus.Captured("native-complete-tuple-private-snapshot-verified")};
            CommitAcquisition(work,acquisition,new(){StableId=n.SourceStableId,Size=snapshot.Bytes.Length,Status=EvidenceStatus.Captured("native-device-inode; source-timestamps-unavailable")});
        }
    }
    internal void CommitUnavailable(string id,string reason,LinuxActorLeaseStatus? status=null,string? nativeCode=null)
    {
        lock(gate)
        {
            var work=Read(id);var a=new LinuxActorAcquisitionEvidence{SourceEventId=id,NativeObservationSha256=work.Observation.Attribution!.LinuxKernel!.NativeObservationSha256,NativeStatus=status?.ToEvidence(),Status=new("unavailable",reason,nativeCode)};
            CommitAcquisition(work,a,new());
        }
    }
    private void CommitAcquisition(Work work,LinuxActorAcquisitionEvidence acquisition,FileIdentityEvidence source)
    {
        using var actor=ActorLease.Unavailable(work.Observation,"journal-acquisition-validation");actor.ApplyKernel(work.Observation,sensor);
        if(!acquisition.Matches(work.Observation.Attribution!.LinuxKernel!)||!acquisition.IsValid(actor.Process,work.Observation.EventId,null,null,source))throw new InvalidDataException("Invalid committed Linux acquisition");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(acquisition);var sourceBytes=JsonSerializer.SerializeToUtf8Bytes(source);
        if(work.Acquisition!=null)
        {
            if(!JsonSerializer.SerializeToUtf8Bytes(work.Acquisition).AsSpan().SequenceEqual(bytes)||!JsonSerializer.SerializeToUtf8Bytes(work.SourceFile).AsSpan().SequenceEqual(sourceBytes))throw new InvalidDataException("Linux acquisition already finalized");
            return;
        }
        using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE work SET acquisition=$a,source_file=$s WHERE event_id=$id AND acquisition IS NULL",("$a",bytes),("$s",sourceBytes),("$id",work.Observation.EventId));t.Commit();
    }
    internal ActorLease RestoreActor(string id)
    {
        // Acquisition is immutable once committed. Read validates it under
        // the journal gate; private descriptor verification happens outside.
            var work=Read(id);var e=work.Observation;var native=ReadNativeWorkEvidence(id);var a=work.Acquisition;
            if(a==null)
            {
                if(native?.State!="PIN_INTERRUPTED_UNKNOWN")throw new InvalidDataException("Linux acquisition not finalized");
                // This is a projection of artifact availability. It does not
                // finalize the durable unknown native acquisition outcome.
                a=new(){SourceEventId=id,NativeObservationSha256=e.Attribution!.LinuxKernel!.NativeObservationSha256,
                    Status=EvidenceStatus.Unavailable("linux-native-work-outcome-unknown-no-verified-actor-copy")};
                var unknown=ActorLease.Unavailable(e,a.Status.Reason);unknown.ApplyKernel(e,sensor);
                unknown.LinuxAcquisition=a;unknown.LinuxNativeWork=native;return unknown;
            }
            var actor=ActorLease.Unavailable(e,a.Status.Reason);actor.ApplyKernel(e,sensor);
            if(work.SourceFile==null||!a.Matches(e.Attribution!.LinuxKernel!)||!a.IsValid(actor.Process,id,null,null,work.SourceFile)){actor.Dispose();throw new InvalidDataException("Linux journal acquisition linkage corrupted");}
            actor.File=work.SourceFile;actor.LinuxAcquisition=a;actor.LinuxNativeWork=native;
            if(a.Status.State!="captured")return actor;
            actor.BindingSourceEventId=id;actor.BindingCapturedUtc=a.PersistedUtc;
            try
            {
                var path=SnapshotPath(a.SnapshotId!);EvidenceDurability.NoLinks(path);
                actor.Image=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
                var file=NativeFileIdentity.Read(actor.Image);
                if(!NativeFileIdentity.Same(a.SnapshotFile!,file)||actor.Image.Length!=a.SnapshotFile!.Size||!Convert.ToHexString(SHA256.HashData(actor.Image)).Equals(a.SnapshotSha256,StringComparison.OrdinalIgnoreCase)||!NativeFileIdentity.Same(file,NativeFileIdentity.Read(actor.Image)))throw new InvalidDataException("Linux private snapshot recovery check failed");
                actor.SnapshotFile=file;actor.SnapshotPath=path;actor.Binding=EvidenceStatus.Captured("native-complete-tuple-private-snapshot-recovered");
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                actor.Image?.Dispose();actor.Image=null;
                var failure=new EvidenceStatus("failed","linux-private-snapshot-recovery-failed",ex is System.ComponentModel.Win32Exception nativeError?nativeError.NativeErrorCode.ToString():ex.GetType().Name);
                actor.Binding=failure;actor.LinuxAcquisition=a with{RecoveryStatus=failure};
            }
            return actor;
    }
    internal byte[] PrepareOriginal(string id,Func<Work,AgentEvent> create,Action? beforeCommit=null)=>PrepareEvent(id,false,create,beforeCommit);
    internal byte[] PrepareCompletion(string id,Func<Work,AgentEvent> create)=>PrepareEvent(id,true,create);
    private static string PreparationContext(Work work,LinuxNativeWorkEvidence? native)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
        new{work.Observation,work.Policy,work.CompletionId,work.Acquisition,work.SourceFile,Native=native})));
    private byte[] PrepareEvent(string id,bool completion,Func<Work,AgentEvent> create,Action? beforeCommit=null)
    {
        Work work;PrivateWork operation;LinuxNativeWorkEvidence? native;PreparedAttempt? attempt;string context;
        lock(gate)
        {
            work=Read(id);var prior=completion?work.Completion:work.Original;if(prior!=null)return prior;
            if(completion&&work.Original==null)throw new InvalidDataException("Original not prepared");
            native=ReadNativeWorkEvidence(id);
            context=PreparationContext(work,native);
            attempt=!completion&&originalAttempts.TryGetValue(id,out var saved)?saved:null;
            if(attempt!=null&&attempt.ContextSha256!=context)throw new InvalidDataException("Uncommitted original context changed; frozen attempt retained");
            if(activeNativePins.ContainsKey(id)||native?.State is "PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED")
                throw new InvalidOperationException("Native operation still owns the prepared outcome");
            if(completion&&JsonSerializer.Deserialize<AgentEvent>(work.Original!)!.Forensics?.ActorExecutable.LinuxNativeWork!=native)
                throw new InvalidDataException("Native timeline changed after original event preparation");
            operation=BeginPrivateWorkLocked(id);
        }
        using(operation)
        {
            // Enrichment, hashing and evidence-store fsync may be expensive.
            // The per-event owner excludes duplicates without blocking intake.
            var e=attempt==null?create(work):JsonSerializer.Deserialize<AgentEvent>(attempt.Bytes)!;
            if(e.Forensics?.SensorId!=sensor||e.Attribution?.LinuxKernel!=work.Observation.Attribution?.LinuxKernel||e.Forensics.ActorExecutable.LinuxNativeWork!=native||
                !completion&&(e.EventId!=id||e.Forensics.RelatedEventId!=null)||
                completion&&(e.EventId!=work.CompletionId||e.Forensics.RelatedEventId!=id))throw new InvalidDataException("Prepared Linux event identity changed");
            var bytes=attempt?.Bytes??EventSpool.Encode(e);
            if(!completion)
            {
                lock(gate)
                {
                    if(PreparationContext(Read(id),ReadNativeWorkEvidence(id))!=context)
                        throw new InvalidDataException("Original context changed before its in-memory decision was sealed");
                    originalAttempts[id]=new(context,bytes);
                }
                // No journal lock is held across qualification cuts or the
                // eventual disk transaction. A failed attempt stays frozen.
                beforeCommit?.Invoke();
            }
            lock(gate)
            {
                var current=Read(id);
                if(PreparationContext(current,ReadNativeWorkEvidence(id))!=context)
                    throw new InvalidDataException("Prepared Linux context changed during enrichment");
                var prior=completion?current.Completion:current.Original;
                if(prior!=null){if(!prior.AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Prepared event was concurrently replaced");return prior;}
                var committed=CommitEvent(id,completion?"completion":"original",bytes);
                if(!completion)originalAttempts.Remove(id);
                return committed;
            }
        }
    }
    private byte[] CommitEvent(string id,string field,byte[] bytes)
    {
        using var c=Open();using var t=c.BeginTransaction();Execute(c,t,$"UPDATE work SET {field}=$payload WHERE event_id=$id",("$payload",bytes),("$id",id));t.Commit();return bytes;
    }
    internal void MarkUploadedOrNotApplicable(string id)
    {lock(gate){var work=Read(id);if(work.Completion==null)throw new InvalidDataException("Completion not committed");using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE work SET done=1 WHERE event_id=$id",("$id",id));t.Commit();}}
    internal void RecordDrop(string id,string state)
    {
        if(state is not ("returned" or "unresolved" or "not-applicable"))throw new ArgumentException("Invalid native release state");
        lock(gate){var work=Read(id);if(work.Acquisition==null||state=="not-applicable"&&work.Observation.Attribution!.LinuxKernel!.Lease>0)throw new InvalidOperationException("Committed acquisition and applicable release state required");using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE work SET drop_state=$state WHERE event_id=$id",("$state",state),("$id",id));t.Commit();}
    }
    private string SnapshotPath(string id)
    {if(!Guid.TryParseExact(id,"N",out _))throw new InvalidDataException("Invalid private snapshot identifier");return Path.Combine(root,id+".bin");}
    private SqliteConnection Open()
    {ObjectDisposedException.ThrowIf(disposed,this);var c=new SqliteConnection(connectionString);try{c.Open();Execute(c,null,"PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;");if(Scalar(c,null,"PRAGMA foreign_keys")!=1)throw new InvalidOperationException("SQLite foreign-key enforcement unavailable");return c;}catch{c.Dispose();throw;}}
    private static SqliteCommand Command(SqliteConnection c,SqliteTransaction? t,string sql,params (string,object)[] values)
    {var cmd=c.CreateCommand();cmd.Transaction=t;cmd.CommandText=sql;foreach(var (name,value) in values)cmd.Parameters.AddWithValue(name,value);return cmd;}
    private static long Scalar(SqliteConnection c,SqliteTransaction? t,string sql){using var q=Command(c,t,sql);return Convert.ToInt64(q.ExecuteScalar());}
    private static void Execute(SqliteConnection c,SqliteTransaction? t,string sql,params (string,object)[] values){using var q=Command(c,t,sql,values);q.ExecuteNonQuery();}
    public void Dispose()
    {
        lock(gate)
        {
            if(disposed)return;
            if(nativePolicyOwner!=null)throw new InvalidOperationException("Root policy admission still owns this journal");
            if(activeNativePins.Count!=0||privateWork.Count!=0)throw new InvalidOperationException("Journal still owns in-process native or private work; owner lock retained");
            lifetimeConnection?.Dispose();lifetimeConnection=null;
            owner.Dispose();disposed=true;
        }
    }
}
