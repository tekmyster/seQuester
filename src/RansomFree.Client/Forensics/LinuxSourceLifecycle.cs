using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Companion to the existing raw/snapshot journal. No native calls or implied
// cancellation occur here. Boundaries survive CLOSED and are never healed by
// later successful writes. SQLite/WAL capacity is not physically reserved.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record SourceLifecycle(string Id,string BankId,string CollectorInstance,string ProviderEpoch,
        string? LostAtOpen,string? LatestLost,DateTimeOffset OpenedUtc,string State,DateTimeOffset? CloseReturnedUtc);
    internal sealed record SourceWorkKey(string EventId,string ProviderEpoch,string Cookie,long Lease);
    internal sealed record SourceBoundary(string Reason,DateTimeOffset RecordedUtc,long? InputLength,
        string? PreviousLost,string? SampledLost,string? SampleError,string? ObservedEpoch,SourceWorkKey[] Unresolved,
        bool OpenEnded=true,string UnresolvedStatus="captured",int UnresolvedOmitted=0,bool SampleErrorTruncated=false);
    private static void MigrateSourceLifecycle(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();
        Execute(c,t,"""
            CREATE TABLE source_banks(bank_id TEXT PRIMARY KEY,path TEXT NOT NULL UNIQUE,
              stable_id TEXT NOT NULL UNIQUE,bytes INTEGER NOT NULL CHECK(bytes>0));
            CREATE TABLE source_lifecycle(session_id TEXT PRIMARY KEY,bank_id TEXT NOT NULL REFERENCES source_banks(bank_id),
              collector TEXT NOT NULL UNIQUE,provider_epoch TEXT NOT NULL,lost_at_open TEXT,latest_lost TEXT,
              opened_utc TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('OPEN','CONTINUITY_FAULTED','CLOSE_UNKNOWN_OPEN','CLOSED')),
              close_returned_utc TEXT);
            CREATE TABLE source_boundaries(sequence INTEGER PRIMARY KEY,session_id TEXT NOT NULL REFERENCES source_lifecycle(session_id),
              boundary BLOB NOT NULL CHECK(length(boundary)<=1048576));
            PRAGMA user_version=4;
            """);
        checkpoint?.Invoke("lifecycle-migration-before-commit");t.Commit();checkpoint?.Invoke("lifecycle-migration-after-commit");
    }
    private static bool Counter(string? value)=>value!=null&&ulong.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out var n)&&n.ToString(CultureInfo.InvariantCulture)==value;
    internal SourceLifecycle OpenSource(LinuxRawDeliveryMap bank,string epoch,string? lost,DateTimeOffset openedUtc,long bankQuota)
        =>OpenSourceCore(new(bank.SensorId,bank.FullPath,bank.BankIdentity,bank.CollectorInstance,bank.Reopened,"raw-reserve-v2"),epoch,lost,openedUtc,bankQuota,null);
    private sealed record SourceBank(string Sensor,string FullPath,FileIdentityEvidence BankIdentity,string CollectorInstance,bool Reopened,string Format);
    internal SourceLifecycle PrepareControlledSource(LinuxRawIngressReserve bank,ForensicPolicy policy,string? lost,DateTimeOffset preparedUtc,long bankQuota)
    {
        if(bank.Reopened||bank.Entries.Length!=0||bank.FirstBoundary!=null)throw new InvalidOperationException("Controlled source preparation requires a fresh empty raw ingress bank; no automatic recovery opening");
        return OpenSourceCore(new(bank.SensorId,bank.FullPath,bank.BankIdentity,bank.CollectorInstance,false,bank.Format),bank.ProviderEpoch,lost,preparedUtc,bankQuota,LinuxRawPolicyCodec.Encode(policy));
    }
    private SourceLifecycle OpenSourceCore(SourceBank bank,string epoch,string? lost,DateTimeOffset openedUtc,long bankQuota,byte[]? policy)
    {
        if(bank.Sensor!=sensor||!Counter(epoch)||epoch=="0"||lost!=null&&!Counter(lost)||openedUtc==default||bank.BankIdentity.StableId==null||bank.BankIdentity.Size is not >0)
            throw new InvalidDataException("Validated bank identity, provider epoch and loader sample required");
        lock(gate)
        {
            if(admissionChecking)throw new InvalidOperationException("Owned source admission is checking retained evidence");
            using var c=Open();using var t=c.BeginTransaction();
            // A previous owner may still be closing in the kernel. Actual
            // close completion, or an explicit live no-controller startup
            // terminal proof, is required before a different session/bank.
            if(Scalar(c,t,"SELECT count(*) FROM source_lifecycle WHERE state<>'CLOSED'")!=0)
                throw new InvalidOperationException("SOURCE_OWNER_UNRESOLVED: previous source has no actual close receipt");
            string? bankId=null;
            using(var q=Command(c,t,"SELECT bank_id,stable_id,bytes FROM source_banks WHERE path=$path",("$path",bank.FullPath)))
            using(var r=q.ExecuteReader())if(r.Read())
            {
                if(r.GetString(1)!=bank.BankIdentity.StableId||r.GetInt64(2)!=bank.BankIdentity.Size)throw new InvalidDataException("RAW_BANK_IDENTITY_CHANGED: retained bank was replaced");
                bankId=r.GetString(0);
            }
            if(bankId!=null&&ReadSourceBankFormat(c,t,bankId)!=bank.Format)throw new InvalidDataException("Retained source bank format differs");
            if(bankId==null)
            {
                if(checked(Scalar(c,t,"SELECT COALESCE(SUM(bytes),0) FROM source_banks")+bank.BankIdentity.Size.Value)>bankQuota)
                    throw new IOException("RAW_BANK_QUOTA_EXHAUSTED: source not opened; retained banks are never evicted");
                bankId=Guid.NewGuid().ToString("N");
                Execute(c,t,"INSERT INTO source_banks VALUES($id,$path,$stable,$bytes)",("$id",bankId),("$path",bank.FullPath),("$stable",bank.BankIdentity.StableId),("$bytes",bank.BankIdentity.Size.Value));
                Execute(c,t,"INSERT INTO source_bank_formats VALUES($id,$format)",("$id",bankId),("$format",bank.Format));
            }
            var result=new SourceLifecycle(Guid.NewGuid().ToString("N"),bankId,bank.CollectorInstance,epoch,lost,lost,openedUtc,"OPEN",null);
            Execute(c,t,"INSERT INTO source_lifecycle VALUES($id,$bank,$collector,$epoch,$lost,$lost,$time,'OPEN',NULL)",
                ("$id",result.Id),("$bank",bankId),("$collector",result.CollectorInstance),("$epoch",epoch),("$lost",(object?)lost??DBNull.Value),("$time",openedUtc.ToString("O")));
            if(policy!=null)InsertPreparedSource(c,t,result.Id,policy,openedUtc);
            if(bank.Reopened)InsertBoundary(c,t,result.Id,new("COLLECTOR_RESTART_UNKNOWN",openedUtc,null,null,lost,null,null,[]));
            t.Commit();return result;
        }
    }
    internal SourceLifecycle ReadSource(string id)
    {lock(gate){using var c=Open();return ReadSource(c,id);}}
    private SourceLifecycle ReadSource(SqliteConnection c,string id)
    {
            using var q=Command(c,null,"SELECT bank_id,collector,provider_epoch,lost_at_open,latest_lost,opened_utc,state,close_returned_utc FROM source_lifecycle WHERE session_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())throw new InvalidDataException("Source lifecycle missing");
            return new(id,r.GetString(0),r.GetString(1),r.GetString(2),r.IsDBNull(3)?null:r.GetString(3),r.IsDBNull(4)?null:r.GetString(4),DateTimeOffset.Parse(r.GetString(5),CultureInfo.InvariantCulture),r.GetString(6),r.IsDBNull(7)?null:DateTimeOffset.Parse(r.GetString(7),CultureInfo.InvariantCulture));
    }
    internal SourceBoundary[] ReadSourceBoundaries(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT boundary FROM source_boundaries WHERE session_id=$id ORDER BY sequence",("$id",id));using var r=q.ExecuteReader();var all=new List<SourceBoundary>();
            while(r.Read())all.Add(JsonSerializer.Deserialize<SourceBoundary>((byte[])r[0])??throw new InvalidDataException("Source boundary missing"));return all.ToArray();
        }
    }
    private static byte[] EncodeBoundary(SourceBoundary boundary)
    {
        if(boundary.Reason.Length>128||boundary.UnresolvedStatus.Length>128)throw new InvalidDataException("Unbounded source reason/status");
        if(boundary.SampleError?.Length>128)boundary=boundary with{SampleError=boundary.SampleError[..128],SampleErrorTruncated=true};
        if(boundary.Unresolved.Length>4096)boundary=boundary with{Unresolved=boundary.Unresolved[..4096],UnresolvedOmitted=checked(boundary.UnresolvedOmitted+boundary.Unresolved.Length-4096)};
        var bytes=JsonSerializer.SerializeToUtf8Bytes(boundary);
        while(bytes.Length>1048576&&boundary.Unresolved.Length>0)
        {
            var keep=boundary.Unresolved.Length/2;
            boundary=boundary with{Unresolved=boundary.Unresolved[..keep],UnresolvedOmitted=checked(boundary.UnresolvedOmitted+boundary.Unresolved.Length-keep)};
            bytes=JsonSerializer.SerializeToUtf8Bytes(boundary);
        }
        if(bytes.Length>1048576)throw new InvalidDataException("Source boundary exceeds admitted size");return bytes;
    }
    private static void InsertBoundary(SqliteConnection c,SqliteTransaction t,string id,SourceBoundary boundary)
        =>Execute(c,t,"INSERT INTO source_boundaries(session_id,boundary) VALUES($id,$value)",("$id",id),("$value",EncodeBoundary(boundary)));
    internal void TransitionSource(string id,string state,SourceBoundary boundary,bool deduplicate=false)
    {
        lock(gate)
        {
            var prior=ReadSource(id);
            if(state=="CLOSE_UNKNOWN_OPEN"&&ReadSourceOwnership(id)?.Phase=="PREPARED_NO_OWNER")throw new InvalidOperationException("No controller close intent before an actual opening attempt");
            if(state is not ("CONTINUITY_FAULTED" or "CLOSE_UNKNOWN_OPEN")||prior.State=="CLOSED"||prior.State=="CLOSE_UNKNOWN_OPEN"&&state!="CLOSE_UNKNOWN_OPEN"||!boundary.OpenEnded||boundary.RecordedUtc==default)
                throw new InvalidOperationException("Invalid source boundary transition");
            if(boundary.SampledLost!=null&&!Counter(boundary.SampledLost))throw new InvalidDataException("Noncanonical loader counter");
            var bytes=EncodeBoundary(boundary); // Bound the material before opening a write transaction.
            using var c=Open();using var t=c.BeginTransaction();
            if(deduplicate)
            {
                using var priorBoundary=Command(c,t,"SELECT count(*) FROM source_boundaries WHERE session_id=$id AND boundary=$value",("$id",id),("$value",bytes));
                if(Convert.ToInt64(priorBoundary.ExecuteScalar())!=0)return;
            }
            Execute(c,t,"INSERT INTO source_boundaries(session_id,boundary) VALUES($id,$value)",("$id",id),("$value",bytes));
            Execute(c,t,"UPDATE source_lifecycle SET state=$state,latest_lost=$lost WHERE session_id=$id",("$state",state),("$lost",(object?)boundary.SampledLost??DBNull.Value),("$id",id));t.Commit();
        }
    }
    internal void RecordSourceCloseReturned(string id,DateTimeOffset returnedUtc)
    {
        lock(gate)
        {
            var prior=ReadSource(id);
            if(prior.State=="CLOSED")
            {
                if(prior.CloseReturnedUtc!=returnedUtc)throw new InvalidDataException("Original close return cannot be replaced");return;
            }
            if(ReadSource(id).State!="CLOSE_UNKNOWN_OPEN"||returnedUtc==default)throw new InvalidOperationException("Durable close intent required");
            if(ReadSourceOwnership(id)?.Phase=="PREPARED_NO_OWNER")throw new InvalidOperationException("An unopened controller cannot have a native close-return receipt");
            if(IsControlledRawFormat(ReadSourceBankFormat(id)))
            {
                var receipt=ReadOwnerMethodReturn(id,"CLOSE");
                if(receipt?.Outcome!="returned"||receipt.ReturnedUtc!=returnedUtc)throw new InvalidOperationException("Successful actual close method receipt required");
            }
            using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE source_lifecycle SET state='CLOSED',close_returned_utc=$time WHERE session_id=$id",("$time",returnedUtc.ToString("O")),("$id",id));
            Execute(c,t,"UPDATE source_ownership SET phase='CLOSED',recorded_utc=$time WHERE session_id=$id",("$time",returnedUtc.ToString("O")),("$id",id));t.Commit();
        }
    }
    internal void RecordUnclosedCollectorRestart(DateTimeOffset time)
    {
        lock(gate)
        {
            using var c=Open();var ids=new List<string>();
            using(var q=Command(c,null,"SELECT session_id FROM source_lifecycle WHERE state<>'CLOSED'"))using(var r=q.ExecuteReader())while(r.Read())ids.Add(r.GetString(0));
            foreach(var id in ids)
            {
                var s=ReadSource(id);
                if(ReadSourceOwnership(id)?.Phase=="PREPARED_NO_OWNER")
                {
                    // Preparation is not an interrupted native owner. Preserve
                    // the startup gap, deny opening, and create no false owner
                    // reconciliation receipt or controller-close timestamp.
                    TransitionSource(id,"CONTINUITY_FAULTED",new("PREPARED_SOURCE_INTERRUPTED_NO_OWNER",time,null,s.LatestLost,null,"controller-open-never-attempted",null,[]));
                    continue;
                }
                var receipt=PrepareSourceReconciliation(s,time);
                var boundary=new SourceBoundary("COLLECTOR_RESTART_UNKNOWN",time,null,s.LatestLost,null,"counter-unavailable-on-restart",null,UnresolvedSourceWork(id));
                // Receipt, restart boundary and lifecycle transition share one
                // commit. A failed receipt or boundary retains all prior state.
                using(var t=c.BeginTransaction())
                {
                    if(receipt!=null)Execute(c,t,"INSERT INTO source_reconciliation VALUES($id,$receipt)",("$id",id),("$receipt",receipt));
                    InsertBoundary(c,t,id,boundary);
                    Execute(c,t,"UPDATE source_lifecycle SET state=$state,latest_lost=NULL WHERE session_id=$id",("$id",id),("$state",s.State=="CLOSE_UNKNOWN_OPEN"?s.State:"CONTINUITY_FAULTED"));
                    t.Commit();
                }
                FinalizeSourceWorkUnavailable(id,"ACTOR_COPY_UNAVAILABLE_COLLECTOR_RESTART");
            }
        }
    }
    internal SourceWorkKey[] UnresolvedSourceWork(string sessionId)
    {
        lock(gate)
        {
            var source=ReadSource(sessionId);
            return Pending().Select(Read).Where(w=>w.Observation.Attribution!.LinuxKernel!.ProviderEpoch==source.ProviderEpoch&&w.Observation.Attribution.LinuxKernel.CollectorInstance==source.CollectorInstance&&(w.Acquisition==null||w.DropState is not ("returned" or "not-applicable")))
                .Select(w=>new SourceWorkKey(w.Observation.EventId,source.ProviderEpoch,w.Observation.Attribution!.LinuxKernel!.Cookie,w.Observation.Attribution.LinuxKernel.Lease)).ToArray();
        }
    }
    internal bool HasWork(string id)
    {lock(gate){using var c=Open();using var q=Command(c,null,"SELECT count(*) FROM work WHERE event_id=$id",("$id",id));return Convert.ToInt64(q.ExecuteScalar())==1;}}
    internal void FinalizeSourceWorkUnavailable(string sessionId,string reason)
    {
        SourceLifecycle source;string[] pending;
        lock(gate){source=ReadSource(sessionId);pending=Pending();}
        foreach(var id in pending)
        {
            bool recover=false;
            lock(gate)
            {
                // In-process private/native work and unknown durable pins own
                // their outcome. Never finalize them from an unrelated stop.
                if(NativePinOwnsOutcome(id))continue;
                var w=Read(id);if(w.Observation.Attribution!.LinuxKernel!.ProviderEpoch!=source.ProviderEpoch||w.Observation.Attribution.LinuxKernel.CollectorInstance!=source.CollectorInstance||w.Acquisition!=null)continue;
                var intent=ReadSnapshotIntent(id);
                if(intent?.State=="bytes-verified")recover=true;
                else
                {
                    CommitUnavailable(id,reason,intent?.ExpectedStatus??ReadNativeProgress(id)?.Status);
                    if(intent!=null)SetSnapshotState(id,"unavailable");
                }
            }
            if(recover)RecoverAdmittedSnapshot(id); // Heavy verification outside journal gate.
        }
    }
}
