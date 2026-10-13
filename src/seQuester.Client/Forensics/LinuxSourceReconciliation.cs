using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace RansomFree.Client.Forensics;

// Receipt only. Stored bank identity is historical evidence, not a new stat or
// proof that an old controller closed. No native/bank file is opened here.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record SourceReconciliation(int SchemaVersion,string Status,string Reason,
        string SessionId,string BankId,string StoredBankPath,string StoredBankStableId,long StoredBankBytes,
        string CollectorInstance,string ProviderEpoch,string? LastKnownLost,string PriorLifecycleState,
        DateTimeOffset FirstObservedUtc);
    private static void MigrateSourceReconciliation(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_reconciliation(session_id TEXT PRIMARY KEY REFERENCES source_lifecycle(session_id),
              receipt BLOB NOT NULL CHECK(typeof(receipt)='blob' AND length(receipt)<=65536));
            PRAGMA user_version=7;
            """);checkpoint?.Invoke("reconciliation-migration-before-commit");t.Commit();checkpoint?.Invoke("reconciliation-migration-after-commit");
    }
    internal SourceReconciliation? ReadSourceReconciliation(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT receipt FROM source_reconciliation WHERE session_id=$id",("$id",id));
            var raw=q.ExecuteScalar();if(raw==null)return null;
            var bytes=raw as byte[]??throw new InvalidDataException("Source reconciliation receipt is not a blob");
            var value=JsonSerializer.Deserialize<SourceReconciliation>(bytes)??throw new InvalidDataException("Missing source reconciliation receipt");
            ValidateReconciliation(value,id);
            var source=ReadSource(id);
            if(source.BankId!=value.BankId||source.CollectorInstance!=value.CollectorInstance||source.ProviderEpoch!=value.ProviderEpoch)
                throw new InvalidDataException("Reconciliation receipt belongs to a different source");
            using var bank=Command(c,null,"SELECT path,stable_id,bytes FROM source_banks WHERE bank_id=$id",("$id",value.BankId));using var r=bank.ExecuteReader();
            if(!r.Read()||r.GetString(0)!=value.StoredBankPath||r.GetString(1)!=value.StoredBankStableId||r.GetInt64(2)!=value.StoredBankBytes)
                throw new InvalidDataException("Reconciliation receipt differs from recorded bank identity");
            return value;
        }
    }
    private static void ValidateReconciliation(SourceReconciliation value,string id)
    {
        if(value.SchemaVersion!=1||value.Status!="RECONCILIATION_REQUIRED"||value.Reason!="COLLECTOR_RESTART_UNKNOWN"||value.SessionId!=id||
            !Guid.TryParseExact(id,"N",out _)||!Guid.TryParseExact(value.BankId,"N",out _)||!Guid.TryParseExact(value.CollectorInstance,"N",out _)||
            !Counter(value.ProviderEpoch)||value.ProviderEpoch=="0"||value.LastKnownLost!=null&&!Counter(value.LastKnownLost)||
            value.PriorLifecycleState is not ("OPEN" or "CONTINUITY_FAULTED" or "CLOSE_UNKNOWN_OPEN")||value.FirstObservedUtc==default||
            string.IsNullOrWhiteSpace(value.StoredBankPath)||string.IsNullOrWhiteSpace(value.StoredBankStableId)||value.StoredBankBytes<=0)
            throw new InvalidDataException("Invalid receipt-only reconciliation evidence");
    }
    private byte[]? PrepareSourceReconciliation(SourceLifecycle source,DateTimeOffset observedUtc)
    {
        lock(gate)
        {
            // Preserve the first pre-restart state/loss across repeated reopen.
            // This record confers no opening, status, SELECT or DROP authority.
            var id=source.Id;
            if(ReadSourceReconciliation(id)!=null)return null;
            if(source.State=="CLOSED")throw new InvalidOperationException("Closed source requires no ownership reconciliation");
            using var c=Open();SourceReconciliation value;
            using(var q=Command(c,null,"SELECT path,stable_id,bytes FROM source_banks WHERE bank_id=$id",("$id",source.BankId)))
            using(var r=q.ExecuteReader())
            {
                if(!r.Read())throw new InvalidDataException("Historical source bank missing");
                value=new(1,"RECONCILIATION_REQUIRED","COLLECTOR_RESTART_UNKNOWN",id,source.BankId,r.GetString(0),r.GetString(1),r.GetInt64(2),
                    source.CollectorInstance,source.ProviderEpoch,source.LatestLost,source.State,observedUtc);
            }
            ValidateReconciliation(value,id);var bytes=JsonSerializer.SerializeToUtf8Bytes(value);
            if(bytes.Length>65536)throw new InvalidDataException("Source reconciliation receipt exceeds bound");
            return bytes;
        }
    }
}
