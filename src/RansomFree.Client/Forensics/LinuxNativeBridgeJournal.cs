using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Optional export ledger in the existing forensic journal. Import receipts
// acknowledge only an immutable duplicate; source rows/artifacts are retained.
internal sealed partial class LinuxForensicJournal
{
    private void EnsureNativeExports()
    {
        using var c=Open();Execute(c,null,"""
            CREATE TABLE IF NOT EXISTS native_bridge_exports(event_id TEXT PRIMARY KEY REFERENCES work(event_id),
              version INTEGER NOT NULL CHECK(version=1),packet_sha256 TEXT NOT NULL,published_utc TEXT NOT NULL,
              imported_receipt BLOB CHECK(length(imported_receipt)<=2048),imported_utc TEXT,
              delivery_retired INTEGER NOT NULL DEFAULT 0 CHECK(delivery_retired IN(0,1)));
            """);
    }
    internal string[] PendingNativeExports(int maximum=4)
    {
        if(maximum is <1 or >128)throw new ArgumentException("Bounded export inventory required");
        lock(gate)
        {
            EnsureNativeExports();using var c=Open();using var q=Command(c,null,"""
                SELECT w.event_id FROM work w LEFT JOIN native_bridge_exports x ON x.event_id=w.event_id
                WHERE w.done=1 AND x.imported_receipt IS NULL ORDER BY w.rowid LIMIT $limit
                """,("$limit",maximum));using var r=q.ExecuteReader();var ids=new List<string>();while(r.Read())ids.Add(r.GetString(0));return ids.ToArray();
        }
    }
    internal void RecordNativeExport(string id,string packetHash)
    {
        if(!EvidenceTransferLimits.Hash(packetHash)||packetHash!=packetHash.ToUpperInvariant())throw new ArgumentException("Canonical packet hash required");
        lock(gate)
        {
            var work=Read(id);if(!work.Done||work.Original==null||work.Completion==null)throw new InvalidOperationException("Completed committed evidence required for export");
            EnsureNativeExports();CheckQuota(4096);using var c=Open();using var t=c.BeginTransaction();
            using(var q=Command(c,t,"SELECT packet_sha256 FROM native_bridge_exports WHERE event_id=$id",("$id",id)))
                if(q.ExecuteScalar() is string prior){if(prior!=packetHash)throw new InvalidDataException("Native export identity conflict; retained");t.Commit();return;}
            Execute(c,t,"INSERT INTO native_bridge_exports VALUES($id,1,$hash,$time,NULL,NULL,0)",("$id",id),("$hash",packetHash),("$time",DateTimeOffset.UtcNow.ToString("O")));t.Commit();
        }
    }
    internal string? ImportedNativeExportHash(string id)
    {
        if(!EvidenceTransferLimits.Id(id))throw new ArgumentException("Canonical source event identity required");
        lock(gate)
        {
            EnsureNativeExports();using var c=Open();using var q=Command(c,null,
                "SELECT packet_sha256 FROM native_bridge_exports WHERE event_id=$id AND imported_receipt IS NOT NULL",("$id",id));
            return q.ExecuteScalar() as string;
        }
    }
    internal Work RecordNativeImport(LinuxNativeBridgeImport.Receipt receipt)
    {
        if(receipt.Version!=1||receipt.SensorId!=sensor||!EvidenceTransferLimits.Id(receipt.SourceEventId)||!EvidenceTransferLimits.Id(receipt.CompletionEventId)||!EvidenceTransferLimits.Hash(receipt.PacketSha256))throw new InvalidDataException("Native import receipt identity invalid");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(receipt);if(bytes.Length>2048)throw new InvalidDataException("Native import receipt exceeds bound");
        lock(gate)
        {
            var work=Read(receipt.SourceEventId);
            if(!work.Done||work.CompletionId!=receipt.CompletionEventId||work.Original==null||work.Completion==null)throw new InvalidDataException("Native import receipt has no committed event pair");
            EnsureNativeExports();CheckQuota(4096);using var c=Open();using var t=c.BeginTransaction();
            using(var q=Command(c,t,"SELECT packet_sha256,imported_receipt FROM native_bridge_exports WHERE event_id=$id",("$id",receipt.SourceEventId)))using(var r=q.ExecuteReader())
            {
                if(!r.Read()||r.GetString(0)!=receipt.PacketSha256)throw new InvalidDataException("Native import receipt differs from published packet");
                if(!r.IsDBNull(1)){if(!((byte[])r[1]).AsSpan().SequenceEqual(bytes))throw new InvalidDataException("Native import receipt conflicts with prior acknowledgment");t.Commit();return work;}
            }
            Execute(c,t,"UPDATE native_bridge_exports SET imported_receipt=$receipt,imported_utc=$time WHERE event_id=$id",
                ("$receipt",bytes),("$time",DateTimeOffset.UtcNow.ToString("O")),("$id",receipt.SourceEventId));t.Commit();return work;
        }
    }
    internal LinuxNativeBridgeImport.Receipt[] PendingNativeImportRetirements()
    {
        lock(gate)
        {
            EnsureNativeExports();using var c=Open();using var q=Command(c,null,"SELECT imported_receipt FROM native_bridge_exports WHERE imported_receipt IS NOT NULL AND delivery_retired=0 ORDER BY rowid LIMIT 4");
            using var r=q.ExecuteReader();var receipts=new List<LinuxNativeBridgeImport.Receipt>();while(r.Read())receipts.Add(JsonSerializer.Deserialize<LinuxNativeBridgeImport.Receipt>((byte[])r[0])??throw new InvalidDataException("Native import receipt missing"));return receipts.ToArray();
        }
    }
    internal void FinishNativeImportRetirement(LinuxNativeBridgeImport.Receipt receipt)
    {
        lock(gate)
        {
            _=RecordNativeImport(receipt);using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"UPDATE native_bridge_exports SET delivery_retired=1 WHERE event_id=$id",("$id",receipt.SourceEventId));t.Commit();
        }
    }
}
