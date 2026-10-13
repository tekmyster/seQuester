using System.Text.Json;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed partial class Store
{
    public void InitializeEvidenceTransferStorage()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"actor-evidence",1);return;}
        using var c=Open();using var cmd=Command(c,null,"""
            CREATE TABLE IF NOT EXISTS actor_evidence(endpoint TEXT NOT NULL REFERENCES endpoints(id),evidence_id TEXT NOT NULL,
            completion_event TEXT NOT NULL,receipt_id TEXT NOT NULL,sha256 TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,
            size INTEGER NOT NULL,manifest TEXT NOT NULL,state TEXT NOT NULL,created INTEGER NOT NULL,received INTEGER,
            PRIMARY KEY(endpoint,evidence_id),UNIQUE(endpoint,completion_event));
            """);cmd.ExecuteNonQuery();
    }
    public AgentEvent? EvidenceSource(string endpoint,string eventId)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT payload FROM events WHERE endpoint=$endpoint AND event_id=$event",("$endpoint",endpoint),("$event",eventId));
        return cmd.ExecuteScalar() is string json?JsonSerializer.Deserialize<AgentEvent>(json):null;
    }
    public EvidenceUploadReceipt? EvidenceReceipt(string endpoint,string evidenceId)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT completion_event,sha256,manifest_sha256,size,state,receipt_id,received FROM actor_evidence WHERE endpoint=$endpoint AND evidence_id=$id",("$endpoint",endpoint),("$id",evidenceId));using var r=cmd.ExecuteReader();
        if(!r.Read())return null;
        var size=r.GetInt64(3);var state=r.GetString(4);
        return new(1,endpoint,evidenceId,r.GetString(0),r.GetString(1),r.GetString(2),size,state=="received"?size:0,state,r.GetString(5),r.IsDBNull(6)?null:DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)));
    }
    public byte[] EvidenceManifest(string endpoint,string evidenceId)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT manifest FROM actor_evidence WHERE endpoint=$endpoint AND evidence_id=$id",("$endpoint",endpoint),("$id",evidenceId));
        return Convert.FromBase64String(cmd.ExecuteScalar() as string??throw new InvalidDataException("Evidence record missing."));
    }
    public EvidenceUploadReceipt ReserveEvidence(string endpoint,AgentEvent completion,byte[] manifest,long perSensorBytes,long totalBytes)
    {
        var p=completion.Forensics!.Preservation;
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var active=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))if(Convert.ToInt64(active.ExecuteScalar())!=1)throw new EvidenceUploadException(401,"sensor-revoked");
        using(var quota=Command(c,t,"SELECT COALESCE(SUM(size+65536),0),COALESCE(SUM(CASE WHEN endpoint=$endpoint THEN size+65536 ELSE 0 END),0),COALESCE(SUM(CASE WHEN endpoint=$endpoint AND state='receiving' THEN 1 ELSE 0 END),0) FROM actor_evidence",("$endpoint",endpoint)))
        {using var r=quota.ExecuteReader();r.Read();if(r.GetInt64(0)+p.Size!.Value+65536>totalBytes||r.GetInt64(1)+p.Size.Value+65536>perSensorBytes||Convert.ToInt64(r.GetValue(2))>=32)throw new EvidenceUploadException(507,"evidence-store-quota-exceeded");}
        var receipt=new EvidenceUploadReceipt(1,endpoint,p.EvidenceId!,completion.EventId,p.Sha256!,p.ManifestSha256!,p.Size!.Value,0,"receiving",Guid.NewGuid().ToString("N"),null);
        using(var cmd=Command(c,t,"INSERT INTO actor_evidence(endpoint,evidence_id,completion_event,receipt_id,sha256,manifest_sha256,size,manifest,state,created) VALUES($endpoint,$id,$event,$receipt,$hash,$manifestHash,$size,$manifest,'receiving',$now)",("$endpoint",endpoint),("$id",receipt.EvidenceId),("$event",completion.EventId),("$receipt",receipt.ReceiptId),("$hash",receipt.Sha256),("$manifestHash",receipt.ManifestSha256),("$size",receipt.Size),("$manifest",Convert.ToBase64String(manifest)),("$now",Now())))cmd.ExecuteNonQuery();
        Audit(c,t,"Actor evidence transfer reserved",JsonSerializer.Serialize(new{Sensor=endpoint,receipt.EvidenceId,receipt.ReceiptId,CompletionEvent=completion.EventId}));t.Commit();return receipt;
    }
    public EvidenceUploadReceipt CommitEvidence(EvidenceUploadReceipt receipt,AgentEvent completion)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var now=DateTimeOffset.FromUnixTimeMilliseconds(Now());
        var forensic=completion.Forensics!;var id=receipt.ReceiptId;
        var transfer=new EvidenceTransferEvidence(receipt.EvidenceId,completion.EventId,id,receipt.Sha256,receipt.ManifestSha256,receipt.Size,now);
        var e=completion with{EventId=id,ObservedUtc=now,Source="Evidence transfer",Operation="Actor executable received and hash verified by server",Trust=null,
            Forensics=forensic with{EventId=id,RelatedEventId=forensic.RelatedEventId,ObservedUtc=now,CapturedUtc=now,EnrichedUtc=now,CollectorEpoch=id,CollectorSequence=1,ProcessSequence=null,MonotonicTicks=System.Diagnostics.Stopwatch.GetTimestamp(),MonotonicFrequency=System.Diagnostics.Stopwatch.Frequency,Transfer=transfer,Response=new("actor-evidence-upload","received",completion.EventId)}};
        if(!e.Forensics.IsValid())throw new InvalidDataException("Invalid transfer evidence.");
        using(var update=Command(c,t,"UPDATE actor_evidence SET state='received',received=$now WHERE endpoint=$endpoint AND evidence_id=$id AND state='receiving'",("$now",now.ToUnixTimeMilliseconds()),("$endpoint",receipt.SensorId),("$id",receipt.EvidenceId)))
        {
            if(update.ExecuteNonQuery()!=1)throw new EvidenceUploadException(409,"evidence-state-changed");
        }
        using(var insert=Command(c,t,"INSERT INTO events(endpoint,event_id,received,payload) VALUES($endpoint,$id,$now,$payload)",("$endpoint",receipt.SensorId),("$id",id),("$now",now.ToUnixTimeMilliseconds()),("$payload",JsonSerializer.Serialize(e))))insert.ExecuteNonQuery();
        Audit(c,t,"Actor evidence received and verified",JsonSerializer.Serialize(transfer));t.Commit();
        return receipt with{State="received",ReceivedUtc=now,ReceivedBytes=receipt.Size};
    }
}
