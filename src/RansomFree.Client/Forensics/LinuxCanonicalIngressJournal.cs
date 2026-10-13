using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Historical indexing only. Neither canonical events nor raw diagnostics are
// native capabilities. Dispatch still requires a separately qualified live
// source owner, exact device binding and durable one-use operation intent.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record RawIngressDiagnostic(int SchemaVersion,string SourceSessionId,string DeliveryId,
        int BankSequence,string RawSha256,int RawLength,DateTimeOffset ReceivedUtc,
        LinuxSourceWorkBarrier.View ReceiveView,string Classification,string Reason);
    internal sealed record IndexedIngress(string Status,string DeliveryId,string? CanonicalEventId,
        AgentEvent? CanonicalEvent,RawIngressDiagnostic? Diagnostic,bool RequiresSourceStop,bool AlreadyIndexed);
    private static void MigrateCanonicalIngress(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE source_ingress(session_id TEXT NOT NULL REFERENCES source_lifecycle(session_id),
              delivery_id TEXT NOT NULL,bank_id TEXT NOT NULL REFERENCES source_banks(bank_id),
              sequence INTEGER NOT NULL CHECK(sequence>0),entry BLOB NOT NULL CHECK(length(entry)<=4096),
              classification TEXT NOT NULL CHECK(classification IN ('RAW_VALID','DUPLICATE','RAW_INVALID','RAW_FOREIGN_EPOCH',
                'RAW_AFTER_FAULT','RAW_AFTER_STOP','POLICY_EVIDENCE_MISSING','POLICY_EVIDENCE_INVALID','CANONICAL_KEY_CONTRADICTION')),
              reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 128),canonical_event_id TEXT,
              PRIMARY KEY(session_id,delivery_id),UNIQUE(session_id,sequence),
              FOREIGN KEY(session_id,canonical_event_id) REFERENCES canonical_events(session_id,event_id));
            CREATE TABLE canonical_events(event_id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES source_lifecycle(session_id),
              provider_epoch TEXT NOT NULL,positive_cookie TEXT,delivery_key TEXT,first_delivery_id TEXT NOT NULL,
              first_raw_sha256 TEXT NOT NULL,policy_sha256 TEXT NOT NULL,decoded BLOB NOT NULL CHECK(length(decoded)<=65536),
              CHECK((positive_cookie IS NOT NULL AND typeof(positive_cookie)='text' AND positive_cookie<>'0' AND delivery_key IS NULL)
                OR (positive_cookie IS NULL AND delivery_key IS NOT NULL)),
              UNIQUE(session_id,event_id),UNIQUE(session_id,delivery_key),
              FOREIGN KEY(session_id,first_delivery_id) REFERENCES source_ingress(session_id,delivery_id),
              FOREIGN KEY(session_id,policy_sha256) REFERENCES source_policy(session_id,sha256));
            CREATE UNIQUE INDEX canonical_positive_cookie ON canonical_events(session_id,provider_epoch,positive_cookie)
              WHERE positive_cookie IS NOT NULL;
            PRAGMA user_version=9;
            """);checkpoint?.Invoke("canonical-ingress-migration-before-commit");t.Commit();checkpoint?.Invoke("canonical-ingress-migration-after-commit");
    }
    internal void VerifyIngressBank(string sessionId,LinuxRawIngressReserve bank)
    {
        var source=ReadSource(sessionId);
        if(bank.SensorId!=sensor||bank.CollectorInstance!=source.CollectorInstance||bank.ProviderEpoch!=source.ProviderEpoch)
            throw new InvalidDataException("Ingress bank does not belong to this source session");
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT b.path,b.stable_id,b.bytes,f.format FROM source_banks b JOIN source_bank_formats f USING(bank_id) WHERE b.bank_id=$id",("$id",source.BankId));using var r=q.ExecuteReader();
            if(!r.Read()||r.GetString(0)!=bank.FullPath||r.GetString(1)!=bank.BankIdentity.StableId||r.GetInt64(2)!=bank.BankIdentity.Size||r.GetString(3)!=bank.Format)
                throw new InvalidDataException("Verified source bank descriptor differs from stored identity");
        }
    }
    private static RawIngressDiagnostic IngressDiagnostic(string session,LinuxRawIngressReserve.Entry entry,string classification,string reason)
        =>new(1,session,entry.DeliveryId,entry.Sequence,entry.RawSha256,entry.RawLength,entry.ReceivedUtc,entry.View,classification,reason);
    private static bool MustStop(string classification)=>classification is "RAW_INVALID" or "RAW_FOREIGN_EPOCH" or "POLICY_EVIDENCE_MISSING" or "POLICY_EVIDENCE_INVALID" or "CANONICAL_KEY_CONTRADICTION";
    private void RequireTargetAssociation(string session,LinuxKernelEvidence evidence)
    {
        var control=ReadSourceControl(session);
        var ready=control==null?null:LinuxControlledLoaderProtocol.ParseReady(control.Ready);
        if(evidence.NativeSchemaVersion==5)
        {
            if(ready?.ControlVersion is 2 or 3 or 4)throw new InvalidDataException("Legacy observation belongs to no v2 target set");
            return;
        }
        var target=evidence.TargetIdentity;
        var versionMatches=evidence.NativeSchemaVersion==8?ready?.ControlVersion==4:evidence.NativeSchemaVersion==7?ready?.ControlVersion is 3 or 4:ready?.ControlVersion==2;
        if(!versionMatches||target==null||evidence.ProviderEpoch!=ready!.Epoch.ToString(System.Globalization.CultureInfo.InvariantCulture)||
            ready.Targets?.Contains(target.Ordinal,target.Device,ulong.Parse(target.Inode,System.Globalization.CultureInfo.InvariantCulture))!=true)
            throw new InvalidDataException("Observed target identity is not in this source's exact ready revision");
    }
    private static void FaultIndexedSource(SqliteConnection c,SqliteTransaction t,SourceLifecycle source,string reason,DateTimeOffset now)
    {
        // Historical indexing never rewrites an actual close or closing intent.
        if(source.State!="OPEN")return;
        InsertBoundary(c,t,source.Id,new(reason,now,null,source.LatestLost,null,"indexing-source-fault; no-current-loss-sample",null,[],UnresolvedStatus:"unavailable"));
        Execute(c,t,"UPDATE source_lifecycle SET state='CONTINUITY_FAULTED',latest_lost=NULL WHERE session_id=$id",("$id",source.Id));
    }
    internal IndexedIngress IndexRawIngress(string sessionId,LinuxRawIngressReserve bank,LinuxRawIngressReserve.Entry entry,Action<string>? checkpoint=null)
    {
        // The verified bank, not caller-provided bytes or a PID/path, is the
        // indexing input. All raw file I/O finishes before the DB transaction.
        var raw=bank.ReadRaw(entry);var metadata=JsonSerializer.SerializeToUtf8Bytes(entry);
        if(metadata.Length>4096)throw new InvalidDataException("Ingress metadata outside admitted bound");
        AgentEvent? decoded=null;
        try{decoded=LinuxKernelDecoder.Decode(raw,sensor,entry.Collector,entry.Sequence,entry.ReceivedUtc);}
        catch(Exception ex)when(ex is JsonException or InvalidDataException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        { /* Exact invalid input remains in the bank; no invented operation. */ }
        try
        {
            // Even descriptor validation needs SQLite reads. Disk/lock errors
            // here must leave the same durable emergency as later index errors.
            VerifyIngressBank(sessionId,bank);
            lock(gate)
            {
                var source=ReadSource(sessionId);SourcePolicy? policy=null;string? policyFailure=null;
                var targetBindingFailed=false;
                if(decoded!=null)
                {
                    try{RequireTargetAssociation(sessionId,decoded.Attribution!.LinuxKernel!);}
                    catch(Exception ex)when(ex is InvalidDataException or JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
                    {targetBindingFailed=true;}
                }
                try{policy=ReadSourcePolicy(sessionId);if(policy==null)policyFailure="POLICY_EVIDENCE_MISSING";}
                catch(Exception ex)when(ex is InvalidDataException or JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
                {policyFailure="POLICY_EVIDENCE_INVALID";}
                using var c=Open();using var t=c.BeginTransaction();
                using(var q=Command(c,t,"SELECT entry,classification,reason,canonical_event_id FROM source_ingress WHERE session_id=$session AND delivery_id=$delivery",("$session",sessionId),("$delivery",entry.DeliveryId)))
                using(var r=q.ExecuteReader())if(r.Read())
                {
                    if(!((byte[])r[0]).AsSpan().SequenceEqual(metadata))throw new InvalidDataException("Indexed ingress receipt changed");
                    var classification=r.GetString(1);var reason=r.GetString(2);var canonical=r.IsDBNull(3)?null:r.GetString(3);r.Close();
                    // A later missing policy cannot yield an AgentEvent or a
                    // native claim. Existing immutable index evidence remains.
                    if(policyFailure!=null)
                    {
                        FaultIndexedSource(c,t,source,policyFailure,DateTimeOffset.UtcNow);t.Commit();
                        return new(policyFailure,entry.DeliveryId,null,null,IngressDiagnostic(sessionId,entry,policyFailure,policyFailure),true,true);
                    }
                    var result=ReadIndexedResult(c,t,sessionId,entry,raw,classification,reason,canonical,policy!,true);t.Commit();return result;
                }
                // Index in ingress order, even when competing callers arrive
                // out of order. This preserves the first RECEIVED context, not
                // whichever duplicate happened to acquire SQLite first.
                using(var q=Command(c,t,"SELECT COALESCE(MAX(sequence),0) FROM source_ingress WHERE session_id=$id",("$id",sessionId)))
                    if(Convert.ToInt64(q.ExecuteScalar())+1!=entry.Sequence)return new("INDEX_PREDECESSOR_PENDING",entry.DeliveryId,null,null,null,false,false);
                var kind=policyFailure??(decoded==null?"RAW_INVALID":decoded.Attribution!.LinuxKernel!.ProviderEpoch!=source.ProviderEpoch?"RAW_FOREIGN_EPOCH":targetBindingFailed?"RAW_INVALID":
                    entry.View.State=="Faulted"?"RAW_AFTER_FAULT":entry.View.State!="Active"?"RAW_AFTER_STOP":"RAW_VALID");
                var reasonCode=kind=="RAW_INVALID"?(decoded!=null&&targetBindingFailed?"NATIVE_TARGET_BINDING_FAILED":"NATIVE_SCHEMA_DECODE_FAILED"):kind;
                string? canonicalId=null;AgentEvent? firstEvent=null;byte[]? firstBytes=null;bool newCanonical=false;
                if(decoded!=null&&!targetBindingFailed&&decoded.Attribution!.LinuxKernel!.ProviderEpoch==source.ProviderEpoch&&policyFailure==null)
                {
                    var cookie=decoded.Attribution.LinuxKernel.CanonicalCookie;
                    if(cookie!="0")
                    {
                        using var q=Command(c,t,"SELECT event_id,first_raw_sha256,policy_sha256,decoded FROM canonical_events WHERE session_id=$session AND provider_epoch=$epoch AND positive_cookie=$cookie",("$session",sessionId),("$epoch",source.ProviderEpoch),("$cookie",cookie));using var r=q.ExecuteReader();
                        if(r.Read())
                        {
                            canonicalId=r.GetString(0);firstBytes=(byte[])r[3];firstEvent=JsonSerializer.Deserialize<AgentEvent>(firstBytes)??throw new InvalidDataException("Canonical event missing");
                            var prior=firstEvent.Attribution?.LinuxKernel??throw new InvalidDataException("Canonical native context missing");
                            // Decode in the original context. Later ingress
                            // sequence/time must not manufacture a contradiction.
                            var same=r.GetString(1)==entry.RawSha256&&r.GetString(2)==policy!.Sha256&&
                                EventSpool.Encode(LinuxKernelDecoder.Decode(raw,sensor,prior.CollectorInstance,prior.CollectorSequence,firstEvent.ObservedUtc)).AsSpan().SequenceEqual(firstBytes);
                            if(!same){kind="CANONICAL_KEY_CONTRADICTION";reasonCode=kind;canonicalId=null;firstEvent=null;firstBytes=null;}
                            else if(kind=="RAW_VALID"){kind="DUPLICATE";reasonCode="EXACT_NATIVE_DUPLICATE";}
                        }
                    }
                    if(canonicalId==null&&kind=="RAW_VALID")
                    {canonicalId=decoded.EventId;firstEvent=decoded;firstBytes=EventSpool.Encode(decoded);newCanonical=true;}
                }
                Execute(c,t,"INSERT INTO source_ingress(session_id,delivery_id,bank_id,sequence,entry,classification,reason) VALUES($source,$delivery,$bank,$sequence,$entry,$kind,$reason)",
                    ("$source",sessionId),("$delivery",entry.DeliveryId),("$bank",source.BankId),("$sequence",entry.Sequence),("$entry",metadata),("$kind",kind),("$reason",reasonCode));
                checkpoint?.Invoke("ingress-index-inserted");
                if(newCanonical)
                {
                    var cookie=decoded!.Attribution!.LinuxKernel!.CanonicalCookie;
                    Execute(c,t,"INSERT INTO canonical_events VALUES($event,$source,$epoch,$cookie,$delivery,$first,$raw,$policy,$decoded)",
                        ("$event",canonicalId!),("$source",sessionId),("$epoch",source.ProviderEpoch),("$cookie",cookie=="0"?DBNull.Value:cookie),
                        ("$delivery",cookie=="0"?entry.DeliveryId:DBNull.Value),("$first",entry.DeliveryId),("$raw",entry.RawSha256),("$policy",policy!.Sha256),("$decoded",firstBytes!));
                    checkpoint?.Invoke("canonical-event-inserted");
                }
                if(canonicalId!=null)Execute(c,t,"UPDATE source_ingress SET canonical_event_id=$event WHERE session_id=$source AND delivery_id=$delivery",("$event",canonicalId),("$source",sessionId),("$delivery",entry.DeliveryId));
                if(MustStop(kind))FaultIndexedSource(c,t,source,kind,DateTimeOffset.UtcNow);
                if(kind is not ("RAW_VALID" or "DUPLICATE"))checkpoint?.Invoke("raw-diagnostic-indexed");
                t.Commit();checkpoint?.Invoke("ingress-index-committed");
                // A residual duplicate can reference its historical canonical
                // identity, but it does not return a new operational event.
                return new(kind,entry.DeliveryId,canonicalId,kind is "RAW_VALID" or "DUPLICATE"?firstEvent:null,
                    kind is "RAW_VALID" or "DUPLICATE"?null:IngressDiagnostic(sessionId,entry,kind,reasonCode),MustStop(kind),false);
            }
        }
        catch(Exception ex)when(ex is not OutOfMemoryException)
        {
            // A failed index never invalidates the already committed raw slot.
            // The fixed emergency slot is used outside the journal gate, and
            // an existing boundary is never represented as this new failure.
            try{if(bank.CanAppend)bank.RecordBoundary("INGRESS_INDEX_UNCOMMITTED",entry.View,entry.RawLength,ex.GetType().Name);}
            catch(Exception boundaryFailure){throw new IOException("Ingress index and emergency boundary failed; raw bank retained",new AggregateException(ex,boundaryFailure));}
            throw;
        }
    }
    private IndexedIngress ReadIndexedResult(SqliteConnection c,SqliteTransaction t,string session,LinuxRawIngressReserve.Entry entry,byte[] raw,string kind,string reason,string? canonical,SourcePolicy policy,bool replay)
    {
        if(kind is not ("RAW_VALID" or "DUPLICATE" or "RAW_INVALID" or "RAW_FOREIGN_EPOCH" or "RAW_AFTER_FAULT" or "RAW_AFTER_STOP" or "POLICY_EVIDENCE_MISSING" or "POLICY_EVIDENCE_INVALID" or "CANONICAL_KEY_CONTRADICTION")||
            (kind=="RAW_INVALID"?reason is not ("NATIVE_SCHEMA_DECODE_FAILED" or "NATIVE_TARGET_BINDING_FAILED"):reason!=(kind=="DUPLICATE"?"EXACT_NATIVE_DUPLICATE":kind))||
            kind is "RAW_VALID" or "DUPLICATE"&&canonical==null)
            throw new InvalidDataException("Stored ingress classification invalid");
        AgentEvent? value=null;
        if(canonical!=null)
        {
            using var q=Command(c,t,"""
                SELECT c.decoded,c.policy_sha256,c.provider_epoch,c.positive_cookie,c.delivery_key,c.first_raw_sha256,i.entry
                FROM canonical_events c JOIN source_ingress i ON i.session_id=c.session_id AND i.delivery_id=c.first_delivery_id
                WHERE c.session_id=$source AND c.event_id=$event
                """,("$source",session),("$event",canonical));using var r=q.ExecuteReader();
            if(!r.Read()||r.GetString(1)!=policy.Sha256||r.GetString(5)!=entry.RawSha256)throw new InvalidDataException("Canonical policy or raw reference unavailable");
            var bytes=(byte[])r[0];value=JsonSerializer.Deserialize<AgentEvent>(bytes)??throw new InvalidDataException("Canonical event unavailable");
            var first=JsonSerializer.Deserialize<LinuxRawIngressReserve.Entry>((byte[])r[6])??throw new InvalidDataException("First ingress context unavailable");
            var kernel=value.Attribution?.LinuxKernel??throw new InvalidDataException("Canonical native context unavailable");
            RequireTargetAssociation(session,kernel);
            if(value.EventId!=canonical||!LinuxKernelEvidence.Matches(value)||r.GetString(2)!=entry.ProviderEpoch||
                kernel.CanonicalCookie!=(r.IsDBNull(3)?"0":r.GetString(3))||kernel.Cookie=="0"&&r.GetString(4)!=first.DeliveryId||
                !EventSpool.Encode(LinuxKernelDecoder.Decode(raw,sensor,first.Collector,first.Sequence,first.ReceivedUtc)).AsSpan().SequenceEqual(bytes))
                throw new InvalidDataException("Canonical event identity invalid");
        }
        return new(kind,entry.DeliveryId,canonical,kind is "RAW_VALID" or "DUPLICATE"?value:null,
            kind is "RAW_VALID" or "DUPLICATE"?null:IngressDiagnostic(session,entry,kind,reason),MustStop(kind),replay);
    }
}
