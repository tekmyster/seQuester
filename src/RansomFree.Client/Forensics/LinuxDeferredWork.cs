using RansomFree.Contracts;
using System.Text.Json;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    // The canonical/raw index is the durable backlog; no competing in-memory
    // event queue or restart-native capability is reconstructed. A result here
    // is not a reservation. The one source dispatcher must still acquire its
    // own bounded work token and commit the pin before live native I/O.
    internal LinuxRawIngressReserve.Entry[] ReadDeferredCanonical(string session,LinuxRawIngressReserve bank,Action? beforeQueryForTest=null)
    {
        VerifyIngressBank(session,bank);var ids=new List<string>();
        beforeQueryForTest?.Invoke();
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"""
                SELECT e.first_delivery_id FROM canonical_events e
                JOIN source_ingress i ON i.session_id=e.session_id AND i.delivery_id=e.first_delivery_id
                LEFT JOIN work w ON w.event_id=e.event_id
                WHERE e.session_id=$session AND w.event_id IS NULL ORDER BY i.sequence LIMIT 4
                """,("$session",session));using var r=q.ExecuteReader();while(r.Read())ids.Add(r.GetString(0));
        }
        // Indexing follows durable raw commit. Take the append-only bank snapshot
        // AFTER the SQL query: an earlier snapshot can miss a receipt indexed
        // concurrently between that snapshot and the query.
        var entries=bank.Entries;
        return ids.Select(id=>entries.SingleOrDefault(e=>e.DeliveryId==id)??throw new InvalidDataException("Deferred canonical row has no exact original raw receipt")).ToArray();
    }
    internal string PromoteStoppedCanonicalUnavailable(string session,LinuxRawIngressReserve bank,LinuxRawIngressReserve.Entry entry)
    {
        // Re-indexing verifies the original canonical event, receive context
        // and frozen policy from the same exact raw bytes, including on restart.
        var indexed=IndexRawIngress(session,bank,entry);
        var observation=indexed.CanonicalEvent??throw new InvalidDataException("Deferred delivery requires a verified canonical observation");
        var raw=bank.ReadRaw(entry);
        lock(gate)
        {
            if(ReadSource(session).State=="OPEN")throw new InvalidOperationException("Live source work must be authorized by its owned runtime");
            var id=observation.EventId;
            if(ReadNativePin(id)!=null||activeNativePins.ContainsKey(id)||privateWork.ContainsKey(id))throw new InvalidOperationException("Pinned or private work has its own outcome owner");
            if(HasWork(id))return id;
            var policy=ReadSourcePolicy(session)??throw new InvalidDataException("Frozen deferred policy missing");
            var unavailable=new LinuxActorAcquisitionEvidence{SourceEventId=id,NativeObservationSha256=observation.Attribution!.LinuxKernel!.NativeObservationSha256,
                Status=EvidenceStatus.Unavailable("ACTOR_COPY_UNAVAILABLE_SOURCE_STOPPED_BEFORE_NATIVE_ADMISSION")};
            var file=new FileIdentityEvidence();using var actor=ActorLease.Unavailable(observation,unavailable.Status.Reason);actor.ApplyKernel(observation,sensor);
            if(!unavailable.Matches(observation.Attribution.LinuxKernel)||!unavailable.IsValid(actor.Process,id,null,null,file))throw new InvalidDataException("Invalid deferred unavailable evidence");
            // Raw/work admission and explicit unavailable outcome commit
            // together; a write failure leaves this canonical row deferred.
            using var c=Open();using var t=c.BeginTransaction();InsertObservation(c,t,raw,observation,policy.Policy);
            Execute(c,t,"UPDATE work SET acquisition=$a,source_file=$s WHERE event_id=$id AND acquisition IS NULL",
                ("$a",JsonSerializer.SerializeToUtf8Bytes(unavailable)),("$s",JsonSerializer.SerializeToUtf8Bytes(file)),("$id",id));t.Commit();
            // No Status/SELECT/read/DROP, path lookup or invented release.
            return id;
        }
    }
}
