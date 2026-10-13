using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Durable work ordering and same-process finalizer exclusion. A row or claim
// is not a device capability. Only the owned source runtime may bind it to its
// retained controller. Restart never reconstructs an active claim.
internal sealed partial class LinuxForensicJournal
{
    internal sealed record NativePinIntent(int Version,string PinId,string SessionId,string EventId,string CompletionId,
        string RawSha256,string PolicySha256,string Collector,string Epoch,string Cookie,long Lease,
        LinuxSourceWorkBarrier.View IssuedView,DateTimeOffset IssuedUtc,DateTimeOffset CommittedUtc);
    internal sealed record NativeAuthorization(string AuthorizationId,LinuxSourceWorkBarrier.View View,DateTimeOffset CommittedUtc);
    internal sealed record NativeStart(LinuxSourceWorkBarrier.Selection Selection,DateTimeOffset RecordedUtc);
    internal sealed record NativeReturn(DateTimeOffset ActualReturnUtc,string Outcome,string Reason,
        [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] LinuxNativeMethodEvidence? Method=null);
    internal sealed record NativePin(NativePinIntent Intent,string State,NativeAuthorization? Authorization,NativeStart? Start,NativeReturn? Return);
    internal sealed class NativePinClaim
    {
        internal readonly LinuxForensicJournal Journal;
        internal readonly LinuxSourceWorkBarrier Barrier;
        internal readonly LinuxSourceWorkBarrier.Work Work;
        internal readonly NativePinIntent Intent;
        internal readonly LinuxAtomicLeaseKey? AtomicKey;
        internal bool AuthorizationAttempted,Started,Returned;
        internal NativePinClaim(LinuxForensicJournal journal,LinuxSourceWorkBarrier barrier,LinuxSourceWorkBarrier.Work work,NativePinIntent intent,LinuxAtomicLeaseKey? atomicKey=null)
        {Journal=journal;Barrier=barrier;Work=work;Intent=intent;AtomicKey=atomicKey;}
    }
    private readonly Dictionary<string,NativePinClaim> activeNativePins=new(StringComparer.Ordinal);
    private static void MigrateNativePins(SqliteConnection c,Action<string>? checkpoint)
    {
        using var t=c.BeginTransaction();Execute(c,t,"""
            CREATE TABLE native_pins(event_id TEXT PRIMARY KEY REFERENCES work(event_id),
              session_id TEXT NOT NULL,pin_id TEXT NOT NULL UNIQUE,intent BLOB NOT NULL CHECK(length(intent)<=4096),
              state TEXT NOT NULL CHECK(state IN ('PIN_COMMITTED','SELECTION_AUTHORIZED','NATIVE_STARTED',
                'NATIVE_RETURNED_RECEIPT_COMMITTED','NATIVE_RETURNED_UNAVAILABLE_COMMITTED','PIN_INTERRUPTED_PRESELECT','PIN_INTERRUPTED_UNKNOWN')),
              authorization BLOB CHECK(length(authorization)<=4096),starting BLOB CHECK(length(starting)<=8192),
              returned BLOB CHECK(length(returned)<=4096),
              FOREIGN KEY(session_id,event_id) REFERENCES canonical_events(session_id,event_id));
            PRAGMA user_version=10;
            """);checkpoint?.Invoke("native-pin-migration-before-commit");t.Commit();checkpoint?.Invoke("native-pin-migration-after-commit");
    }
    private void RecordInterruptedNativePins()
    {
        // No historic native operation is retried and no actual-return time is
        // invented. Private byte receipts remain separately recoverable.
        using var c=Open();using var t=c.BeginTransaction();
        Execute(c,t,"UPDATE native_pins SET state='PIN_INTERRUPTED_UNKNOWN' WHERE state IN ('PIN_COMMITTED','SELECTION_AUTHORIZED','NATIVE_STARTED')");t.Commit();
    }
    internal NativePin? ReadNativePin(string eventId)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT intent,state,authorization,starting,returned,pin_id,session_id FROM native_pins WHERE event_id=$id",("$id",eventId));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            T Decode<T>(int n)=>JsonSerializer.Deserialize<T>((byte[])r[n])??throw new InvalidDataException("Native pin evidence missing");
            var pin=new NativePin(Decode<NativePinIntent>(0),r.GetString(1),r.IsDBNull(2)?null:Decode<NativeAuthorization>(2),r.IsDBNull(3)?null:Decode<NativeStart>(3),r.IsDBNull(4)?null:Decode<NativeReturn>(4));
            if(pin.Intent.Version!=1||pin.Intent.EventId!=eventId||pin.Intent.PinId!=r.GetString(5)||pin.Intent.SessionId!=r.GetString(6)||
                !Guid.TryParseExact(pin.Intent.PinId,"N",out _)||pin.Intent.IssuedView.State!="Active"||pin.Intent.IssuedUtc==default||pin.Intent.CommittedUtc==default)
                throw new InvalidDataException("Native pin linkage invalid");
            return pin;
        }
    }
    private bool NativePinOwnsOutcome(string id)
        =>privateWork.ContainsKey(id)||activeNativePins.ContainsKey(id)||ReadNativePin(id)?.State is "PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED" or "PIN_INTERRUPTED_UNKNOWN";
    internal LinuxNativeWorkEvidence? ReadNativeWorkEvidence(string id)
    {
        lock(gate)
        {
            var pin=ReadNativePin(id);if(pin==null)return null;
            var work=Read(id);var k=work.Observation.Attribution!.LinuxKernel!;var intent=pin.Intent;
            var a=pin.Authorization;var s=pin.Start;var returned=pin.Return;
            if(pin.State=="NATIVE_RETURNED_RECEIPT_COMMITTED"&&(work.Acquisition?.Status.State!="captured"||work.DropState is not ("returned" or "not-applicable"))||
                pin.State=="NATIVE_RETURNED_UNAVAILABLE_COMMITTED"&&(work.Acquisition?.Status.State!="unavailable"||work.DropState is not ("returned" or "not-applicable"))||
                pin.State=="PIN_INTERRUPTED_PRESELECT"&&work.Acquisition?.Status.Reason!="ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START")
                throw new InvalidDataException("Native work terminal state contradicts committed acquisition");
            var policy=ReadSourcePolicy(intent.SessionId);
            if(intent.CompletionId!=work.CompletionId||policy?.Sha256!=intent.PolicySha256||policy.Policy!=work.Policy||
                intent.IssuedView is not {State:"Active",Reason:null,ChangedUtc:null,FirstInterruption:null}||
                a!=null&&a.View!=intent.IssuedView||s!=null&&(a==null||s.Selection.Issued!=intent.IssuedView||
                    s.Selection.Authorized!=a.View||s.Selection.AuthorizationId!=a.AuthorizationId))
                throw new InvalidDataException("Native work ordering or policy linkage corrupted");
            using(var c=Open())using(var q=Command(c,null,"SELECT decoded,first_raw_sha256,policy_sha256,provider_epoch FROM canonical_events WHERE event_id=$id AND session_id=$session",("$id",id),("$session",intent.SessionId)))
            using(var r=q.ExecuteReader())
                if(!r.Read()||!((byte[])r[0]).AsSpan().SequenceEqual(EventSpool.Encode(work.Observation))||r.GetString(1)!=intent.RawSha256||r.GetString(2)!=intent.PolicySha256||r.GetString(3)!=intent.Epoch)
                    throw new InvalidDataException("Native work differs from its canonical raw event");
            var result=new LinuxNativeWorkEvidence
            {
                Version=returned?.Method==null?1:2,Method=returned?.Method,
                PinId=intent.PinId,SourceSessionId=intent.SessionId,SourceEventId=id,CompletionEventId=intent.CompletionId,
                NativeObservationSha256=intent.RawSha256,PolicySha256=intent.PolicySha256,CollectorInstance=intent.Collector,
                CollectorSequence=k.CollectorSequence,ProviderEpoch=intent.Epoch,Cookie=intent.Cookie,Lease=intent.Lease,State=pin.State,
                IssuedGeneration=intent.IssuedView.Generation,IssuedUtc=intent.IssuedUtc,PinCommittedUtc=intent.CommittedUtc,
                AuthorizationId=a?.AuthorizationId,AuthorizationGeneration=a?.View.Generation,AuthorizationCommittedUtc=a?.CommittedUtc,
                StartingGeneration=s?.Selection.Starting.Generation,StartingState=s?.Selection.Starting.State,StartingReason=s?.Selection.Starting.Reason,
                StartOrdering=s?.Selection.Ordering,StartRecordedUtc=s?.RecordedUtc,ActualReturnUtc=returned?.ActualReturnUtc,ReturnOutcome=returned?.Outcome,ReturnReason=returned?.Reason
            };
            if(!result.IsValid(id,null)||!result.Matches(k))throw new InvalidDataException("Native work evidence is contradictory");
            return result;
        }
    }
    internal void RecoverVerifiedPrivateReceiptForDelivery(string id)
    {
        bool recover;
        lock(gate)
        {
            var pin=ReadNativeWorkEvidence(id);if(pin==null)return;
            if(activeNativePins.ContainsKey(id)||pin.State is "PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "NATIVE_STARTED")
                throw new InvalidOperationException("Live native operation must return before prepared delivery");
            // A verified private receipt establishes bytes, not native DROP or
            // controller completion. Never touch the historical device here.
            recover=pin.State=="PIN_INTERRUPTED_UNKNOWN"&&Read(id).Acquisition==null&&ReadSnapshotIntent(id)?.State=="bytes-verified";
        }
        if(recover)RecoverAdmittedSnapshot(id);
    }
    private NativePin RequireClaim(NativePinClaim claim)
    {
        if(!ReferenceEquals(claim.Journal,this)||claim.Returned||!activeNativePins.TryGetValue(claim.Intent.EventId,out var active)||!ReferenceEquals(active,claim))
            throw new InvalidOperationException("Foreign, historical or returned native work claim");
        var pin=ReadNativePin(claim.Intent.EventId)??throw new InvalidDataException("Native pin record lost");
        if(pin.Intent!=claim.Intent)throw new InvalidDataException("Native pin immutable context changed");return pin;
    }
    private void RequireLiveControlledSource(string id)
    {
        var control=ReadSourceControl(id);
        if(ReadSource(id).State!="OPEN"||ReadSourceOwnership(id)?.Phase!="LINKED_OWNER"||control?.WriteStartedUtc==null||control.Activated==null||control.Completion!=null)
            throw new InvalidOperationException("Native work requires this live linked source and committed activation acknowledgment");
        var ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
        if(LinuxControlledLoaderProtocol.ParseActivated(control.Activated,ready,id).Lost!=ready.Lost)
            throw new InvalidDataException("Activation loss differs from the linked source baseline; evidence is not native authority");
        if(!SourceActivationWriteConfirmed(id))throw new InvalidOperationException("Native work requires the actual successful activation write and EOF receipt");
    }
    internal NativePinClaim CommitNativePin(string session,LinuxRawIngressReserve bank,LinuxRawIngressReserve.Entry entry,
        LinuxSourceWorkBarrier barrier,LinuxSourceWorkBarrier.Work work,Action<string>? checkpoint=null)
    {
        if(barrier.Inspect(work).State!="Active")throw new InvalidOperationException("Interrupted before native pin commit");
        var indexed=IndexRawIngress(session,bank,entry);var observation=indexed.CanonicalEvent;
        if(observation==null||indexed.Status is not ("RAW_VALID" or "DUPLICATE")||observation.EventId!=work.EventId)
            throw new InvalidDataException("Native pin requires exact canonical raw operation");
        var raw=bank.ReadRaw(entry);var kernel=observation.Attribution!.LinuxKernel!;
        LinuxAtomicLeaseKey? atomicKey=null;
        if(kernel.NativeSchemaVersion is 7 or 8)
        {
            var frame=LinuxAtomicObservationFrame.DecodeEnvelope(raw);
            // RESULT/diagnostic and unavailable ENTRY still get durable logging;
            // only the original finalized ENTRY can issue copy authority.
            if(frame.CanAuthorizeCopy)atomicKey=frame.ObservedKey;
        }
        lock(gate)
        {
            RequireLiveControlledSource(session);
            var policy=ReadSourcePolicy(session)??throw new InvalidDataException("Frozen source policy unavailable");
            if(ReadNativePin(work.EventId)!=null||activeNativePins.ContainsKey(work.EventId))throw new InvalidOperationException("Native pin already exists; no historical or duplicate claim");
            using var c=Open();using var t=c.BeginTransaction();
            var completion=InsertObservation(c,t,raw,observation,policy.Policy);
            var intent=new NativePinIntent(1,Guid.NewGuid().ToString("N"),session,work.EventId,completion,kernel.NativeObservationSha256,
                policy.Sha256,kernel.CollectorInstance,kernel.ProviderEpoch,kernel.Cookie,kernel.Lease,work.Issued,work.IssuedUtc,DateTimeOffset.UtcNow);
            Execute(c,t,"INSERT INTO native_pins(event_id,session_id,pin_id,intent,state) VALUES($event,$session,$pin,$intent,'PIN_COMMITTED')",
                ("$event",work.EventId),("$session",session),("$pin",intent.PinId),("$intent",JsonSerializer.SerializeToUtf8Bytes(intent)));
            checkpoint?.Invoke("native-pin-before-commit");t.Commit();checkpoint?.Invoke("native-pin-committed");
            var claim=new NativePinClaim(this,barrier,work,intent,atomicKey);activeNativePins.Add(work.EventId,claim);return claim;
        }
    }
    internal (LinuxAtomicLeaseKey Key,string AuthorizationId) RequireAtomicCopyAuthorization(NativePinClaim claim)
    {
        lock(gate)
        {
            var pin=RequireClaim(claim);RequireLiveControlledSource(claim.Intent.SessionId);
            if(!claim.Started||claim.AtomicKey is not {} key||pin.State!="NATIVE_STARTED"||pin.Authorization==null||pin.Start==null||
                pin.Start.Selection.AuthorizationId!=pin.Authorization.AuthorizationId||claim.Barrier.Inspect(claim.Work).State!="Active")
                throw new InvalidOperationException("Atomic START requires the original active claim and durably committed raw authorization/start");
            var k=Read(claim.Intent.EventId).Observation.Attribution!.LinuxKernel!;
            if(k.NativeSchemaVersion is not (7 or 8)||!key.Valid||!key.Matches(k)||key.ProviderEpoch.ToString(System.Globalization.CultureInfo.InvariantCulture)!=claim.Intent.Epoch)
                throw new InvalidDataException("Atomic original claim differs from committed work");
            return (key,pin.Authorization.AuthorizationId);
        }
    }
    internal bool AuthorizeNativePin(NativePinClaim claim,Action<string>? checkpoint=null)
    {
        var view=claim.Barrier.Inspect(claim.Work);
        if(view.State!="Active")return false;
        NativeAuthorization authorization;
        lock(gate)
        {
            var pin=RequireClaim(claim);
            if(claim.AuthorizationAttempted||pin.State!="PIN_COMMITTED")throw new InvalidOperationException("Native authorization is one-use");
            claim.AuthorizationAttempted=true;RequireLiveControlledSource(claim.Intent.SessionId);
            if(ReadSourcePolicy(claim.Intent.SessionId)?.Sha256!=claim.Intent.PolicySha256)throw new InvalidDataException("Frozen pin policy changed");
            authorization=new(Guid.NewGuid().ToString("N"),view,DateTimeOffset.UtcNow);
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"UPDATE native_pins SET state='SELECTION_AUTHORIZED',authorization=$a WHERE event_id=$id AND state='PIN_COMMITTED'",
                ("$a",JsonSerializer.SerializeToUtf8Bytes(authorization)),("$id",claim.Intent.EventId));
            checkpoint?.Invoke("native-authorization-before-commit");t.Commit();
        }
        // No journal lock is held at the final barrier check. If stop/fault
        // won while SQLite was busy, even a committed row cannot start I/O.
        checkpoint?.Invoke("native-authorization-committed");
        return claim.Barrier.ConfirmCommittedAuthorization(claim.Work,authorization.AuthorizationId);
    }
    internal void MarkNativePinStarting(NativePinClaim claim,Action<string>? checkpoint=null)
    {
        var selection=claim.Barrier.MarkSelectionStarting(claim.Work);
        lock(gate)
        {
            var pin=RequireClaim(claim);
            if(pin.State!="SELECTION_AUTHORIZED"||pin.Authorization?.AuthorizationId!=selection.AuthorizationId||claim.Started)
                throw new InvalidOperationException("Confirmed exact native authorization required before device I/O");
            using var c=Open();using var t=c.BeginTransaction();
            Execute(c,t,"UPDATE native_pins SET state='NATIVE_STARTED',starting=$s WHERE event_id=$id AND state='SELECTION_AUTHORIZED'",
                ("$s",JsonSerializer.SerializeToUtf8Bytes(new NativeStart(selection,DateTimeOffset.UtcNow))),("$id",claim.Intent.EventId));
            checkpoint?.Invoke("native-start-before-commit");t.Commit();checkpoint?.Invoke("native-start-commit-unobserved");claim.Started=true;
        }
        checkpoint?.Invoke("native-start-committed");
    }
    // Receipt-only reconciliation for the same retained in-memory claim when
    // durable start commitment returned ambiguously. This never authorizes a
    // controller call; the caller has already disabled its execution path.
    internal bool ReconcileUncalledNativeStart(NativePinClaim claim)
    {
        lock(gate)
        {
            var pin=RequireClaim(claim);
            if(claim.Started)return true;
            if(pin.Start==null)return false;
            if(pin.State!="NATIVE_STARTED"||claim.Work.Start==null||pin.Start.Selection!=claim.Work.Start)
                throw new InvalidDataException("Unobserved start differs from the retained original claim");
            claim.Started=true;return true;
        }
    }
    internal void AbortNativePinBeforeStart(NativePinClaim claim,Action<string>? checkpoint=null)
    {
        lock(gate)
        {
            var pin=RequireClaim(claim);
            if(claim.Started||pin.Start!=null||pin.State is not ("PIN_COMMITTED" or "SELECTION_AUTHORIZED" or "PIN_INTERRUPTED_PRESELECT"))throw new InvalidOperationException("Started or interrupted work cannot be reported as never started");
            if(Read(claim.Intent.EventId).Acquisition==null)CommitUnavailable(claim.Intent.EventId,"ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START");
            if(Read(claim.Intent.EventId).Acquisition?.Status is not {State:"unavailable",Reason:"ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START"})throw new InvalidDataException("Prestart abort contradicts retained acquisition");
            if(pin.State!="PIN_INTERRUPTED_PRESELECT")
            {
                using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE native_pins SET state='PIN_INTERRUPTED_PRESELECT' WHERE event_id=$id",("$id",claim.Intent.EventId));t.Commit();checkpoint?.Invoke("native-abort-committed");
            }
            activeNativePins.Remove(claim.Intent.EventId);claim.Returned=true;
        }
        claim.Barrier.Return(claim.Work);
    }
    internal void RecordNativePinReturn(NativePinClaim claim,DateTimeOffset actualReturnUtc,string reason,LinuxNativeMethodEvidence? method=null,Action<string>? checkpoint=null)
    {
        if(actualReturnUtc==default||string.IsNullOrWhiteSpace(reason)||reason.Length>128)throw new ArgumentException("Actual return time and bounded reason required");
        lock(gate)
        {
            var pin=RequireClaim(claim);
            if(!claim.Started)throw new InvalidOperationException("Only started work can record its actual return");
            var work=Read(claim.Intent.EventId);
            var complete=work.Acquisition!=null&&work.DropState is "returned" or "not-applicable";
            var state=!complete?"PIN_INTERRUPTED_UNKNOWN":work.Acquisition!.Status.State=="captured"?"NATIVE_RETURNED_RECEIPT_COMMITTED":"NATIVE_RETURNED_UNAVAILABLE_COMMITTED";
            if(method!=null&&(!method.IsValid(pin.Intent.PinId)||method.LatestStatus!=null&&!method.LatestStatus.Matches(work.Observation.Attribution!.LinuxKernel!)||method.DropReceiptCommitObserved&&work.DropState!="returned"))
                throw new InvalidDataException("Native method return contradicts its exact pin, observation or release receipt");
            var receipt=new NativeReturn(actualReturnUtc,complete?"committed":"unresolved",reason,method);
            var encoded=JsonSerializer.SerializeToUtf8Bytes(receipt);if(encoded.Length>4096)throw new InvalidDataException("Native method return exceeds durable bound");
            var projected=ReadNativeWorkEvidence(claim.Intent.EventId)! with{Version=method==null?1:2,Method=method,State=state,ActualReturnUtc=actualReturnUtc,ReturnOutcome=receipt.Outcome,ReturnReason=reason};
            if(!projected.IsValid(claim.Intent.EventId,null)||!projected.Matches(work.Observation.Attribution!.LinuxKernel!))throw new InvalidDataException("Contradictory native return projection");
            if(pin.Return!=null)
            {
                // A transaction may commit before the caller observes its
                // completion. Only the exact retained payload may reconcile
                // that ambiguity; no timestamp, step or error is regenerated.
                if(pin.State!=state||!JsonSerializer.SerializeToUtf8Bytes(pin.Return).AsSpan().SequenceEqual(encoded))throw new InvalidDataException("Native return was already committed with different evidence");
            }
            else
            {
                if(pin.State!="NATIVE_STARTED")throw new InvalidOperationException("Native return state is no longer active");
                using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE native_pins SET state=$state,returned=$returned WHERE event_id=$id AND returned IS NULL",
                    ("$state",state),("$returned",encoded),("$id",claim.Intent.EventId));t.Commit();
                checkpoint?.Invoke("native-return-committed");
            }
            activeNativePins.Remove(claim.Intent.EventId);claim.Returned=true;
        }
        claim.Barrier.Return(claim.Work);
    }
}
