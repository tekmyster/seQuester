using System.Globalization;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// Opt-in source admission gate, not an installed sensor service. The caller
// opens its exclusive native controller only after this object is constructed.
// Acquisition and release scheduling remain separate from raw admission.
internal sealed class LinuxSourceSession
{
    internal sealed record LostSample(ulong? Value,string? Error=null)
    {
        internal string? Decimal=>Value?.ToString(CultureInfo.InvariantCulture);
    }
    private readonly LinuxForensicJournal journal;
    private readonly LinuxRawDeliveryMap bank;
    private readonly string sensor,epoch;
    private readonly object gate=new();
    private readonly bool layoutReplayForTest;
    private LinuxActorLeaseDevice? controller;
    private SourceOpenPermit? permit;
    private bool openAttempted;
    private LostSample latest;
    private bool closing,closeInProgress,closeReturned,closeFailed,closed;
    private DateTimeOffset? closeReturnedUtc;
    private string? failure;
    private LinuxForensicJournal.SourceBoundary? pendingBoundary;
    internal string Id {get;}
    internal sealed class SourceOpenPermit
    {
        private readonly LinuxSourceSession owner;
        internal SourceOpenPermit(LinuxSourceSession owner)=>this.owner=owner;
        internal LinuxActorLeaseDevice Open()=>owner.OpenController(this,()=>new LinuxActorLeaseDevice());
        internal LinuxActorLeaseDevice OpenForTest(Func<LinuxActorLeaseDevice> create)
        {if(!owner.layoutReplayForTest)throw new InvalidOperationException("Test controller factory is disabled");return owner.OpenController(this,create);}
    }
    internal SourceOpenPermit TakeOpenPermit()
    {
        lock(gate){RequireOpen();if(permit!=null||openAttempted)throw new InvalidOperationException("Source opening permit already issued");return permit=new(this);}
    }
    private LinuxActorLeaseDevice OpenController(SourceOpenPermit capability,Func<LinuxActorLeaseDevice> create)
    {
        ArgumentNullException.ThrowIfNull(create);
        lock(gate)
        {
            RequireOpen();if(!ReferenceEquals(permit,capability)||openAttempted)throw new InvalidOperationException("Source opening permit is foreign or consumed");
            openAttempted=true;
            try{return controller=create()??throw new InvalidDataException("No controller returned by source opener");}
            catch(OutOfMemoryException){closeFailed=true;failure="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY";throw;}
            catch(Exception ex){closeFailed=true;Fault("CONTROLLER_OPEN_UNKNOWN",latest,ex.GetType().Name);throw;}
        }
    }
    internal string? Failure {get{lock(gate)return failure;}}
    internal LinuxForensicJournal.SourceLifecycle State=>journal.ReadSource(Id);
    internal IReadOnlyList<LinuxRawIntakeReserve.RawRecord> Records=>bank.Records;
    internal LinuxSourceSession(LinuxForensicJournal journal,string directory,string sensor,int slots,
        string epoch,LostSample sample,bool layoutReplayForTest=false,long bankQuota=512L*1024*1024)
    {
        this.journal=journal;this.sensor=sensor;this.epoch=epoch;latest=sample;this.layoutReplayForTest=layoutReplayForTest;
        bank=new(directory,sensor,slots);
        try
        {
            if(!bank.PhysicalAllocationEstablished&&!layoutReplayForTest)throw new PlatformNotSupportedException("Physical Linux raw-bank allocation required before source open");
            Id=journal.OpenSource(bank,epoch,sample.Decimal,DateTimeOffset.UtcNow,bankQuota).Id;
            if(sample.Value==null||sample.Error!=null)Fault("LOADER_LOST_COUNTER_UNAVAILABLE",sample,sample.Error??"counter-unavailable");
            else if(bank.Overflow!=null)Fault("RAW_BANK_UNKNOWN",sample,"retained-emergency-boundary");
        }
        catch{bank.Dispose();throw;}
    }
    private void RequireOpen()
    {
        if(closing||closed||failure!=null||State.State!="OPEN")throw new InvalidOperationException("SOURCE_ADMISSION_STOPPED: "+(failure??State.State));
    }
    private LinuxForensicJournal.SourceWorkKey[] Unresolved()
    {
        var indexed=journal.UnresolvedSourceWork(Id).ToDictionary(x=>x.EventId,StringComparer.Ordinal);
        // Raw-only backlog has not entered the bounded four-job journal yet.
        foreach(var r in bank.Records)
        {
            var k=r.Observation.Attribution!.LinuxKernel!;
            if(k.ProviderEpoch==epoch&&k.CollectorInstance==bank.CollectorInstance&&!indexed.ContainsKey(r.Observation.EventId))
            {
                if(journal.HasWork(r.Observation.EventId))
                {var w=journal.Read(r.Observation.EventId);if(w.Acquisition!=null&&w.DropState is "returned" or "not-applicable")continue;}
                indexed[r.Observation.EventId]=new(r.Observation.EventId,epoch,k.Cookie,k.Lease);
            }
        }
        return indexed.Values.ToArray();
    }
    private void Fault(string reason,LostSample sample,string? code=null,long? length=null,string? observedEpoch=null)
    {
        // Sticky before attempting SQLite: a failed boundary write cannot leave
        // acquisition enabled merely because the persisted row still says OPEN.
        failure??=reason;
        pendingBoundary=new(reason,DateTimeOffset.UtcNow,length,latest.Decimal,sample.Decimal,code??sample.Error,observedEpoch,[],UnresolvedStatus:"unavailable");
        try
        {
            pendingBoundary=pendingBoundary with{Unresolved=Unresolved(),UnresolvedStatus="captured"};
            journal.TransitionSource(Id,"CONTINUITY_FAULTED",pendingBoundary);pendingBoundary=null;
            latest=sample;
            journal.FinalizeSourceWorkUnavailable(Id,"ACTOR_COPY_UNAVAILABLE_SOURCE_CONTINUITY");
        }
        catch(Exception ex){failure=(pendingBoundary==null?"SOURCE_WORK_FINALIZATION_UNCOMMITTED:":"SOURCE_BOUNDARY_UNCOMMITTED:")+reason;throw new IOException(failure,ex);}
    }
    internal bool SampleLoss(LostSample sample)
    {
        lock(gate)
        {
            RequireOpen();
            string? reason=sample.Value==null||sample.Error!=null?"LOADER_LOST_COUNTER_UNAVAILABLE":
                latest.Value==null?"LOADER_LOST_COUNTER_UNAVAILABLE":sample.Value>latest.Value?"LOADER_LOST_COUNTER_INCREASED":sample.Value<latest.Value?"LOADER_LOST_COUNTER_RESET":null;
            if(reason!=null){Fault(reason,sample);return false;}
            latest=sample;return true;
        }
    }
    internal LinuxRawDeliveryMap.Admission Admit(ReadOnlyMemory<byte> raw,ForensicPolicy policy,DateTimeOffset receivedUtc)
        =>AdmitCore(raw,policy,receivedUtc,null);
    internal LinuxRawDeliveryMap.Admission AdmitWithAllocationFailureForTest(ReadOnlyMemory<byte> raw,ForensicPolicy policy,DateTimeOffset time)
    {if(!layoutReplayForTest)throw new InvalidOperationException("Test injection is disabled");return AdmitCore(raw,policy,time,()=>throw new OutOfMemoryException("owned decoder allocation failure"));}
    private LinuxRawDeliveryMap.Admission AdmitCore(ReadOnlyMemory<byte> raw,ForensicPolicy policy,DateTimeOffset receivedUtc,Action? beforeDecode)
    {
        lock(gate)
        {
            RequireOpen();AgentEvent decoded;
            if(raw.Length is <2 or >65536){Fault("PREDECODE_UNKNOWN",latest,"RAW_LENGTH_OUTSIDE_BOUND",raw.Length);throw new InvalidDataException("Native raw length outside admitted bound");}
            try{beforeDecode?.Invoke();decoded=LinuxKernelDecoder.Decode(raw,sensor,bank.CollectorInstance,1,receivedUtc);}
            catch(OutOfMemoryException){failure="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY";throw;}
            catch(Exception ex)when(ex is not OutOfMemoryException)
            {Fault("PREDECODE_UNKNOWN",latest,ex.GetType().Name,raw.Length);throw new InvalidDataException("PREDECODE_UNKNOWN: input is not a committed observation",ex);}
            if(decoded.Attribution!.LinuxKernel!.ProviderEpoch!=epoch)
            {
                Fault("PROVIDER_EPOCH_CHANGED",latest,null,raw.Length,decoded.Attribution.LinuxKernel.ProviderEpoch);
                throw new InvalidDataException("PROVIDER_EPOCH_CHANGED: old native IDs are no longer admissible");
            }
            LinuxRawDeliveryMap.Admission result;
            try{result=bank.Admit(raw,policy,receivedUtc);}
            catch(OutOfMemoryException){failure="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY";throw;}
            catch(Exception ex)when(ex is not OutOfMemoryException)
            {Fault("RAW_BANK_UNKNOWN",latest,ex.GetType().Name,raw.Length);throw;}
            if(!result.RawCommitted)Fault("RAW_BANK_UNKNOWN",latest,result.Overflow?.Reason,raw.Length);
            return result;
        }
    }
    // Work must be the canonical committed raw delivery of this live session.
    // Returning a record does not grant callers permission to bypass this gate.
    private LinuxRawIntakeReserve.RawRecord RequireRecord(string id)
    {
        RequireOpen();var r=bank.Records.SingleOrDefault(x=>x.Observation.EventId==id)??throw new InvalidDataException("No canonical raw delivery in this bank");
        var k=r.Observation.Attribution!.LinuxKernel!;
        if(k.ProviderEpoch!=epoch||k.CollectorInstance!=bank.CollectorInstance)
            throw new InvalidOperationException("Historical raw delivery cannot authorize live native control");
        return r;
    }
    internal bool Capture(LinuxActorLeaseDevice device,string id)
    {
        lock(gate)
        {
            var r=RequireRecord(id);
            if(!ReferenceEquals(controller,device))throw new InvalidOperationException("Native controller does not belong to this source opening permit");
            try
            {
                journal.CommitObservation(Convert.FromBase64String(r.RawBase64),r.Observation,r.Policy);
                if(journal.Read(id).Acquisition!=null)return true;
                var k=r.Observation.Attribution!.LinuxKernel!;
                if(k.Lease<=0){journal.CommitUnavailable(id,"ACTOR_COPY_UNAVAILABLE_NO_NATIVE_LEASE");return true;}
                var status=device.Status(k);
                journal.RecordNativeProgress(id,status);
                var disposition=LinuxNativeDisposition.Classify(status);
                if(disposition is "ACTOR_COPY_UNAVAILABLE_NATIVE_FAILED" or "ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS")
                {journal.CommitUnavailable(id,disposition,status,status.Error.ToString(CultureInfo.InvariantCulture));return true;}
                if(!status.Ready)return false; // Expiry is still unreleased work, never timeout cancellation.
                journal.AcquireAdmittedSnapshot(device,id,status);return true;
            }
            catch(OutOfMemoryException){failure="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY";throw;}
            catch(Exception ex)when(ex is not OutOfMemoryException)
            {Fault("ACQUISITION_UNKNOWN",latest,ex.GetType().Name);throw;}
        }
    }
    internal bool Release(LinuxActorLeaseDevice device,string id)
    {
        lock(gate)
        {
            var r=RequireRecord(id);var w=journal.Read(id);
            if(!ReferenceEquals(controller,device))throw new InvalidOperationException("Native controller does not belong to this source opening permit");
            if(w.Acquisition==null)throw new InvalidOperationException("Committed acquisition required before release");
            if(w.DropState is "returned" or "not-applicable")return true;
            if(r.Observation.Attribution!.LinuxKernel!.Lease<=0){journal.RecordDrop(id,"not-applicable");return true;}
            if(w.Acquisition.Status.State=="captured")
            {
                using var actor=journal.RestoreActor(id);
                if(actor.Image==null)throw new IOException("Private actor snapshot is no longer verified; release refused");
            }
            try
            {
                var status=device.Status(r.Observation.Attribution!.LinuxKernel!);journal.RecordNativeProgress(id,status);
                // Every terminal result must still be the tuple committed for
                // this acquisition; a changed requery never authorizes DROP.
                if(w.Acquisition.NativeStatus!=status.ToEvidence())throw new InvalidDataException("Terminal native tuple changed before release");
                if(!LinuxNativeDisposition.MayRelease(status))return false;
                device.DropExact(r.Observation.Attribution!.LinuxKernel!,status);journal.RecordDrop(id,"returned");return true;
            }
            catch(OutOfMemoryException){failure="SOURCE_BOUNDARY_UNCOMMITTED:OUT_OF_MEMORY";throw;}
            catch(Exception ex)when(ex is not OutOfMemoryException)
            {Fault("NATIVE_RELEASE_UNKNOWN",latest,ex.GetType().Name);throw;}
        }
    }
    internal void Close(LostSample sample)=>CloseCore(sample,()=>controller?.Dispose());
    internal void CloseForTest(LostSample sample,Action closeController)
    {if(!layoutReplayForTest)throw new InvalidOperationException("Test callback is disabled");CloseCore(sample,()=>{closeController();controller?.Dispose();});}
    private void CloseCore(LostSample sample,Action closeController)
    {
        ArgumentNullException.ThrowIfNull(closeController);
        lock(gate)
        {
            if(closed)return;
            if(closeFailed)throw new InvalidOperationException("Controller close failed; explicit native ownership reconciliation required");
            if(closeInProgress)throw new InvalidOperationException("Controller close is still running; no second close or owner permitted");
            if(closeReturned){FinishClose();return;}
            closing=true; // Persistence failure also stops all future acquisition.
            try
            {
                if(pendingBoundary!=null)
                {
                    // Retain the original reason, time and sampled counter when
                    // storage recovers. A generic close must not hide the loss.
                    journal.TransitionSource(Id,"CONTINUITY_FAULTED",pendingBoundary);pendingBoundary=null;
                }
                if(failure!=null)journal.FinalizeSourceWorkUnavailable(Id,"ACTOR_COPY_UNAVAILABLE_SOURCE_CONTINUITY");
                if(failure==null&&(sample.Value==null||sample.Error!=null||sample.Value!=latest.Value))
                    Fault(sample.Value==null||sample.Error!=null?"LOADER_LOST_COUNTER_UNAVAILABLE":sample.Value>latest.Value?"LOADER_LOST_COUNTER_INCREASED":"LOADER_LOST_COUNTER_RESET",sample);
                journal.TransitionSource(Id,"CLOSE_UNKNOWN_OPEN",new("CONTROLLER_CLOSE_UNKNOWN",DateTimeOffset.UtcNow,null,latest.Decimal,sample.Decimal,sample.Error??failure,null,Unresolved()));
                latest=sample;closeInProgress=true;
            }
            catch(Exception ex){failure="SOURCE_CLOSE_INTENT_UNCOMMITTED";throw new IOException(failure+": controller close not started",ex);}
        }
        try{closeController();}
        catch(Exception ex)
        {
            lock(gate){closeInProgress=false;closeFailed=true;failure="CONTROLLER_CLOSE_FAILED";}
            throw new IOException("CONTROLLER_CLOSE_FAILED: actual close unresolved; source ownership retained",ex);
        }
        var returnedUtc=DateTimeOffset.UtcNow;
        lock(gate){closeInProgress=false;closeReturned=true;closeReturnedUtc=returnedUtc;FinishClose();}
    }
    private void FinishClose()
    {
        // A failed final transaction can be retried without calling native close
        // twice. Neither elapsed time nor a cancellation token sets this flag.
        journal.FinalizeSourceWorkUnavailable(Id,"ACTOR_COPY_UNAVAILABLE_CONTROLLER_CLOSED");
        journal.RecordSourceCloseReturned(Id,closeReturnedUtc??throw new InvalidOperationException("Actual controller return timestamp missing"));closed=true;bank.Dispose();
    }
}
