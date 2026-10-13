using RansomFree.Contracts;
namespace RansomFree.Client.Forensics;

// Serial control/raw routing for the owned runtime. It never opens or calls a
// native device, and does not turn a map ID or historical row into authority.
internal sealed class LinuxControlledIngress
{
    internal enum Disposition { ControlRecorded,CanonicalReady,CanonicalWaitingForActivation,DiagnosticRetained,CapacityExhausted }
    internal sealed record Receipt(Disposition Kind,LinuxForensicJournal.IndexedIngress? Indexed);
    private readonly LinuxForensicJournal journal;
    private readonly LinuxRawIngressReserve bank;
    private readonly LinuxSourceWorkBarrier barrier;
    private readonly LinuxControlledLoaderProtocol.Ready ready;
    private readonly string session;
    private int reading;
    private bool activated,completed,capacityExhausted;
    private sealed record FaultRecord(string Reason,DateTimeOffset Utc,long Generation,string? Error,string? SampledLost);
    private FaultRecord? firstFault;
    private LinuxForensicJournal.SourceBoundary? faultBoundary;
    private readonly object faultPersistence=new();
    private bool faultPersisted;
    internal bool Activated=>Volatile.Read(ref activated);
    internal LinuxControlledIngress(LinuxForensicJournal journal,LinuxRawIngressReserve bank,LinuxSourceWorkBarrier barrier,string session)
    {
        this.journal=journal;this.bank=bank;this.barrier=barrier;this.session=session;
        var source=journal.ReadSource(session);var control=journal.ReadSourceControl(session)??throw new InvalidOperationException("Exact linked ready required");
        if(source.State!="OPEN"||source.CollectorInstance!=bank.CollectorInstance||source.ProviderEpoch!=bank.ProviderEpoch||bank.Reopened||bank.Entries.Length!=0||barrier.Current.State!="Active"||control.Activated!=null||control.Completion!=null)
            throw new InvalidOperationException("Fresh owned control ingress required; no historical runtime reconstruction");
        ready=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
        journal.VerifyIngressBank(session,bank);
    }
    internal void LatchFault(string reason,string? error=null,string? sampledLost=null)
    {
        var view=barrier.Fault(reason,DateTimeOffset.UtcNow);
        var first=view.FirstInterruption!;
        Interlocked.CompareExchange(ref firstFault,new(first.Reason,first.RecordedUtc,first.Generation,first.Reason==reason?error:null,first.Reason==reason?sampledLost:null),null);
    }
    internal void PersistFaultOnce()
    {
        lock(faultPersistence)
        {
            var first=Volatile.Read(ref firstFault);if(first==null||faultPersisted)return;
            var source=journal.ReadSource(session);
            if(source.State is "CLOSED" or "CLOSE_UNKNOWN_OPEN")return;
            faultBoundary??=new(first.Reason,first.Utc,null,source.LatestLost,first.SampledLost,first.Error,null,[],UnresolvedStatus:"unavailable");
            journal.TransitionSource(session,"CONTINUITY_FAULTED",faultBoundary,deduplicate:true);faultPersisted=true;
        }
    }
    internal void Fault(string reason,string? error=null){LatchFault(reason,error);PersistFaultOnce();}
    internal Receipt Receive(ReadOnlyMemory<byte> raw,DateTimeOffset receivedUtc)
    {
        var indexed=ReceiveCore(raw,receivedUtc);
        if(indexed==null)return new(capacityExhausted?Disposition.CapacityExhausted:Disposition.ControlRecorded,null);
        // This is routing eligibility, not native authority. The dispatcher
        // must still obtain its durable claim and pass the current barrier.
        var eligible=Activated&&barrier.Current.State=="Active"&&!indexed.RequiresSourceStop&&
            indexed.Status is "RAW_VALID" or "DUPLICATE"&&indexed.CanonicalEventId!=null&&indexed.CanonicalEvent!=null;
        return new(eligible?(journal.SourceActivationWriteConfirmed(session)?Disposition.CanonicalReady:Disposition.CanonicalWaitingForActivation):Disposition.DiagnosticRetained,indexed);
    }
    private LinuxForensicJournal.IndexedIngress? ReceiveCore(ReadOnlyMemory<byte> raw,DateTimeOffset receivedUtc)
    {
        if(Interlocked.Exchange(ref reading,1)!=0)throw new InvalidOperationException("Owned control ingress has one reader");
        try
        {
            // This routing recognizes the pinned loader's exact output prefix;
            // it does not decode an operation before durable raw admission.
            if(raw.Span.StartsWith("{\"controlledActivated\":"u8))
            {
                try
                {
                    if(activated||completed||barrier.Current.State!="Active")throw new InvalidDataException("Repeated or late activation frame");
                    var ack=LinuxControlledLoaderProtocol.ParseActivated(raw,ready,session);
                    if(ack.Lost!=ready.Lost)return RetainFaulted(raw,receivedUtc,"ACTIVATION_LOSS_CHANGED",null);
                    journal.RecordSourceControlActivated(session,raw);
                    // A concurrent fault cannot turn this committed ACK into
                    // fresh authority. Late ACKs were retained raw above.
                    if(barrier.Current.State=="Active"&&journal.ReadSource(session).State=="OPEN")Volatile.Write(ref activated,true);
                    return null;
                }
                catch(Exception ex)when(ex is not OutOfMemoryException)
                {return RetainFaulted(raw,receivedUtc,"ACTIVATION_FRAME_INVALID",ex.GetType().Name);}
            }
            if(raw.Span.StartsWith("{\"controlledComplete\":"u8))
            {
                try
                {
                    if(completed)throw new InvalidDataException("Repeated completion frame");
                    journal.RecordSourceControlCompletion(session,raw);completed=true;
                    Fault("LOADER_CONTROL_COMPLETED");return null;
                }
                catch(Exception ex)when(ex is not OutOfMemoryException)
                {return RetainFaulted(raw,receivedUtc,"COMPLETION_FRAME_INVALID",ex.GetType().Name);}
            }
            if(!activated)return RetainFaulted(raw,receivedUtc,"NATIVE_BEFORE_ACTIVATION_ACK",null);
            var result=PersistRaw(raw,receivedUtc);
            if(result?.RequiresSourceStop==true)Fault(result.Status,result.Diagnostic?.Reason);
            return result;
        }
        catch(Exception original)
        {
            if(barrier.Current.State!="Closed")
            {
                LatchFault("CONTROL_INGRESS_FAILED",original.GetType().Name);
                try{PersistFaultOnce();}
                catch(Exception persistence){throw new IOException("Control ingress and first-fault persistence failed; raw/emergency evidence retained",new AggregateException(original,persistence));}
            }
            throw;
        }
        finally{Volatile.Write(ref reading,0);}
    }
    private LinuxForensicJournal.IndexedIngress? RetainFaulted(ReadOnlyMemory<byte> raw,DateTimeOffset receivedUtc,string reason,string? error)
    {
        LatchFault(reason,error);
        // Exact operation/control bytes survive before schema decoding and
        // before fault persistence. A later ACK cannot change this saved view.
        var result=PersistRaw(raw,receivedUtc);Fault(reason,error);return result;
    }
    private LinuxForensicJournal.IndexedIngress? PersistRaw(ReadOnlyMemory<byte> raw,DateTimeOffset receivedUtc)
    {
        var admission=bank.Commit(raw,barrier.Current,receivedUtc);
        if(!admission.Committed){capacityExhausted=true;Fault("RAW_BACKLOG_EXHAUSTED");return null;}
        try{return journal.IndexRawIngress(session,bank,admission.Entry!);}
        catch
        {
            // Indexing already attempts its preallocated emergency receipt.
            // Even when disk writes fail, no subsequent work token is valid.
            barrier.Fault("INGRESS_INDEX_UNCOMMITTED",DateTimeOffset.UtcNow);throw;
        }
    }
}
