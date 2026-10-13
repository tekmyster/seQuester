namespace RansomFree.Client.Forensics;

// Bounded coordination for the owned source runtime. This is NOT a native
// permit: the source must independently validate raw/session/device identity
// and commit operation intent before issuing a device request. No device,
// journal, file operation or callback runs while this short gate is held.
internal sealed class LinuxSourceWorkBarrier
{
    internal sealed record Interruption(long Generation,string State,string Reason,DateTimeOffset RecordedUtc);
    internal sealed record View(long Generation,string State,string? Reason,DateTimeOffset? ChangedUtc,Interruption? FirstInterruption=null);
    internal sealed record Selection(View Issued,string AuthorizationId,View Authorized,View Starting,string Ordering);
    internal sealed class Work
    {
        internal readonly LinuxSourceWorkBarrier Owner;
        internal readonly View Issued;
        internal readonly string EventId;
        internal readonly bool ObservationOnly;
        internal readonly DateTimeOffset IssuedUtc=DateTimeOffset.UtcNow;
        internal bool Returned;
        internal bool AuthorizationAttempted;
        internal string? AuthorizationId;
        internal View? Authorized;
        internal Selection? Start;
        internal Work(LinuxSourceWorkBarrier owner,string id,View issued,bool observationOnly=false){Owner=owner;EventId=id;Issued=issued;ObservationOnly=observationOnly;}
    }
    private readonly object gate=new();
    private readonly Dictionary<string,Work> issued=new(StringComparer.Ordinal);
    private View view=new(1,"Active",null,null);
    private TaskCompletionSource drained=Completed();
    private static TaskCompletionSource Completed(){var value=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);value.SetResult();return value;}
    internal View Current {get{lock(gate)return view;}}
    // Brackets an observation made OUTSIDE this lock. This is only a historical
    // active-generation check, not proof of continued liveness or zero loss
    // through this call/persistence. The owned runtime must supply its actual
    // sampled map/child evidence and retain the sample's timing separately.
    internal View? TrySealActiveObservation(View before)
    {
        lock(gate)return ReferenceEquals(before,view)&&view.State=="Active"&&view.FirstInterruption==null?view:null;
    }
    internal int InFlight {get{lock(gate)return issued.Count;}}
    internal Work? TryIssue(string eventId)
        =>TryIssueCore(eventId,false);
    // A health read holds the same resource drain barrier but can never enter
    // native actor-selection authorization. It shares the bounded capacity.
    internal Work? TryIssueObservation()=>TryIssueCore(Guid.NewGuid().ToString("N"),true);
    private Work? TryIssueCore(string eventId,bool observationOnly)
    {
        if(!Guid.TryParseExact(eventId,"N",out _))throw new ArgumentException("Canonical committed event ID required");
        lock(gate)
        {
            if(issued.ContainsKey(eventId))throw new InvalidOperationException("This event already has in-flight source work");
            if(view.State!="Active"||issued.Count==4)return null;
            if(issued.Count==0)drained=new(TaskCreationOptions.RunContinuationsAsynchronously);
            var work=new Work(this,eventId,view,observationOnly);issued.Add(eventId,work);return work;
        }
    }
    private void Require(Work work)
    {
        if(!ReferenceEquals(work.Owner,this)||work.Returned||!issued.TryGetValue(work.EventId,out var actual)||!ReferenceEquals(work,actual))
            throw new InvalidOperationException("Source work is foreign or already returned");
    }
    internal View Inspect(Work work){lock(gate){Require(work);return view;}}
    // Call ONLY after the source has committed its exact native authorization.
    // This final in-memory check closes the race between the DB commit and an
    // immediately visible fault/stop whose own DB write may still be pending.
    // An identifier here is coordination evidence, NOT a native capability;
    // the owned runtime must also retain and validate that durable receipt.
    internal bool ConfirmCommittedAuthorization(Work work,string authorizationId)
    {
        if(!Guid.TryParseExact(authorizationId,"N",out _))throw new ArgumentException("Exact durable authorization ID required");
        lock(gate)
        {
            Require(work);
            if(work.ObservationOnly)throw new InvalidOperationException("Health observation cannot authorize native actor work");
            if(work.AuthorizationAttempted)throw new InvalidOperationException("Authorization confirmation is one-use");
            work.AuthorizationAttempted=true;
            if(view.State!="Active"||view.Generation!=work.Issued.Generation)return false;
            work.AuthorizationId=authorizationId;work.Authorized=view;return true;
        }
    }
    // Record this marker durably BEFORE native I/O. It never claims SELECT
    // executed. Only previously confirmed work can start after interruption;
    // bare pre-fault token issuance does not authorize such a late start.
    internal Selection MarkSelectionStarting(Work work)
    {
        lock(gate)
        {
            Require(work);if(work.Start!=null)throw new InvalidOperationException("Selection start marker is one-use");
            if(work.Authorized==null||work.AuthorizationId==null)throw new InvalidOperationException("Durable native authorization must be confirmed before starting work");
            return work.Start=new(work.Issued,work.AuthorizationId,work.Authorized,view,work.Authorized.Generation==view.Generation?"SAME_GENERATION_START":
                view.FirstInterruption?.State=="Faulted"?"AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT":"AUTHORIZED_BEFORE_STOP_SELECT_STARTING_AFTER_STOP");
        }
    }
    internal void Return(Work work)
    {
        TaskCompletionSource? ready=null;
        lock(gate)
        {
            Require(work);work.Returned=true;issued.Remove(work.EventId);if(issued.Count==0)ready=drained;
        }
        ready?.TrySetResult(); // Continuations never execute under the gate.
    }
    private static void Reason(string reason,DateTimeOffset changedUtc)
    {if(string.IsNullOrWhiteSpace(reason)||reason.Length>128||changedUtc==default)throw new ArgumentException("Bounded actual stop reason/time required");}
    internal View Fault(string reason,DateTimeOffset changedUtc)
    {
        Reason(reason,changedUtc);
        lock(gate)
        {
            if(view.State=="Closed")throw new InvalidOperationException("Closed source cannot start another transition");
            // Keep the first stop/fault cause. Later failures must be recorded
            // separately by the journal, rather than replacing its evidence.
            if(view.State=="Active")view=new(checked(view.Generation+1),"Faulted",reason,changedUtc,new(checked(view.Generation+1),"Faulted",reason,changedUtc));
            return view;
        }
    }
    internal View RequestStop(string reason,DateTimeOffset changedUtc)
    {
        Reason(reason,changedUtc);
        lock(gate)
        {
            if(view.State=="Closed")return view;
            if(view.State=="Active")view=new(checked(view.Generation+1),"StopRequested",reason,changedUtc,new(checked(view.Generation+1),"StopRequested",reason,changedUtc));
            return view;
        }
    }
    // Caller may cancel its WAIT, but cannot decrement work or record close
    // from that cancellation. Actual native/file work must call Return itself.
    internal Task BeginClose(string reason,DateTimeOffset changedUtc)
    {
        Reason(reason,changedUtc);
        lock(gate)
        {
            if(view.State is not ("Closing" or "Closed"))
                view=new(checked(view.Generation+1),"Closing",view.Reason??reason,changedUtc,view.FirstInterruption??new(checked(view.Generation+1),"Closing",reason,changedUtc));
            return drained.Task;
        }
    }
    internal void RecordCloseReturned()
    {
        lock(gate)
        {
            if(view.State=="Closed")return;
            if(view.State!="Closing"||issued.Count!=0||!drained.Task.IsCompletedSuccessfully)
                throw new InvalidOperationException("Work must actually return before controller-close receipt");
            // This only follows the caller's actual native close return. The
            // barrier neither calls Dispose nor claims a native completion.
            view=view with{State="Closed"};
        }
    }
}
