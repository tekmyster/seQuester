using System.Text.Json;
using RansomFree.Client.Forensics;

static class SourceWorkBarrierChecks
{
    internal static async Task Run()
    {
        int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is ArgumentException or InvalidOperationException){Check(true,label);return;}throw new Exception("Unexpected barrier acceptance: "+label);}
        var barrier=new LinuxSourceWorkBarrier();var work=Enumerable.Range(0,4).Select(_=>barrier.TryIssue(Guid.NewGuid().ToString("N"))!).ToArray();
        Check(barrier.InFlight==4&&barrier.TryIssue(Guid.NewGuid().ToString("N"))==null,"four in-flight entries bound coordination memory");
        Reject(()=>barrier.TryIssue(work[0].EventId),"duplicate live work cannot manufacture a second entry");
        Reject(()=>barrier.MarkSelectionStarting(work[0]),"bare work token cannot start native selection coordination");
        var authorization=Guid.NewGuid().ToString("N");
        Check(barrier.ConfirmCommittedAuthorization(work[0],authorization)&&barrier.ConfirmCommittedAuthorization(work[1],Guid.NewGuid().ToString("N")),"same-generation final coordination latch accepts a committed authorization reference");
        Reject(()=>barrier.ConfirmCommittedAuthorization(work[0],Guid.NewGuid().ToString("N")),"confirmed authorization cannot be exchanged for another identity");
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var worker=Task.Run(async()=>{entered.SetResult();await release.Task;barrier.MarkSelectionStarting(work[0]);barrier.Return(work[0]);});
        await entered.Task;
        var fault=barrier.Fault("LOADER_LOST_COUNTER_INCREASED",DateTimeOffset.UtcNow);
        Check(fault.State=="Faulted"&&barrier.TryIssue(Guid.NewGuid().ToString("N"))==null,"loss transition progresses while an existing worker is blocked and denies new work");
        Check(!barrier.ConfirmCommittedAuthorization(work[2],Guid.NewGuid().ToString("N")),"fault before final confirmation refuses an unstarted operation even if DB commit preceded it");
        Reject(()=>barrier.MarkSelectionStarting(work[2]),"unconfirmed pre-fault token cannot start after fault");
        Reject(()=>barrier.ConfirmCommittedAuthorization(work[2],Guid.NewGuid().ToString("N")),"rejected authorization confirmation cannot be retried");
        var start=barrier.MarkSelectionStarting(work[1]);
        Check(start.Issued.State=="Active"&&start.Authorized.State=="Active"&&start.Starting==fault&&start.Ordering=="AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT","previously authorized work retains both sides of the start ordering");
        Reject(()=>barrier.MarkSelectionStarting(work[1]),"selection marker cannot be replayed");
        Check(barrier.Fault("SECONDARY_ERROR",DateTimeOffset.UtcNow)==fault,"later fault does not erase original cause");
        var drain=barrier.BeginClose("REQUESTED_CLOSE",DateTimeOffset.UtcNow);
        Check(!drain.IsCompleted&&barrier.InFlight==4&&barrier.Current.Reason==fault.Reason,"close preserves first fault and waits for actual work return");
        using(var canceled=new CancellationTokenSource())
        {
            canceled.Cancel();try{await drain.WaitAsync(canceled.Token);throw new Exception("Expected canceled managed wait");}catch(OperationCanceledException){}
            Check(!drain.IsCompleted&&barrier.InFlight==4,"canceling only a wait never completes work or closes source");
        }
        Reject(barrier.RecordCloseReturned,"blocked work forbids close-return coordination");
        for(int i=1;i<work.Length;i++)barrier.Return(work[i]);
        Check(!drain.IsCompleted&&barrier.InFlight==1,"last real blocked worker retains ownership");
        release.SetResult();await worker;await drain;
        Check(barrier.InFlight==0&&drain.IsCompletedSuccessfully,"drain completes only after last actual worker return");
        Check(work[0].Start!.AuthorizationId==authorization&&work[0].Start!.Ordering=="AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT"&&work[0].Start!.Starting.State=="Closing"&&work[0].Start!.Starting.FirstInterruption==fault.FirstInterruption,"late start retains exact authorization, closing state and original fault transition");
        barrier.RecordCloseReturned();Check(barrier.Current.State=="Closed"&&barrier.TryIssue(Guid.NewGuid().ToString("N"))==null,"closed barrier cannot restart source work");
        Reject(()=>barrier.Return(work[0]),"returned work cannot decrement twice");
        Reject(()=>barrier.MarkSelectionStarting(work[0]),"returned work cannot resume native selection coordination");
        Reject(()=>new LinuxSourceWorkBarrier().Return(work[0]),"foreign source cannot return this work");
        Reject(()=>barrier.Fault("LATE",DateTimeOffset.UtcNow),"closed source cannot be resurrected by late failure");
        var clean=new LinuxSourceWorkBarrier();var original=clean.TryIssue(Guid.NewGuid().ToString("N"))!;
        Check(clean.ConfirmCommittedAuthorization(original,Guid.NewGuid().ToString("N")),"normal authorization confirms before start");
        Check(clean.MarkSelectionStarting(original).Ordering=="SAME_GENERATION_START","normal work records same generation ordering");
        clean.Return(original);var replacement=clean.TryIssue(Guid.NewGuid().ToString("N"))!;
        Check(clean.ConfirmCommittedAuthorization(replacement,Guid.NewGuid().ToString("N")),"replacement work has its own authorization reference");
        Check(clean.InFlight==1,"real returned work frees exactly one bounded slot");
        var stop=clean.RequestStop("USER_STOP",DateTimeOffset.UtcNow);Check(stop.State=="StopRequested"&&clean.TryIssue(Guid.NewGuid().ToString("N"))==null,"ordinary stop also rejects new work");
        Check(clean.MarkSelectionStarting(replacement).Starting==stop,"pre-stop entry retains observed stop at selection marker");
        var closing=clean.BeginClose("CLOSE",DateTimeOffset.UtcNow);clean.Return(replacement);await closing;clean.RecordCloseReturned();
        var empty=new LinuxSourceWorkBarrier();Check(empty.BeginClose("EMPTY",DateTimeOffset.UtcNow).IsCompletedSuccessfully,"zero-work close has no fabricated wait");empty.RecordCloseReturned();
        Reject(()=>new LinuxSourceWorkBarrier().RecordCloseReturned(),"active source cannot report a close return");
        Reject(()=>new LinuxSourceWorkBarrier().TryIssue("pid-123"),"PID string cannot serve as an event identity");
        Reject(()=>new LinuxSourceWorkBarrier().Fault(new string('x',129),DateTimeOffset.UtcNow),"unbounded stop diagnostics rejected");
        var race=new LinuxSourceWorkBarrier();var delayed=race.TryIssue(Guid.NewGuid().ToString("N"))!;
        var commitStarted=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var commitReturned=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var committing=Task.Run(async()=>{commitStarted.SetResult();await commitReturned.Task;return race.ConfirmCommittedAuthorization(delayed,Guid.NewGuid().ToString("N"));});
        await commitStarted.Task;race.RequestStop("STOP_WHILE_COMMIT_PENDING",DateTimeOffset.UtcNow);commitReturned.SetResult();
        Check(!await committing,"stop during delayed durable commit wins the final in-memory authorization race");
        Reject(()=>race.MarkSelectionStarting(delayed),"late DB completion cannot authorize stopped source work");
        race.Return(delayed);Check(race.InFlight==0,"refused operation returns coordination slot without native I/O");
        var sampled=new LinuxSourceWorkBarrier();var before=sampled.Current;
        Check(ReferenceEquals(sampled.TrySealActiveObservation(before),before),"unchanged active source brackets an out-of-lock observation");
        Check(sampled.TrySealActiveObservation(before with{})==null,"reconstructed view is not the owner's actual active observation");
        Check(new LinuxSourceWorkBarrier().TrySealActiveObservation(before)==null,"foreign owner cannot seal matching generation numbers");
        var historical=sampled.TrySealActiveObservation(before)!;
        sampled.RequestStop("AFTER_SAMPLE",DateTimeOffset.UtcNow);
        Check(historical.State=="Active"&&historical.FirstInterruption==null&&sampled.Current.State=="StopRequested","post-seal stop does not rewrite immutable historical source sample");
        Check(sampled.TrySealActiveObservation(before)==null&&sampled.TrySealActiveObservation(sampled.Current)==null,"stopped source cannot create another active observation");
        await sampled.BeginClose("AFTER_SAMPLE_CLOSE",DateTimeOffset.UtcNow);sampled.RecordCloseReturned();
        Check(sampled.TrySealActiveObservation(before)==null&&sampled.TrySealActiveObservation(sampled.Current)==null,"closed source cannot resurrect prior sample authority");
        var bracket=new LinuxSourceWorkBarrier();var captured=bracket.Current;
        var sampling=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var sampledValue=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var observationTask=Task.Run(async()=>{sampling.SetResult();await sampledValue.Task;return bracket.TrySealActiveObservation(captured);});
        await sampling.Task;bracket.Fault("FAULT_DURING_SAMPLE",DateTimeOffset.UtcNow);sampledValue.SetResult();
        Check(await observationTask==null,"fault while actual sample task waits prevents sealing");
        Check(bracket.Current.Generation>captured.Generation&&bracket.TrySealActiveObservation(bracket.Current)==null,"fault transition is terminal for active generation even with a fresh view");
        await bracket.BeginClose("FAULTED_SAMPLE_CLOSE",DateTimeOffset.UtcNow);bracket.RecordCloseReturned();
        var service=new LinuxSourceWorkBarrier();var serviceRead=service.TryIssueObservation()!;
        Check(serviceRead.ObservationOnly&&service.InFlight==1,"service health retains an explicitly observation-only resource hold");
        Reject(()=>service.ConfirmCommittedAuthorization(serviceRead,Guid.NewGuid().ToString("N")),"health read cannot acquire actor-selection authorization");
        Reject(()=>service.MarkSelectionStarting(serviceRead),"health read cannot start a native selection");
        var serviceDrain=service.BeginClose("SERVICE_SAMPLE_STOP",DateTimeOffset.UtcNow);
        Check(!serviceDrain.IsCompleted&&service.TryIssueObservation()==null,"stop waits for actual health sample and refuses additional samples");
        service.Return(serviceRead);await serviceDrain;service.RecordCloseReturned();
        Check(service.InFlight==0&&service.Current.State=="Closed","sample return permits normal actual resource closure coordination");
        var boundedHealth=new LinuxSourceWorkBarrier();var heldHealth=Enumerable.Range(0,4).Select(_=>boundedHealth.TryIssueObservation()!).ToArray();
        Check(boundedHealth.TryIssueObservation()==null&&boundedHealth.TryIssue(Guid.NewGuid().ToString("N"))==null,"health and actor observations share the four-entry bound");
        foreach(var read in heldHealth)boundedHealth.Return(read);
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Checks=checks,Scope="Bounded source coordination with blocked real tasks; no native authority, I/O cancellation, source activation or production deployment"}));
    }
}
