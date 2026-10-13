using System.Collections.Concurrent;
using System.Globalization;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

// One selected-stream cursor for the controller privately retained by the
// source owner. It neither opens a controller nor reconstructs old claims.
// All durable authority checks still belong to the source's journal/barrier.
internal sealed class LinuxSerialNativeWorker
{
    internal sealed record ReturnReceipt(LinuxForensicJournal.NativePinClaim Claim,DateTimeOffset ReturnedUtc,string Reason,Exception? Error,LinuxNativeMethodEvidence Method);
    internal sealed record PreNativeFailure(LinuxForensicJournal.NativePinClaim Claim,DateTimeOffset ReturnedUtc,Exception Error);
    private readonly LinuxForensicJournal journal;
    private readonly LinuxSourceWorkBarrier barrier;
    private readonly LinuxActorLeaseDevice device;
    private readonly string session;
    private readonly Action<string>? returnCheckpoint;
    private readonly Action<string>? startupCheckpoint,abortCheckpoint;
    private readonly SemaphoreSlim cursor=new(1,1);
    private readonly ConcurrentDictionary<string,ReturnReceipt> uncommitted=new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string,byte> queued=new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string,PreNativeFailure> beforeNativeFailures=new(StringComparer.Ordinal);
    private int scheduled;
    private readonly object scheduleGate=new();
    private bool accepting=true;
    private readonly TaskCompletionSource managedDrained=new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal ReturnReceipt[] UncommittedReturns=>uncommitted.Values.ToArray();
    internal PreNativeFailure[] PendingPreNativeFailures=>beforeNativeFailures.Values.ToArray();
    internal LinuxSerialNativeWorker(LinuxForensicJournal journal,LinuxSourceWorkBarrier barrier,LinuxActorLeaseDevice ownedController,string sourceSession,Action<string>? returnCheckpoint=null,Action<string>? startupCheckpoint=null,Action<string>? abortCheckpoint=null)
    {this.journal=journal;this.barrier=barrier;device=ownedController;session=sourceSession;this.returnCheckpoint=returnCheckpoint;this.startupCheckpoint=startupCheckpoint;this.abortCheckpoint=abortCheckpoint;}
    internal Task<ReturnReceipt?> RunAsync(LinuxForensicJournal.NativePinClaim claim)
    {
        if(!ReferenceEquals(claim.Journal,journal)||!ReferenceEquals(claim.Barrier,barrier)||claim.Intent.SessionId!=session||claim.Started||claim.Returned)
            throw new InvalidOperationException("This worker requires its source's fresh in-process claim");
        lock(scheduleGate)
        {
            if(!accepting)throw new InvalidOperationException("Native worker scheduling has closed");
            if(scheduled>=4)throw new InvalidOperationException("Native work exceeds the owned four-claim bound");
            if(!queued.TryAdd(claim.Intent.EventId,0))throw new InvalidOperationException("This claim is already scheduled");
            scheduled++;
        }
        // Even a synchronously completing semaphore wait must not execute a
        // blocking ioctl/read/private fsync on the raw ingress caller's thread.
        // Native retention has a kernel deadline. Shared thread-pool starvation
        // behind synchronous journal/export work must not postpone START. The
        // existing four-claim limit also bounds these dedicated workers; the
        // cursor still permits only one controller stream operation at a time.
        return Task.Factory.StartNew(()=>
        {
            try
            {
                cursor.Wait();
                try{return Execute(claim);}
                finally{cursor.Release();}
            }
            finally{lock(scheduleGate){scheduled--;queued.TryRemove(claim.Intent.EventId,out _);CompleteDrainIfReady();}}
        },CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
    }
    // Call after stopping the source barrier. This closes scheduling without
    // canceling any actual operation. The owner must ALSO await the barrier
    // (which may include issued but unscheduled claims) before controller close.
    internal Task FinishScheduling()
    {
        lock(scheduleGate)
        {
            if(barrier.Current.State=="Active")throw new InvalidOperationException("Source must stop before closing native scheduling");
            accepting=false;CompleteDrainIfReady();return managedDrained.Task;
        }
    }
    private void CompleteDrainIfReady()
    {if(!accepting&&scheduled==0&&uncommitted.IsEmpty&&beforeNativeFailures.IsEmpty)managedDrained.TrySetResult();}
    private ReturnReceipt? Execute(LinuxForensicJournal.NativePinClaim claim)
    {
        try
        {
            if(!journal.AuthorizeNativePin(claim,startupCheckpoint)){journal.AbortNativePinBeforeStart(claim,abortCheckpoint);return null;}
            journal.MarkNativePinStarting(claim,startupCheckpoint);
        }
        catch(Exception original)when(original is not OutOfMemoryException)
        {
            barrier.Fault("NATIVE_AUTHORIZATION_FAILED",DateTimeOffset.UtcNow);
            // No device method has been reached. Keep this exact failed
            // orchestration fact even if its abort/return receipt cannot commit.
            var beforeFailure=new PreNativeFailure(claim,DateTimeOffset.UtcNow,original);
            if(!beforeNativeFailures.TryAdd(claim.Intent.EventId,beforeFailure))throw new InvalidOperationException("Pre-native failure already retained");
            try{CommitPreNativeFailure(beforeFailure);}
            catch(Exception receipt){throw new IOException("Pre-native failure and its durable receipt require reconciliation",new AggregateException(original,receipt));}
            throw;
        }
        string reason="NATIVE_OPERATION_RETURNED";Exception? failure=null;
        var method=new LinuxNativeMethodEvidence{PinId=claim.Intent.PinId,LastStep="WORK_CONTEXT"};
        try
        {
            var work=journal.Read(claim.Intent.EventId);var k=work.Observation.Attribution!.LinuxKernel!;
            if(k.Lease<=0)
            {reason="NATIVE_METHOD_NOT_CALLED_NO_LEASE";method=method with{LastStep="NO_NATIVE_LEASE"};journal.CommitUnavailable(work.Observation.EventId,"ACTOR_COPY_UNAVAILABLE_NO_NATIVE_LEASE");journal.RecordDrop(work.Observation.EventId,"not-applicable");}
            else
            {
                if(claim.AtomicKey!=null)
                {
                    method=method with{ControllerMethodAttempted=true,LastStep="ATOMIC_START_METHOD"};
                    var authorization=journal.RequireAtomicCopyAuthorization(claim);
                    device.StartAtomicAuthorizedCopy(authorization.Key,authorization.AuthorizationId);
                }
                while(true)
                {
                    method=method with{ControllerMethodAttempted=true,LastStep="STATUS_METHOD"};
                    var status=device.Status(k);method=method with{LatestStatus=status.ToEvidence()};journal.RecordNativeProgress(work.Observation.EventId,status);
                    if(!LinuxNativeDisposition.MayRelease(status))
                    {
                        // Stopping this userspace polling loop does not claim
                        // the kernel's copy stopped. Unknown pin/drop remains;
                        // the source must separately await the real close.
                        if(barrier.Current.State!="Active"){reason="NATIVE_PENDING_AT_SOURCE_STOP";break;}
                        // This runs only on a dedicated bounded native worker.
                        // Keep status polling off the shared pool as well.
                        Thread.Sleep(10);continue;
                    }
                    if(status.Ready){method=method with{LastStep="ACTOR_CAPTURE"};journal.AcquireAdmittedSnapshot(device,work.Observation.EventId,status);}
                    else journal.CommitUnavailable(work.Observation.EventId,LinuxNativeDisposition.Classify(status),status,status.Error.ToString(CultureInfo.InvariantCulture));
                    var acquired=journal.Read(work.Observation.EventId);
                    if(acquired.Acquisition==null)throw new InvalidDataException("Native result has no durable acquisition outcome");
                    if(acquired.Acquisition.Status.State=="captured")
                    {
                        using var verified=journal.RestoreActor(work.Observation.EventId);
                        if(verified.Image==null)throw new IOException("Committed private actor receipt no longer verifies; release refused");
                    }
                    method=method with{LastStep="PRE_DROP_STATUS_METHOD"};
                    var beforeDrop=device.Status(k);method=method with{LatestStatus=beforeDrop.ToEvidence()};journal.RecordNativeProgress(work.Observation.EventId,beforeDrop);
                    if(acquired.Acquisition.NativeStatus!=beforeDrop.ToEvidence())throw new InvalidDataException("Terminal tuple differs from committed acquisition before release");
                    method=method with{LastStep="DROP_METHOD",DropMethodAttempted=true};device.DropExact(k,beforeDrop);
                    method=method with{LastStep="DROP_RECEIPT_COMMIT",DropMethodReturned=true};journal.RecordDrop(work.Observation.EventId,"returned");
                    method=method with{DropReceiptCommitObserved=true};break;
                }
            }
        }
        catch(Exception ex)when(ex is not OutOfMemoryException)
        {
            failure=ex;reason="NATIVE_OPERATION_FAILED";barrier.Fault(reason,DateTimeOffset.UtcNow);
            method=WithError(method,ex);
        }
        // Actual managed operation return is independent of committed bytes,
        // successful DROP, and later controller close. Save it before SQLite.
        var returned=new ReturnReceipt(claim,DateTimeOffset.UtcNow,reason,failure,method);
        if(!uncommitted.TryAdd(claim.Intent.EventId,returned))throw new InvalidOperationException("Native method return already retained");
        try{CommitReturn(returned);}
        catch{barrier.Fault("NATIVE_RETURN_UNCOMMITTED",DateTimeOffset.UtcNow);throw;}
        return returned;
    }
    private void CommitReturn(ReturnReceipt receipt)
    {
        journal.RecordNativePinReturn(receipt.Claim,receipt.ReturnedUtc,receipt.Reason,receipt.Method,returnCheckpoint);
        uncommitted.TryRemove(receipt.Claim.Intent.EventId,out _);
        lock(scheduleGate)CompleteDrainIfReady();
    }
    private static LinuxNativeMethodEvidence WithError(LinuxNativeMethodEvidence method,Exception ex)
        =>method with{ErrorKind=ex.GetType().FullName,ErrorDomain=ex is System.ComponentModel.Win32Exception?"posix":ex is Microsoft.Data.Sqlite.SqliteException?"sqlite":"dotnet",
            ErrorCode=(ex is System.ComponentModel.Win32Exception n?n.NativeErrorCode:ex is Microsoft.Data.Sqlite.SqliteException sql?sql.SqliteExtendedErrorCode:ex.HResult).ToString(CultureInfo.InvariantCulture),ErrorDetail=ex.Message.Length>256?ex.Message[..256]:ex.Message};
    private void CommitPreNativeFailure(PreNativeFailure failure)
    {
        var claim=failure.Claim;
        if(!claim.Returned)
        {
            if(journal.ReconcileUncalledNativeStart(claim))
            {
                var method=WithError(new(){PinId=claim.Intent.PinId,LastStep="WORK_CONTEXT",ControllerMethodAttempted=false},failure.Error);
                var returned=uncommitted.GetOrAdd(claim.Intent.EventId,new ReturnReceipt(claim,failure.ReturnedUtc,"NATIVE_OPERATION_FAILED",failure.Error,method));
                CommitReturn(returned);
            }
            else journal.AbortNativePinBeforeStart(claim,abortCheckpoint);
        }
        beforeNativeFailures.TryRemove(claim.Intent.EventId,out _);
        lock(scheduleGate)CompleteDrainIfReady();
    }
    internal async Task RetryUncommittedReturnsAsync()
    {
        await cursor.WaitAsync().ConfigureAwait(false);
        try
        {
            foreach(var failure in beforeNativeFailures.Values.ToArray())CommitPreNativeFailure(failure);
            foreach(var receipt in uncommitted.Values.ToArray())CommitReturn(receipt);
        }
        finally{cursor.Release();}
    }
}
