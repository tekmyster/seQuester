using System.Security.Cryptography;
using System.Text.Json;
using RansomFree.Contracts;

namespace RansomFree.Client.Forensics;

internal sealed partial class LinuxForensicJournal
{
    internal sealed record SnapshotStorageHealth(long TotalJournalBytes,long QuotaBytes,int AllocationIntents,
        int WriteIntents,int VerifiedReceipts,int UnindexedPrivateFiles,long UnindexedPrivateBytes);
    internal SnapshotStorageHealth ReadSnapshotStorageHealth()
    {
        lock(gate)
        {
            var known=new HashSet<string>(StringComparer.Ordinal);int allocation=0,writes=0,verified=0;
            using(var c=Open())
            {
                using(var q=Command(c,null,"SELECT snapshot_id,state FROM snapshot_intents"))using(var r=q.ExecuteReader())
                    while(r.Read()){known.Add(r.GetString(0)+".bin");switch(r.GetString(1)){case "allocation-intent":allocation++;break;case "write-intent":writes++;break;case "bytes-verified":verified++;break;}}
                using(var q=Command(c,null,"SELECT acquisition FROM work WHERE acquisition IS NOT NULL"))using(var r=q.ExecuteReader())
                    while(r.Read())if(JsonSerializer.Deserialize<LinuxActorAcquisitionEvidence>((byte[])r[0])?.SnapshotId is {} id)known.Add(id+".bin");
            }
            long total=0,unindexedBytes=0;int unindexed=0;
            foreach(var path in Directory.EnumerateFiles(root))
            {
                EvidenceDurability.NoLinks(path);var size=new FileInfo(path).Length;total=checked(total+size);
                if(path.EndsWith(".bin",StringComparison.Ordinal)&&!known.Contains(Path.GetFileName(path))){unindexed++;unindexedBytes=checked(unindexedBytes+size);}
            }
            return new(total,quota,allocation,writes,verified,unindexed,unindexedBytes);
        }
    }
    internal sealed record SnapshotIntent(string EventId,string SnapshotId,LinuxActorLeaseStatus ExpectedStatus,
        FileIdentityEvidence? ReservedFile,string? VerifiedHash,FileIdentityEvidence? VerifiedFile,string State);
    internal SnapshotIntent? ReadSnapshotIntent(string id)
    {
        lock(gate)
        {
            using var c=Open();using var q=Command(c,null,"SELECT snapshot_id,expected_status,reserved_file,verified_hash,verified_file,state FROM snapshot_intents WHERE event_id=$id",("$id",id));using var r=q.ExecuteReader();
            if(!r.Read())return null;
            var intent=new SnapshotIntent(id,r.GetString(0),JsonSerializer.Deserialize<LinuxActorLeaseStatus>((byte[])r[1])!,r.IsDBNull(2)?null:JsonSerializer.Deserialize<FileIdentityEvidence>((byte[])r[2]),r.IsDBNull(3)?null:r.GetString(3),r.IsDBNull(4)?null:JsonSerializer.Deserialize<FileIdentityEvidence>((byte[])r[4]),r.GetString(5));
            if(!Guid.TryParseExact(intent.SnapshotId,"N",out _)||intent.ExpectedStatus==null||!intent.ExpectedStatus.ToEvidence().Ready||!intent.ExpectedStatus.Matches(Read(id).Observation.Attribution!.LinuxKernel!)||
                intent.State is not ("allocation-intent" or "unavailable")&&(intent.ReservedFile?.StableId==null||intent.ReservedFile.Size!=(long)intent.ExpectedStatus.Size))throw new InvalidDataException("Snapshot intent identity corrupted; retained");
            return intent;
        }
    }
    internal LinuxSnapshotAdmission AdmitSnapshot(string id,LinuxActorLeaseStatus status,Action<string>? checkpoint=null)
    {
        Work work;string snapshotId;PrivateWork operation;
        lock(gate)
        {
            work=Read(id);
            if(work.Acquisition!=null||ReadSnapshotIntent(id)!=null)throw new InvalidOperationException("Snapshot work already finalized or admitted; recover its private intent");
            if(!status.Ready||!status.Matches(work.Observation.Attribution!.LinuxKernel!)||!status.ToEvidence().Ready)throw new InvalidDataException("Terminal matching actor status required before destination admission");
            CheckQuota(checked((long)status.Size)+65536);
            snapshotId=Guid.NewGuid().ToString("N");operation=BeginPrivateWorkLocked(id);
            try
            {
                using var c=Open();using var t=c.BeginTransaction();
                Execute(c,t,"INSERT INTO snapshot_intents(event_id,snapshot_id,expected_status,state) VALUES($id,$snapshot,$status,'allocation-intent')",
                    ("$id",id),("$snapshot",snapshotId),("$status",JsonSerializer.SerializeToUtf8Bytes(status)));t.Commit();
            }
            catch{operation.Dispose();throw;}
        }
        using(operation)
        {
            checkpoint?.Invoke("allocation-intent-committed");
            // The exact durable intent precedes allocation. No journal/source
            // lock is held while allocating, flushing or querying private bytes.
            var admission=new LinuxSnapshotAdmission(SnapshotPath(snapshotId),snapshotId,work.Observation,status);
            try
            {
                checkpoint?.Invoke("private-allocation-complete");
                lock(gate)
                {
                    var current=ReadSnapshotIntent(id);
                    if(Read(id).Acquisition!=null||current?.SnapshotId!=snapshotId||current.ExpectedStatus!=status||current.State!="allocation-intent")
                        throw new InvalidDataException("Snapshot destination intent changed during private allocation; artifact retained");
                    using var c=Open();using var t=c.BeginTransaction();
                    Execute(c,t,"UPDATE snapshot_intents SET reserved_file=$file,state='write-intent' WHERE event_id=$id AND state='allocation-intent'",
                        ("$id",id),("$file",JsonSerializer.SerializeToUtf8Bytes(admission.ReservedFile)));t.Commit();
                    admission.BindReceipt(LinuxSnapshotWriteReceipt.ReadCommitted(this,admission));
                }
                checkpoint?.Invoke("write-intent-committed");return admission;
            }
            catch{admission.Dispose();throw;}
        }
    }
    internal void CommitAdmittedSnapshot(LinuxSnapshotAdmission admission,Action<string>? checkpoint=null)
    {
        var id=admission.SourceEventId;SnapshotIntent intent;PrivateWork operation;
        lock(gate)
        {
            intent=ReadSnapshotIntent(id)??throw new InvalidDataException("No durable snapshot write intent");
            if(Read(id).Acquisition is {} final&&final.Status.State!="captured")throw new InvalidOperationException("Acquisition already finalized unavailable; retain private intent");
            admission.RequireWriteReceipt();
            if(admission.SnapshotId!=intent.SnapshotId||admission.ExpectedStatus!=intent.ExpectedStatus||admission.PrivatePath!=SnapshotPath(intent.SnapshotId)||admission.VerifiedFile==null||admission.VerifiedSha256==null)throw new InvalidDataException("Snapshot copy is not verified against its intent");
            operation=BeginPrivateWorkLocked(id);
        }
        using(operation)
        {
            admission.Dispose();
            VerifyPrivate(intent,admission.VerifiedFile!,admission.VerifiedSha256!);
            checkpoint?.Invoke("admitted-private-verified");
            lock(gate)
            {
                if(ReadSnapshotIntent(id)!=intent||Read(id).Acquisition is {Status.State:not "captured"})throw new InvalidDataException("Snapshot state changed during private verification; artifact retained");
                if(intent.State=="write-intent")
                {
                    using var c=Open();using var t=c.BeginTransaction();
                    Execute(c,t,"UPDATE snapshot_intents SET verified_hash=$hash,verified_file=$file,state='bytes-verified' WHERE event_id=$id AND state='write-intent'",
                        ("$id",id),("$hash",admission.VerifiedSha256!),("$file",JsonSerializer.SerializeToUtf8Bytes(admission.VerifiedFile)));t.Commit();
                }
                else if(intent.VerifiedHash!=admission.VerifiedSha256||intent.VerifiedFile!=admission.VerifiedFile)throw new InvalidDataException("Snapshot already has a different immutable receipt");
            }
            checkpoint?.Invoke("admitted-receipt-committed");
        }
        RecoverAdmittedSnapshot(id,allowActiveNativePin:true);
        checkpoint?.Invoke("admitted-manifest-committed");
    }
    internal void AcquireAdmittedSnapshot(LinuxActorLeaseDevice device,LinuxSnapshotAdmission admission)
    {
        var observation=Read(admission.SourceEventId).Observation;
        var receipt=admission.RequireWriteReceipt();
        try{device.ReadReadySnapshotInto(observation,admission);}
        catch(Exception capture)
        {
            try{CommitAdmittedFailure(admission,receipt,capture is System.ComponentModel.Win32Exception native?native.NativeErrorCode.ToString(System.Globalization.CultureInfo.InvariantCulture):capture.GetType().Name);}
            catch(Exception persistence){throw new IOException("ACQUISITION_OUTCOME_UNCOMMITTED: native release not authorized",new AggregateException(capture,persistence));}
            return;
        }
        // A persistence failure here leaves the existing private receipt/intent
        // unresolved. Do not replace it with a guessed successful release.
        CommitAdmittedSnapshot(admission);
    }
    internal void AcquireAdmittedSnapshot(LinuxActorLeaseDevice device,string id,LinuxActorLeaseStatus expected)
    {
        lock(gate)
        {
            var work=Read(id);
            if(work.Acquisition!=null||ReadSnapshotIntent(id)!=null||!expected.ToEvidence().Ready||!expected.Matches(work.Observation.Attribution!.LinuxKernel!))throw new InvalidDataException("Unadmitted work and matching terminal status required");
        }
        LinuxSnapshotAdmission admission;
        try{admission=AdmitSnapshot(id,expected);}
        catch(Exception allocation)
        {
            try{CommitAllocationFailure(id,expected,allocation is System.ComponentModel.Win32Exception native?native.NativeErrorCode.ToString(System.Globalization.CultureInfo.InvariantCulture):allocation.GetType().Name);}
            catch(Exception persistence){throw new IOException("ACQUISITION_OUTCOME_UNCOMMITTED: allocation retained; native release not authorized",new AggregateException(allocation,persistence));}
            return;
        }
        using(admission)AcquireAdmittedSnapshot(device,admission);
    }
    private void CommitAllocationFailure(string id,LinuxActorLeaseStatus expected,string nativeCode)
    {
        lock(gate)
        {
            var work=Read(id);var intent=ReadSnapshotIntent(id);
            if(privateWork.ContainsKey(id))throw new InvalidOperationException("Private allocation is still owned by another operation");
            if(work.Acquisition!=null||!expected.ToEvidence().Ready||!expected.Matches(work.Observation.Attribution!.LinuxKernel!)||intent!=null&&(intent.ExpectedStatus!=expected||intent.State is not ("allocation-intent" or "write-intent")))throw new InvalidDataException("Allocation failure does not match unfinalized raw work");
            CommitUnavailable(id,"ACTOR_COPY_UNAVAILABLE_SNAPSHOT_ADMISSION_FAILED",expected,nativeCode);
            if(intent!=null)SetSnapshotState(id,"unavailable");
        }
    }
    internal void CommitAdmittedFailure(LinuxSnapshotAdmission admission,LinuxSnapshotWriteReceipt receipt,string nativeCode)
    {
        SnapshotIntent intent;PrivateWork operation;
        lock(gate)
        {
            intent=ReadSnapshotIntent(admission.SourceEventId)??throw new InvalidDataException("Snapshot failure has no write intent");
            if(!receipt.Matches(admission)||intent.SnapshotId!=admission.SnapshotId||intent.ExpectedStatus!=admission.ExpectedStatus||intent.ReservedFile!=admission.ReservedFile||intent.State!="write-intent")throw new InvalidDataException("Snapshot failure identity/state differs from write intent");
            operation=BeginPrivateWorkLocked(admission.SourceEventId);
        }
        using(operation)
        {
            admission.MarkFailed();admission.Dispose();
            lock(gate)
            {
                if(ReadSnapshotIntent(admission.SourceEventId)!=intent)throw new InvalidDataException("Snapshot failure context changed during private close");
                CommitUnavailable(admission.SourceEventId,"ACTOR_COPY_UNAVAILABLE_ADMITTED_READ_FAILED",intent.ExpectedStatus,nativeCode);
                SetSnapshotState(admission.SourceEventId,"unavailable");
            }
        }
    }
    private void VerifyPrivate(SnapshotIntent intent,FileIdentityEvidence expected,string hash)
    {
        var path=SnapshotPath(intent.SnapshotId);EvidenceDurability.NoLinks(path);
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);var before=NativeFileIdentity.Read(stream);
        if(intent.ReservedFile==null||before.StableId!=intent.ReservedFile.StableId||before.Size!=intent.ReservedFile.Size||!NativeFileIdentity.Same(before,expected)||hash.Length!=64||Convert.ToHexString(SHA256.HashData(stream))!=hash||!NativeFileIdentity.Same(before,NativeFileIdentity.Read(stream)))throw new InvalidDataException("Admitted private snapshot recovery failed; raw and private bytes retained");
    }
    internal void RecoverAdmittedSnapshot(string id,bool allowActiveNativePin=false)
    {
        SnapshotIntent intent;Work work;PrivateWork operation;
        lock(gate)
        {
            if(privateWork.ContainsKey(id)||!allowActiveNativePin&&activeNativePins.ContainsKey(id))throw new InvalidOperationException("Live operation owns private snapshot outcome");
            intent=ReadSnapshotIntent(id)??throw new InvalidDataException("Snapshot intent missing");work=Read(id);
            if(work.Acquisition!=null)
            {
                if(work.Acquisition.Status.State=="captured"&&(work.Acquisition.SnapshotId!=intent.SnapshotId||work.Acquisition.SnapshotSha256!=intent.VerifiedHash))throw new InvalidDataException("Committed acquisition contradicts snapshot intent");
                SetSnapshotState(id,work.Acquisition.Status.State=="captured"?"manifest-committed":"unavailable");return;
            }
            if(intent.State is "allocation-intent" or "write-intent")
            {
                CommitUnavailable(id,intent.State=="allocation-intent"?"ACTOR_COPY_UNAVAILABLE_SNAPSHOT_ADMISSION_UNCOMMITTED":"ACTOR_COPY_UNAVAILABLE_SNAPSHOT_WRITE_INTERRUPTED",intent.ExpectedStatus);SetSnapshotState(id,"unavailable");return;
            }
            if(intent.State!="bytes-verified"||intent.VerifiedHash==null||intent.VerifiedFile==null)throw new InvalidDataException("Unsupported snapshot recovery state");
            operation=BeginPrivateWorkLocked(id);
        }
        using(operation)
        {
            bool verified;
            try{VerifyPrivate(intent,intent.VerifiedFile,intent.VerifiedHash);verified=true;}
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or System.ComponentModel.Win32Exception){verified=false;}
            lock(gate)
            {
                if(ReadSnapshotIntent(id)!=intent||Read(id).Acquisition!=null)throw new InvalidDataException("Snapshot recovery context changed during verification");
                if(!verified)
                {CommitUnavailable(id,"ACTOR_COPY_UNAVAILABLE_SNAPSHOT_RECOVERY_FAILED",intent.ExpectedStatus);SetSnapshotState(id,"unavailable");return;}
                var k=work.Observation.Attribution!.LinuxKernel!;var n=intent.ExpectedStatus.ToEvidence();
                var acquired=new LinuxActorAcquisitionEvidence{SourceEventId=id,NativeObservationSha256=k.NativeObservationSha256,NativeStatus=n,SnapshotId=intent.SnapshotId,SnapshotSha256=intent.VerifiedHash,SnapshotFile=intent.VerifiedFile,PersistedUtc=DateTimeOffset.UtcNow,SizeMatchesEarlierObservation=n.Size==k.ActorSize,Status=EvidenceStatus.Captured("native-complete-tuple-private-snapshot-verified")};
                CommitAcquisition(work,acquired,new(){StableId=n.SourceStableId,Size=(long)intent.ExpectedStatus.Size,Status=EvidenceStatus.Captured("native-device-inode; source-timestamps-unavailable")});
                SetSnapshotState(id,"manifest-committed");
            }
        }
    }
    private void SetSnapshotState(string id,string state)
    {
        using var c=Open();using var t=c.BeginTransaction();Execute(c,t,"UPDATE snapshot_intents SET state=$state WHERE event_id=$id",("$state",state),("$id",id));t.Commit();
    }
}
