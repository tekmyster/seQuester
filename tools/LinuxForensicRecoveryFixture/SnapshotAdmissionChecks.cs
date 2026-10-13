using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class SnapshotAdmissionChecks
{
    internal static void RunChild(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,string cut)
    {
        void Stop(string point){if(cut==point)Environment.Exit(73);}
        using var journal=new LinuxForensicJournal(root,sensor);journal.CommitObservation(raw,observation,new());
        using var admission=journal.AdmitSnapshot(observation.EventId,snapshot.NativeStatus,Stop);
        if(cut=="partial")
        {
            admission.BeginRead(observation,snapshot.NativeStatus);admission.Append(snapshot.Bytes.Span[..(snapshot.Bytes.Length/2)]);Stop("partial");
        }
        using var device=new LinuxActorLeaseDevice(new Port(snapshot.NativeStatus,snapshot.Bytes.ToArray()));
        device.ReadReadySnapshotInto(observation,admission);journal.CommitAdmittedSnapshot(admission,Stop);
        throw new Exception("Snapshot crash cut not reached");
    }
    internal static async Task RunCrashCuts(string root,string sensor,AgentEvent observation,LinuxActorSnapshot snapshot,string seedPath,Action<bool,string> check)
    {
        var cuts=new[]{"allocation-intent-committed","private-allocation-complete","write-intent-committed","partial","admitted-private-verified","admitted-receipt-committed","admitted-manifest-committed"};
        foreach(var cut in cuts)
        {
            var directory=Path.Combine(root,"admitted-child-"+cut);
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardError=true,RedirectStandardOutput=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(SnapshotAdmissionChecks).Assembly.Location);
            foreach(var arg in new[]{"admitted-child",seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var errors=child.StandardError.ReadToEndAsync();var output=child.StandardOutput.ReadToEndAsync();
            await FixtureProcessTiming.Wait(child);File.WriteAllText(Path.Combine(root,"admitted-child-"+cut+".log"),await output+await errors);
            check(child.ExitCode==73,"actual child exit at admitted snapshot boundary: "+cut);
            using var journal=new LinuxForensicJournal(directory,sensor);var intent=journal.ReadSnapshotIntent(observation.EventId)!;
            var path=Path.Combine(directory,"linux-forensic-intake",intent.SnapshotId+".bin");
            check(intent.EventId==observation.EventId&&intent.ExpectedStatus==snapshot.NativeStatus&&File.Exists(path)==(cut!="allocation-intent-committed"),"private allocation remains linked to exact source across actual exit: "+cut);
            journal.RecoverAdmittedSnapshot(observation.EventId);var result=journal.Read(observation.EventId).Acquisition!;
            var captured=cut is "admitted-receipt-committed" or "admitted-manifest-committed";
            check(captured?result.Status.State=="captured"&&result.SnapshotSha256==snapshot.Sha256.ToUpperInvariant():result.Status.State=="unavailable"&&result.SnapshotSha256==null,"actual child recovery requires committed private receipt: "+cut);
            if(cut=="partial")check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))!=snapshot.Sha256.ToUpperInvariant(),"actual partial private bytes cannot equal verified full executable hash");
        }
    }
    internal static void Run(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,Action<bool,string> check)
    {
        void Reject(Action action,string label)
        {try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException or SqliteException or ArgumentException){check(true,label);return;}throw new Exception("Expected rejection: "+label);}
        var id=observation.EventId;var status=snapshot.NativeStatus;var bytes=snapshot.Bytes.ToArray();
        var directory=Path.Combine(root,"admitted-snapshot-success");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());
            using var admission=journal.AdmitSnapshot(id,status);var port=new Port(status,bytes);using var device=new LinuxActorLeaseDevice(port);
            check(admission.IntentCommitted&&journal.ReadSnapshotIntent(id)?.State=="write-intent"&&admission.ReservedFile.Size==bytes.Length&&port.Selects==0,"exact snapshot size and private identity are durable before any SELECT");
            check(journal.ReadSnapshotStorageHealth() is {WriteIntents:1,UnindexedPrivateFiles:0},"snapshot health exposes durable write intent and linked private allocation");
            check(admission.PhysicalAllocationEstablished==OperatingSystem.IsLinux(),"snapshot allocation distinguishes Linux fallocate from layout replay");
            device.ReadReadySnapshotInto(observation,admission);
            check(admission.VerifiedSha256==Convert.ToHexString(SHA256.HashData(bytes))&&port.Selects==1&&port.StatusReads==2&&port.Drops==0,"streaming native capture verifies status B/C and private readback without implicit DROP");
            journal.CommitAdmittedSnapshot(admission);var a=journal.Read(id).Acquisition!;
            using var restored=journal.RestoreActor(id);
            check(a.SnapshotId==admission.SnapshotId&&a.Status.State=="captured"&&restored.Image!=null&&journal.ReadSnapshotIntent(id)?.State=="manifest-committed","admitted destination becomes the same recoverable acquisition artifact");
            Reject(()=>journal.AdmitSnapshot(id,status),"committed snapshot cannot be recaptured under another name");
        }
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var before=journal.Read(id).Acquisition;journal.RecoverAdmittedSnapshot(id);
            check(before==journal.Read(id).Acquisition,"restart retains exact committed acquisition receipt");
        }
        foreach(var fault in new[]{"before-select","after-read","short","excess","read-error"})
        {
            directory=Path.Combine(root,"admitted-fault-"+fault);
            using var journal=new LinuxForensicJournal(directory,sensor);journal.CommitObservation(raw,observation,new());
            using var admission=journal.AdmitSnapshot(id,status);var port=new Port(status,fault=="short"?bytes[..^1]:fault=="excess"?[..bytes,0]:bytes){ChangeBefore=fault=="before-select",ChangeAfter=fault=="after-read",ReadError=fault=="read-error"};
            using var device=new LinuxActorLeaseDevice(port);
            Reject(()=>device.ReadReadySnapshotInto(observation,admission),"admitted capture refuses "+fault);
            check(admission.VerifiedSha256==null&&port.Drops==0&&(fault!="before-select"||port.Selects==0),"failed acquisition has no verified hash or premature native release: "+fault);
            admission.Dispose();journal.RecoverAdmittedSnapshot(id);
            check(journal.Read(id).Acquisition?.Status.State=="unavailable"&&File.Exists(admission.PrivatePath),"failed acquisition retains raw and private artifact with explicit unavailable outcome: "+fault);
        }
        foreach(var cut in new[]{"write-intent","partial","admitted-private-verified","admitted-receipt-committed","admitted-manifest-committed"})
        {
            directory=Path.Combine(root,"admitted-restart-"+cut);string path;
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                journal.CommitObservation(raw,observation,new());using var admission=journal.AdmitSnapshot(id,status);path=admission.PrivatePath;
                if(cut=="partial"){admission.BeginRead(observation,status);admission.Append(bytes.AsSpan(0,bytes.Length/2));}
                else if(cut!="write-intent")
                {
                    using var device=new LinuxActorLeaseDevice(new Port(status,bytes));device.ReadReadySnapshotInto(observation,admission);
                    Reject(()=>journal.CommitAdmittedSnapshot(admission,point=>{if(point==cut)throw new IOException("injected stop at "+cut);}),"interrupted admitted commit: "+cut);
                }
            }
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                journal.RecoverAdmittedSnapshot(id);var a=journal.Read(id).Acquisition!;
                bool complete=cut is "admitted-receipt-committed" or "admitted-manifest-committed";
                check(File.Exists(path)&&(complete?a.Status.State=="captured"&&a.SnapshotSha256==Convert.ToHexString(SHA256.HashData(bytes)):a.Status.State=="unavailable"&&a.SnapshotSha256==null),"reopen uses only durable private receipt or records unavailable: "+cut);
            }
        }
        directory=Path.Combine(root,"admitted-sqlite-outcome-failure");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());using var admission=journal.AdmitSnapshot(id,status);var port=new Port(status,bytes);using var device=new LinuxActorLeaseDevice(port);
            device.ReadReadySnapshotInto(observation,admission);
            Sql(directory,"CREATE TRIGGER owned_fail_receipt BEFORE UPDATE ON snapshot_intents WHEN NEW.state='bytes-verified' BEGIN SELECT RAISE(FAIL,'owned receipt failure'); END;");
            Reject(()=>journal.CommitAdmittedSnapshot(admission),"SQLite receipt failure after private copy remains uncommitted");
            check(journal.Read(id).Acquisition==null&&journal.ReadSnapshotIntent(id)?.State=="write-intent"&&port.Drops==0&&File.Exists(admission.PrivatePath),"uncommitted outcome retains private data and cannot authorize DROP");
            Sql(directory,"DROP TRIGGER owned_fail_receipt;");journal.RecoverAdmittedSnapshot(id);
            check(journal.Read(id).Acquisition?.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SNAPSHOT_WRITE_INTERRUPTED","complete-looking bytes without a committed receipt remain explicitly unverified");
        }
        directory=Path.Combine(root,"admitted-sqlite-intent-failure");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());
            Sql(directory,"CREATE TRIGGER owned_fail_intent BEFORE UPDATE ON snapshot_intents WHEN NEW.state='write-intent' BEGIN SELECT RAISE(FAIL,'owned intent failure'); END;");
            Reject(()=>journal.AdmitSnapshot(id,status),"SQLite write-intent failure returns no selectable admission");
            var intent=journal.ReadSnapshotIntent(id)!;
            check(intent.State=="allocation-intent"&&intent.ReservedFile==null&&journal.Read(id).Acquisition==null&&File.Exists(Path.Combine(directory,"linux-forensic-intake",intent.SnapshotId+".bin")),"uncommitted allocation retains exact durable source-event association");
            check(journal.ReadSnapshotStorageHealth() is {AllocationIntents:1,UnindexedPrivateFiles:0},"uncommitted preselect allocation is visible by intent without being an unlinked orphan");
            journal.RecoverAdmittedSnapshot(id);
            check(journal.Read(id).Acquisition?.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SNAPSHOT_ADMISSION_UNCOMMITTED","failed write intent finalizes one linked unavailable result without selecting");
        }
        directory=Path.Combine(root,"admitted-allocation-intent-failure");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());
            Sql(directory,"CREATE TRIGGER owned_fail_allocation BEFORE INSERT ON snapshot_intents BEGIN SELECT RAISE(FAIL,'owned allocation intent failure'); END;");
            Reject(()=>journal.AdmitSnapshot(id,status),"failed allocation-intent transaction creates no private file");
            check(journal.ReadSnapshotIntent(id)==null&&Directory.GetFiles(Path.Combine(directory,"linux-forensic-intake"),"*.bin").Length==0,"allocation-intent failure cannot create an unlinked orphan");
        }
        directory=Path.Combine(root,"admitted-boundary-read-failure");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());using var admission=journal.AdmitSnapshot(id,status);var port=new Port(status,bytes){ReadError=true};using var device=new LinuxActorLeaseDevice(port);
            journal.AcquireAdmittedSnapshot(device,admission);
            check(journal.Read(id).Acquisition?.Status is {Reason:"ACTOR_COPY_UNAVAILABLE_ADMITTED_READ_FAILED",NativeCode:"IOException"}&&journal.ReadSnapshotIntent(id)?.State=="unavailable"&&port.Drops==0,"acquisition boundary commits explicit read failure with raw error type before any release");
            Reject(()=>journal.CommitSnapshot(id,snapshot),"memory-copy API cannot bypass an admitted snapshot intent");
        }
        directory=Path.Combine(root,"admitted-no-write-receipt");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());var unboundId=Guid.NewGuid().ToString("N");
            using var admission=new LinuxSnapshotAdmission(Path.Combine(directory,"linux-forensic-intake",unboundId+".bin"),unboundId,observation,status);
            var port=new Port(status,bytes);using var device=new LinuxActorLeaseDevice(port);
            Reject(()=>LinuxSnapshotWriteReceipt.ReadCommitted(journal,admission),"receipt cannot be issued without an actual matching durable write intent");
            Reject(()=>device.ReadReadySnapshotInto(observation,admission),"unreceipted private destination cannot authorize SELECT");
            check(port.Selects==0&&port.Drops==0,"missing receipt prevents native selection and release");
            check(journal.ReadSnapshotStorageHealth() is {UnindexedPrivateFiles:1} health&&health.UnindexedPrivateBytes==bytes.Length,"unlinked private test artifact remains explicitly counted against journal storage");
        }
        directory=Path.Combine(root,"admitted-corrupt-private");string privatePath;
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());using var admission=journal.AdmitSnapshot(id,status);privatePath=admission.PrivatePath;
            using var device=new LinuxActorLeaseDevice(new Port(status,bytes));device.ReadReadySnapshotInto(observation,admission);
            Reject(()=>journal.CommitAdmittedSnapshot(admission,p=>{if(p=="admitted-receipt-committed")throw new IOException("owned cut");}),"retained verified private receipt before recovery corruption");
        }
        using(var stream=new FileStream(privatePath,FileMode.Open,FileAccess.Write)){stream.WriteByte((byte)(bytes[0]^1));stream.Flush(true);}
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.RecoverAdmittedSnapshot(id);
            check(journal.Read(id).Acquisition?.Status.Reason=="ACTOR_COPY_UNAVAILABLE_SNAPSHOT_RECOVERY_FAILED"&&File.Exists(privatePath),"corrupted verified private copy is retained and cannot become a captured acquisition");
        }
        directory=Path.Combine(root,"admitted-quota");
        using(var journal=new LinuxForensicJournal(directory,sensor,2*LinuxForensicJournal.PerWorkReservation))
        {
            journal.CommitObservation(raw,observation,new());
            using(var filler=File.Create(Path.Combine(directory,"linux-forensic-intake","owned-quota-filler")))filler.SetLength(2*LinuxForensicJournal.PerWorkReservation);
            Reject(()=>journal.AdmitSnapshot(id,status),"snapshot quota failure returns no native selection permit");
            check(journal.ReadSnapshotIntent(id)==null&&journal.Read(id).Acquisition==null,"quota rejection keeps raw evidence without invented destination metadata");
        }
        foreach(var failure in new[]{"initial-intent","write-intent","outcome-uncommitted"})
        {
            directory=Path.Combine(root,"allocation-boundary-"+failure);using var journal=new LinuxForensicJournal(directory,sensor);journal.CommitObservation(raw,observation,new());
            if(failure=="initial-intent")Sql(directory,"CREATE TRIGGER owned_fail_alloc BEFORE INSERT ON snapshot_intents BEGIN SELECT RAISE(FAIL,'owned allocation failure'); END;");
            else Sql(directory,"CREATE TRIGGER owned_fail_write BEFORE UPDATE ON snapshot_intents WHEN NEW.state='write-intent' BEGIN SELECT RAISE(FAIL,'owned write intent failure'); END;");
            if(failure=="outcome-uncommitted")Sql(directory,"CREATE TRIGGER owned_fail_outcome BEFORE UPDATE ON work WHEN NEW.acquisition IS NOT NULL BEGIN SELECT RAISE(FAIL,'owned outcome failure'); END;");
            var port=new Port(status,bytes);using var device=new LinuxActorLeaseDevice(port);
            if(failure=="outcome-uncommitted")
            {
                try{journal.AcquireAdmittedSnapshot(device,id,status);throw new Exception("Uncommitted outcome not surfaced");}
                catch(IOException ex){check(ex.Message.Contains("ACQUISITION_OUTCOME_UNCOMMITTED",StringComparison.Ordinal),"allocation failure plus SQLite outcome failure remains explicitly uncommitted");}
                check(journal.Read(id).Acquisition==null&&journal.ReadSnapshotIntent(id)?.State=="allocation-intent","failed outcome retains source-linked allocation for later recovery");
            }
            else
            {
                journal.AcquireAdmittedSnapshot(device,id,status);
                check(journal.Read(id).Acquisition?.Status is {Reason:"ACTOR_COPY_UNAVAILABLE_SNAPSHOT_ADMISSION_FAILED",NativeCode:"SqliteException"},"ordinary allocation boundary failure becomes a durable unavailable result: "+failure);
                check(failure=="initial-intent"?journal.ReadSnapshotIntent(id)==null:journal.ReadSnapshotIntent(id)?.State=="unavailable","allocation failure leaves exact expected durable intent state: "+failure);
            }
            check(port.Selects==0&&port.Drops==0,"allocation boundary failure authorizes neither SELECT nor DROP: "+failure);
        }
        directory=Path.Combine(root,"admitted-foreign-receipt");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var other=LinuxKernelDecoder.Decode(raw,sensor,observation.Attribution!.LinuxKernel!.CollectorInstance,900,observation.ObservedUtc);
            journal.CommitObservation(raw,observation,new());journal.CommitObservation(raw,other,new());
            using var first=journal.AdmitSnapshot(id,status);using var second=journal.AdmitSnapshot(other.EventId,status);
            Reject(()=>journal.CommitAdmittedFailure(second,first.RequireWriteReceipt(),"fixture"),"foreign immutable receipt cannot authorize another snapshot's failure");
            check(journal.Read(id).Acquisition==null&&journal.Read(other.EventId).Acquisition==null,"foreign receipt rejection preserves both unfinalized observations");
        }
        directory=Path.Combine(root,"admitted-acquisition-boundary-success");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            journal.CommitObservation(raw,observation,new());var port=new Port(status,bytes);using var device=new LinuxActorLeaseDevice(port);
            journal.AcquireAdmittedSnapshot(device,id,status);
            check(journal.Read(id).Acquisition?.Status.State=="captured"&&port.Selects==1&&port.Drops==0,"full admitted acquisition boundary commits capture without implicit release");
        }
        static void Sql(string directory,string sql)
        {
            using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"linux-forensic-intake","journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();
        }
    }
    internal sealed class Port(LinuxActorLeaseStatus status,byte[] bytes):ILinuxActorLeaseTransport
    {
        private int position;
        internal int Selects,Drops,StatusReads;
        internal bool ChangeBefore,ChangeAfter,ReadError;
        internal LinuxActorLeaseStatus? CurrentStatus;
        internal Queue<LinuxActorLeaseStatus>? Responses;
        public void Control(uint command,byte[] request)
        {
            if(command==LinuxActorLeaseDevice.StatusCommand)
            {
                StatusReads++;var current=Responses is {Count:>0}?Responses.Dequeue():CurrentStatus??status;
                var s=ChangeBefore||ChangeAfter&&StatusReads>1?current with{ProviderEpoch=current.ProviderEpoch+1}:current;
                ulong[] words=[s.Id,s.Cookie,s.StartedNs,s.FinishedNs,s.DeadlineNs,s.Size,s.Inode,s.Device,s.Bytes,s.ProcessId,s.ThreadId,s.ProcessStartNs,s.TaskStartNs,s.SelfExecId,s.AssociationGeneration,s.ProviderEpoch];
                for(int i=0;i<words.Length;i++)BinaryPrimitives.WriteUInt64LittleEndian(request.AsSpan(i*8),words[i]);
                int[] tail=[(int)s.State,s.Error,(int)s.WriteLease,(int)s.MetadataChanged,(int)s.AssociationState,s.AssociationError,(int)s.SchemaVersion,(int)s.StructSize];
                for(int i=0;i<tail.Length;i++)BinaryPrimitives.WriteInt32LittleEndian(request.AsSpan(128+i*4),tail[i]);
            }
            else if(command==LinuxActorLeaseDevice.SelectCommand){Selects++;position=0;}
            else if(command==LinuxActorLeaseDevice.DropCommand)Drops++;
            else throw new Exception("Unknown native test command");
        }
        public int Read(byte[] buffer,int count)
        {
            if(ReadError&&position>0)throw new IOException("owned read failure");
            var n=Math.Min(137,Math.Min(count,bytes.Length-position));bytes.AsSpan(position,n).CopyTo(buffer);position+=n;return n;
        }
        public void Dispose(){}
    }
}
