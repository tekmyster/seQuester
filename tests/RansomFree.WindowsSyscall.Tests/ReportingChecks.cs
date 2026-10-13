using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

internal static class ReportingChecks
{
    internal static async Task<int> Run(byte[] raw)
    {
        var count=0;void Check(bool value,string message){if(!value)throw new Exception(message);count++;}
        void Reject(Action action,string message){try{action();}catch(Exception ex)when(ex is InvalidDataException or ArgumentException or IOException){count++;return;}throw new Exception(message);}
        using(var entered=new ManualResetEventSlim())
        using(var release=new ManualResetEventSlim()){
            var sharedWorker=false;var sameThread=false;
            var intake=WindowsSyscallSource.StartReceiver(()=>{
                var first=Environment.CurrentManagedThreadId;sharedWorker=Thread.CurrentThread.IsThreadPoolThread;
                entered.Set();release.Wait();sameThread=first==Environment.CurrentManagedThreadId;
            });
            try{Check(entered.Wait(TimeSpan.FromSeconds(5))&&!sharedWorker,"native intake starts independently of the shared worker pool");}
            finally{release.Set();await intake;}
            Check(sameThread,"native intake retains its dedicated thread across a synchronous poll wait");
        }
        // Target replies are synthetic transport cases. Token payloads below are
        // the independently captured native records, not fabricated test tokens.
        var sensor=Guid.NewGuid().ToString("N");var instance=Guid.NewGuid();var source=new byte[56];
        BinaryPrimitives.WriteUInt32LittleEndian(source,1);BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(4),56);instance.TryWriteBytes(source.AsSpan(8,16));
        var identity=WindowsSyscallSource.SourceInfo(source);Check(identity.Instance==instance&&identity.Lost==0,"native UUID parsing");
        Check(WindowsSyscallSource.SnapshotMayArrive("syscall-exact-process-snapshot-unavailable; recovery-records-rejected"),"partial recovery does not eliminate bounded first-use acquisition retry");
        Check(!WindowsSyscallSource.SnapshotMayArrive("syscall-process-snapshot-ambiguous")&&!WindowsSyscallSource.SnapshotMayArrive(null),"ambiguous identities cannot become retryable acquisitions");
        var drives=new Dictionary<string,string>{{"C:",@"\Device\HarddiskVolume3"}};
        Check(WindowsNativePaths.Display(@"\??\C:\Windows\actor.exe",drives,false)==@"C:\Windows\actor.exe","native DOS image path normalized for process reporting");
        Check(WindowsNativePaths.Display(@"\Device\HarddiskVolume3\case.txt",drives,false)==@"C:\case.txt","retained object name maps to known drive for display");
        Check(WindowsNativePaths.Display(@"\Device\HarddiskVolume30\case.txt",drives,false)==@"\Device\HarddiskVolume30\case.txt","drive prefix cannot match a different native volume");
        Check(WindowsNativePaths.Display(@"\??\C:relative.exe",drives,false)==@"\??\C:relative.exe","relative native image path is not promoted to an absolute executable");
        var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Codex","syscall-reporting-tests-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);using var journal=new WindowsSyscallJournal(directory,sensor);
        {
            var lifetimeJournal=new WindowsSyscallJournal(Path.Combine(directory,"lifetime-drain"),sensor);
            var cancellation=new CancellationTokenSource();
            var intake=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var reporting=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var drain=WindowsSyscallSource.DrainLifetime(cancellation,intake.Task,reporting.Task,lifetimeJournal);
            var first=drain.DisposeAsync();
            Check(cancellation.IsCancellationRequested&&!first.IsCompleted,"source shutdown cancels intake before waiting for both producers");
            var concurrent=Enumerable.Range(0,32).Select(_=>drain.DisposeAsync()).ToArray();
            Check(concurrent.All(task=>ReferenceEquals(first,task)),"concurrent source shutdown callers await the same resource drain");
            Check(lifetimeJournal.Pending().Length==0,"journal remains usable while producers are still draining");
            intake.SetResult();
            Check(!first.IsCompleted,"intake exit alone cannot dispose the reporting journal");
            reporting.SetResult();await Task.WhenAll(concurrent);
            Check(ReferenceEquals(first,drain.DisposeAsync())&&first.IsCompletedSuccessfully,"repeated completed shutdown does not cancel a disposed token source");
            var closed=false;try{lifetimeJournal.Pending();}catch(ObjectDisposedException){closed=true;}
            Check(closed,"journal closes only after intake and reporting finish");
            using var reopened=new WindowsSyscallJournal(Path.Combine(directory,"lifetime-drain"),sensor);
            Check(reopened.Pending().Length==0,"fresh owner can reopen journal after shared shutdown");
            var failedJournal=new WindowsSyscallJournal(Path.Combine(directory,"failed-drain"),sensor);
            var failure=new IOException("controlled reporting drain failure");
            var failed=WindowsSyscallSource.DrainLifetime(new(),Task.CompletedTask,Task.FromException(failure),failedJournal);
            foreach(var attempt in Enumerable.Range(0,2)){
                Exception? observed=null;try{await failed.DisposeAsync();}catch(Exception ex){observed=ex;}
                Check(ReferenceEquals(observed,failure),"shutdown preserves original producer failure for every caller");
            }
            closed=false;try{failedJournal.Pending();}catch(ObjectDisposedException){closed=true;}
            Check(closed,"producer failure still releases its journal after drain");
        }
        await using var pipeline=new ForensicPipeline(sensor,directory,_=>{});using var spool=new EventSpool(directory,sensor);
        for(var i=0;i<9;i++){
            var record=raw.AsSpan(i*696,408).ToArray();var native=WindowsSyscallDecoder.Decode(record);var key=WindowsSyscallSource.Key(instance,native.Sequence);
            Check(new Guid(key.AsSpan(8,16))==instance&&BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(24))==(ulong)native.Sequence,"ACK exact lifetime and sequence");
            var reply=new byte[3120];BinaryPrimitives.WriteUInt32LittleEndian(reply,1);BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4),3120);instance.TryWriteBytes(reply.AsSpan(8,16));
            BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(24),(ulong)native.Sequence);BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(32),(ulong)DateTimeOffset.UtcNow.ToFileTime());
            var name=Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume9\test-honeypot.txt");BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(44),(uint)name.Length);name.CopyTo(reply,48);
            var observation=WindowsSyscallSource.Observation(record,identity,reply);var e=journal.Put(record,observation);
            Check(observation.TargetReplySha256==Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(reply)),"target reply integrity retained");
            var malformed=reply.ToArray();malformed[48]=0;malformed[49]=0xD8;malformed[50]=0x41;malformed[51]=0;
            var unprintable=WindowsSyscallSource.Observation(record,identity,malformed);
            Check(unprintable.IsValid()&&unprintable.TargetPath==null&&unprintable.UnavailableTargetNameBase64==Convert.ToBase64String(malformed,48,name.Length),"invalid UTF16 retained as unavailable with exact name bytes");
            malformed=reply.ToArray();malformed[48]=0;malformed[49]=0;
            unprintable=WindowsSyscallSource.Observation(record,identity,malformed);
            Check(unprintable.IsValid()&&unprintable.TargetStatus.Reason=="retained-target-name-not-displayable","control characters cannot block observation publication");
            Check(!(unprintable with{UnavailableTargetNameBase64="bad base64"}).IsValid(),"unavailable name corruption rejected");
            Check(!(unprintable with{UnavailableTargetNameBase64=null}).IsValid(),"undisplayable name cannot lose its raw evidence");
            var invalidNameDirectory=Path.Combine(directory,"invalid-name-"+i);
            using var invalidNameWriter=new WindowsSyscallJournal(invalidNameDirectory,sensor);
            var invalidNameEvent=invalidNameWriter.Put(record,unprintable);
            using var invalidNameReader=new WindowsSyscallJournal(invalidNameDirectory,sensor);
            Check(invalidNameReader.Pending().Single().Attribution!.WindowsSyscall!.UnavailableTargetNameBase64==unprintable.UnavailableTargetNameBase64&&invalidNameEvent.ProcessId==native.ProcessId,"restart retains raw invalid name and actual native actor identity");
            var oldWire=JsonSerializer.Serialize(observation with{TargetReplySha256=null});
            Check(!oldWire.Contains("TargetReplySha256")&&!oldWire.Contains("UnavailableTargetNameBase64"),"historical observation serialization remains unchanged when additive fields absent");
            Check(!(observation with{UnavailableTargetNameBase64=Convert.ToBase64String(name)}).IsValid(),"captured path cannot simultaneously claim undecodable bytes");
            Check(!(observation.Native with{ProcessCreatedFileTime=long.MaxValue}).IsValid(),"unrepresentable process birth rejected before enrichment");
            Check(WindowsSyscallObservation.Matches(e)&&e.User==native.ThreadEffective.Sid&&e.ProcessId==native.ProcessId,"sensor fields match actual native record");
            Check(EventActivity.From(e).Outcome==(i<8?"failed":"success"),"failed operation remains failed in reporting");
            var replay=journal.Put(record,observation with{TargetQueriedUtc=observation.TargetQueriedUtc.AddMinutes(1)});
            Check(JsonSerializer.Serialize(replay)==JsonSerializer.Serialize(e),"retry retains original metadata and event ID");
            using var restarted=new WindowsSyscallJournal(directory,sensor);Check(restarted.Pending().Any(x=>x.EventId==e.EventId),"restart recovers committed raw record");
            using var actor=ActorLease.Capture(e with{Process=@"C:\Windows\System32\notepad.exe"},sensor);
            Check(actor.Image==null&&actor.Binding.State=="unavailable","no later PID or path open for historical syscall actor");
            Check(actor.Process.Owner.Sid=="S-1-5-18"&&actor.Process.EffectiveThreadContext?.Sid==native.ThreadEffective.Sid&&actor.Process.Impersonating==(i<8),"distinct forensic owner/effective principal");
            using var unavailable=ActorLease.Capture(e,sensor);var publication=pipeline.CollectForPublication(e,unavailable,new());
            Check(publication.Original.Forensics!.ActorExecutable.Sha256==null&&publication.Original.Forensics.ActorExecutable.HashStatus.State=="unavailable","missing actor hash remains explicit");
            Check(publication.Original.Forensics!.Preservation.Status.State is "failed" or "unavailable","missing executable preservation cannot succeed");
            journal.Prepare(publication);using var preparedRestart=new WindowsSyscallJournal(directory,sensor);var recovered=preparedRestart.Prepared(e.EventId)!;
            var responseId=Guid.NewGuid().ToString("N");var response=e with{EventId=responseId,ObservedUtc=DateTimeOffset.UtcNow,Source="Agent response",Operation="Automatic response denied: fixture",Forensics=pipeline.LinkResponse(publication.Original.Forensics!,responseId,DateTimeOffset.UtcNow)};
            Check(WindowsSyscallObservation.Matches(response)&&response.Forensics!.IsValid(),"linked response retains historical syscall context without claiming new access");
            Check(JsonSerializer.Serialize(recovered)==JsonSerializer.Serialize(publication),"original and completion recovered unchanged");
            Reject(()=>journal.Prepare(publication with{Completion=publication.Completion with{EventId=Guid.NewGuid().ToString("N")}}),"completion ID changed during retry");
            pipeline.RegisterPublication(recovered);spool.Enqueue(recovered.Original);spool.Enqueue(recovered.Completion);journal.Complete(e.EventId);
            Check(journal.Pending().All(x=>x.EventId!=e.EventId),"retire after both durable spool events");
            journal.Put(record,observation);Check(journal.Pending().All(x=>x.EventId!=e.EventId),"native ACK retry cannot duplicate enrichment");
            var altered=reply.ToArray();Guid.NewGuid().TryWriteBytes(altered.AsSpan(8,16));Reject(()=>WindowsSyscallSource.Observation(record,identity,altered),"foreign target lifetime accepted");
            altered=reply.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(altered.AsSpan(44),3);Reject(()=>WindowsSyscallSource.Observation(record,identity,altered),"odd UTF16 target length accepted");
            altered=reply.ToArray();BinaryPrimitives.WriteUInt32LittleEndian(altered.AsSpan(40),0xC0000022);BinaryPrimitives.WriteUInt32LittleEndian(altered.AsSpan(44),0);
            var missing=WindowsSyscallSource.Observation(record,identity,altered);Check(missing.TargetPath==null&&missing.TargetStatus.NativeCode=="0xC0000022","target query failure retains OS status and null path");
            Reject(()=>journal.Put(record,observation with{Native=observation.Native with{ProcessCreatedFileTime=native.ProcessCreatedFileTime+1}}),"raw/JSON process birth disagreement accepted");
            Check(!WindowsSyscallObservation.Matches(e with{ProcessId=e.ProcessId+1}),"wrong reported PID rejected");
            Check(!WindowsSyscallObservation.Matches(e with{Attribution=e.Attribution! with{UserSid="S-1-5-20"}}),"wrong reported user rejected");
        }
        Check(spool.Count==18,"nine native records and nine linked completions durably queued");
        if(OperatingSystem.IsWindows()||OperatingSystem.IsLinux()){
            var queueDirectory=Path.Combine(directory,"queue-lifetime");
            var queueDatabase=Path.Combine(queueDirectory,"events-"+sensor+".db");
            var firstEvent=spool.Peek().Events[0];
            using(var retainedQueue=new EventSpool(queueDirectory,sensor,retainJournalLifetime:true)){
                retainedQueue.Enqueue(firstEvent);
                var committedProgress=retainedQueue.CaptureWriteDiagnostics();
                Check(committedProgress.Stage=="committed"&&committedProgress.EventId==firstEvent.EventId&&committedProgress.ElapsedMilliseconds>=0,"durable-writer diagnostics link only the committed event");
                Check(File.Exists(queueDatabase+"-wal"),"enrolled event spool retains WAL while its owner is alive");
                using(var independent=new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder{DataSource=queueDatabase,Pooling=false}.ToString())){
                    independent.Open();using var query=independent.CreateCommand();query.CommandText="SELECT payload FROM queue";
                    Check(query.ExecuteScalar() is byte[] payload&&payload.AsSpan().SequenceEqual(EventSpool.Encode(firstEvent)),"fresh connection sees exact committed event bytes before central delivery");
                }
                Check(Enumerable.Range(0,20).All(_=>retainedQueue.Peek().Events.Single().EventId==firstEvent.EventId),"repeated retained spool reads preserve event identity");
                Check(File.Exists(queueDatabase+"-wal"),"queue polling does not close the final WAL owner");
                retainedQueue.Enqueue(firstEvent);
                Check(retainedQueue.Count==1,"retained spool still deduplicates immutable event IDs");
                Check(retainedQueue.CaptureWriteDiagnostics().Stage=="deduplicated","duplicate diagnostics do not claim another durable write");
                var conflicting=firstEvent with{Operation=firstEvent.Operation+" altered"};
                var conflictRejected=false;try{retainedQueue.Enqueue(conflicting);}catch(InvalidOperationException){conflictRejected=true;}
                Check(conflictRejected,"diagnostics cannot permit conflicting immutable event bytes");
                Check(retainedQueue.CaptureWriteDiagnostics().Stage=="failed"&&EventSpool.Encode(retainedQueue.Peek().Events.Single()).AsSpan().SequenceEqual(EventSpool.Encode(firstEvent)),"failed-write diagnostic preserves original queued evidence");
                retainedQueue.Dispose();
                var closed=false;try{retainedQueue.Peek();}catch(ObjectDisposedException){closed=true;}
                Check(closed,"disposed enrolled spool cannot reopen itself");
            }
            using var restartedQueue=new EventSpool(queueDirectory,sensor,retainJournalLifetime:true);
            Check(restartedQueue.Peek().Events.Single().EventId==firstEvent.EventId,"exact pending event survives owner shutdown and fresh restart");
        }
        var lifetimeDirectory=Path.Combine(directory,"wal-lifetime");
        using(var retained=new WindowsSyscallJournal(lifetimeDirectory,sensor)){
            var record=raw.AsSpan(0,408).ToArray();var n=WindowsSyscallDecoder.Decode(record);
            var reply=new byte[3120];BinaryPrimitives.WriteUInt32LittleEndian(reply,1);BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4),3120);
            instance.TryWriteBytes(reply.AsSpan(8,16));BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(24),(ulong)n.Sequence);
            BinaryPrimitives.WriteUInt64LittleEndian(reply.AsSpan(32),(ulong)DateTimeOffset.UtcNow.ToFileTime());
            var name=Encoding.Unicode.GetBytes(@"\Device\HarddiskVolume9\wal-durability.txt");BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(44),(uint)name.Length);name.CopyTo(reply,48);
            var observation=WindowsSyscallSource.Observation(record,identity,reply);var saved=retained.Put(record,observation);
            var database=Path.Combine(lifetimeDirectory,"syscall-intake","syscall-intake-"+sensor+".db");
            Check(File.Exists(database+"-wal"),"committed WAL remains owned during intake lifetime");
            using(var independent=new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder{DataSource=database,Pooling=false}.ToString())){
                independent.Open();using var query=independent.CreateCommand();query.CommandText="SELECT raw FROM intake";
                Check(query.ExecuteScalar() is byte[] committed&&committed.AsSpan().SequenceEqual(record),"fresh independent connection sees committed native bytes before acknowledgement");
            }
            Check(Enumerable.Range(0,20).All(_=>retained.Pending().Single().EventId==saved.EventId),"polling never changes committed event identity");
            Check(File.Exists(database+"-wal"),"polling reads do not close the last WAL owner");
            retained.Dispose();
            var rejected=false;try{retained.Pending();}catch(ObjectDisposedException){rejected=true;}
            Check(rejected,"retired journal cannot reopen after its source shuts down");
            using var reopened=new WindowsSyscallJournal(lifetimeDirectory,sensor);
            Check(reopened.Pending().Single().EventId==saved.EventId,"pending native evidence survives owner shutdown and fresh restart");
        }
        Console.WriteLine(JsonSerializer.Serialize(new{ReportingChecks=count,JournalRestartVerified=true,NativeRecords=9,TargetReplies="synthetic transport fixtures",LiveDriverIntakeQualified=false,Artifacts=directory}));return count;
    }
}
