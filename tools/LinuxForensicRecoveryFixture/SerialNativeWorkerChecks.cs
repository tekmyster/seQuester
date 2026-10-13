using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;

static class SerialNativeWorkerChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,LinuxActorSnapshot snapshot)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh serial worker fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        var modes=new[]{"normal","stopped-before-run","stop-during-status","pending-at-stop","drop-error","status-mismatch","return-commit-failure","start-commit-failure","no-native-lease","drop-receipt-failure","return-postcommit-failure"};
        foreach(var mode in modes)
        {
            var input=raw;
            if(mode=="no-native-lease"){var node=JsonNode.Parse(raw)!;node["lease"]=0;node["reservation"]=0;input=JsonSerializer.SerializeToUtf8Bytes(node);}
            using var s=new NativePinChecks.Scope(Path.Combine(root,mode),sensor,input);var work=s.Issue();var claim=s.Claim(work);
            var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());
            if(mode=="pending-at-stop")port.CurrentStatus=snapshot.NativeStatus with{State=5,Error=-110,FinishedNs=0,WriteLease=1,Bytes=0};
            if(mode=="status-mismatch")port.ChangeBefore=true;
            using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
            var wrap=new Port(port){DropError=mode=="drop-error",Entered=mode is "stop-during-status" or "pending-at-stop"?entered:null,Release=mode is "stop-during-status" or "pending-at-stop"?release:null};
            using var device=new LinuxActorLeaseDevice(wrap);var worker=new LinuxSerialNativeWorker(s.Journal,s.Barrier,device,s.Id,mode=="return-postcommit-failure"?point=>throw new IOException("Owned failure after durable return commit"):null);
            if(mode=="stopped-before-run")s.Barrier.RequestStop("OWNED_STOP_BEFORE_RUN",DateTimeOffset.UtcNow);
            if(mode=="return-commit-failure")Sql(s.Root,"CREATE TRIGGER owned_worker_return_failure BEFORE UPDATE ON native_pins WHEN NEW.returned IS NOT NULL BEGIN SELECT RAISE(FAIL,'owned native return commit failure'); END;");
            if(mode=="start-commit-failure")Sql(s.Root,"CREATE TRIGGER owned_worker_start_failure BEFORE UPDATE ON native_pins WHEN NEW.state='NATIVE_STARTED' BEGIN SELECT RAISE(FAIL,'owned native start commit failure'); END;");
            if(mode=="drop-receipt-failure")Sql(s.Root,"CREATE TRIGGER owned_drop_receipt_failure BEFORE UPDATE ON work WHEN NEW.drop_state='returned' BEGIN SELECT RAISE(FAIL,'owned drop receipt failure'); END;");
            var running=worker.RunAsync(claim);LinuxSerialNativeWorker.ReturnReceipt? returned=null;
            if(mode is "stop-during-status" or "pending-at-stop")
            {
                try
                {
                    Check(entered.Wait(TimeSpan.FromSeconds(20)),"native status call is actually outstanding: "+mode);
                    try{_ =worker.RunAsync(claim);throw new Exception("Claim scheduled twice");}catch(InvalidOperationException){Check(true,"in-flight native claim cannot be scheduled twice: "+mode);}
                    var receipt=s.Bank.Commit(raw,s.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var indexed=s.Journal.IndexRawIngress(s.Id,s.Bank,receipt);
                    Check(indexed.Status=="DUPLICATE"&&s.Bank.Entries.Length==2,"raw/index progress independently while native cursor blocked: "+mode);
                    s.Barrier.RequestStop("OWNED_STOP_DURING_STATUS",DateTimeOffset.UtcNow);var closing=s.Barrier.BeginClose("OWNED_CLOSE",DateTimeOffset.UtcNow);
                    Check(!closing.IsCompleted&&!running.IsCompleted,"stop cannot manufacture native return or permit close: "+mode);
                    Check(!worker.FinishScheduling().IsCompleted,"managed drain waits for actual blocked controller call: "+mode);
                }
                finally{release.Set();}
            }
            if(mode is "return-commit-failure" or "return-postcommit-failure")
            {
                try{await running;throw new Exception("Failed return commit accepted");}catch(Exception ex)when(ex is SqliteException or IOException){Check(true,"actual return commit failure reaches source owner: "+mode);}
                var saved=worker.UncommittedReturns.Single();
                Check(!worker.FinishScheduling().IsCompleted,"uncommitted actual return prevents managed drain: "+mode);
                Check(s.Barrier.InFlight==1&&s.Journal.ReadNativePin(work.EventId)!.State==(mode=="return-commit-failure"?"NATIVE_STARTED":"NATIVE_RETURNED_RECEIPT_COMMITTED")&&s.Barrier.Current.State=="Faulted","unobserved actual return retains token and denies new work: "+mode);
                if(mode=="return-postcommit-failure")
                {
                    try{s.Journal.RecordNativePinReturn(claim,saved.ReturnedUtc.AddTicks(1),saved.Reason,saved.Method);throw new Exception("Changed native return accepted");}catch(InvalidDataException){Check(s.Barrier.InFlight==1,"ambiguous-commit reconciliation rejects regenerated return timestamp");}
                }
                var calls=(port.Selects,port.Drops,port.StatusReads);if(mode=="return-commit-failure")Sql(s.Root,"DROP TRIGGER owned_worker_return_failure;");await worker.RetryUncommittedReturnsAsync();
                Check(s.Journal.ReadNativePin(work.EventId)!.Return!.ActualReturnUtc==saved.ReturnedUtc&&worker.UncommittedReturns.Length==0&&(port.Selects,port.Drops,port.StatusReads)==calls,"return receipt recovery retains exact time without another native call");
                returned=saved;
            }
            else if(mode=="start-commit-failure")
            {try{await running;throw new Exception("Failed start accepted");}catch(SqliteException){Check(true,"native start transaction failure remains explicit");}}
            else returned=await running;
            s.Barrier.RequestStop("OWNED_WORKER_COMPLETE",DateTimeOffset.UtcNow);
            await worker.FinishScheduling();Check(worker.FinishScheduling().IsCompletedSuccessfully,"managed drain completes after all actual work and receipt commits: "+mode);
            var pin=s.Journal.ReadNativePin(work.EventId)!;var savedWork=s.Journal.Read(work.EventId);
            Check(!wrap.CalledFromThreadPool,"controller work stays off shared thread pool: "+mode);
            Check(s.Barrier.InFlight==0&&worker.UncommittedReturns.Length==0,"only committed actual return releases source work: "+mode);
            if(mode=="start-commit-failure")
                Check(returned==null&&pin.State=="PIN_INTERRUPTED_PRESELECT"&&pin.Authorization!=null&&pin.Start==null&&pin.Return==null&&port.StatusReads==0&&port.Selects==0&&port.Drops==0,"failed durable start retains authorization history and explicit prestart abort with no native call");
            else if(mode=="stopped-before-run")
                Check(returned==null&&pin.State=="PIN_INTERRUPTED_PRESELECT"&&pin.Return==null&&port.StatusReads==0&&port.Selects==0&&port.Drops==0,"stopped queued claim makes no native call or invented return");
            else if(mode=="no-native-lease")
                Check(returned!.Reason=="NATIVE_METHOD_NOT_CALLED_NO_LEASE"&&pin.Return!.Method is {ControllerMethodAttempted:false,LastStep:"NO_NATIVE_LEASE",DropMethodAttempted:false,DropMethodReturned:false}&&savedWork.DropState=="not-applicable"&&port.StatusReads==0&&port.Selects==0&&port.Drops==0,"missing lease records no controller method or fabricated DROP");
            else if(mode=="pending-at-stop")
                Check(returned!.Reason=="NATIVE_PENDING_AT_SOURCE_STOP"&&pin.State=="PIN_INTERRUPTED_UNKNOWN"&&savedWork.Acquisition==null&&savedWork.DropState=="not-attempted"&&port.Selects==0&&port.Drops==0,"expired/draining kernel work remains unknown and unreleased after userspace polling returns");
            else if(mode=="status-mismatch")
                Check(returned!.Error is InvalidDataException&&pin.State=="PIN_INTERRUPTED_UNKNOWN"&&savedWork.Acquisition==null&&port.Selects==0&&port.Drops==0,"foreign native tuple cannot hash, acquire or release a different actor");
            else
            {
                Check(savedWork.Acquisition?.SnapshotSha256==snapshot.Sha256.ToUpperInvariant()&&savedWork.Acquisition.Status.State=="captured"&&port.Selects==1,"actor private copy/hash committed once: "+mode);
                Check(mode is "drop-error" or "drop-receipt-failure"?returned!.Error is IOException or SqliteException&&pin.State=="PIN_INTERRUPTED_UNKNOWN"&&savedWork.DropState=="not-attempted":pin.State=="NATIVE_RETURNED_RECEIPT_COMMITTED"&&savedWork.DropState=="returned"&&port.Drops==1,"actual release outcome remains distinct from acquired actor bytes: "+mode);
                if(mode=="drop-receipt-failure")Check(port.Drops==1&&pin.Return!.Method is {DropMethodAttempted:true,DropMethodReturned:true,DropReceiptCommitObserved:false,ErrorDomain:"sqlite",LastStep:"DROP_RECEIPT_COMMIT"},"actual returned DROP and failed database receipt remain distinct durable facts");
                using var actor=s.Journal.RestoreActor(work.EventId);Check(actor.Image!=null&&actor.LinuxAcquisition!.SnapshotSha256==snapshot.Sha256.ToUpperInvariant(),"retained private actor still verifies after worker return: "+mode);
            }
            var spool=new EventSpool(Path.Combine(s.Root,"spool"),sensor);var failures=new List<string>();
            await using(var pipeline=new ForensicPipeline(sensor,s.Root,failures.Add))Check(pipeline.TrySubmitPrepared(s.Journal,work.EventId,spool),"terminal worker evidence enters common pipeline: "+mode);
            Check(failures.Count==0&&spool.Count==2&&spool.Peek().Events.All(e=>e.User==savedWork.Observation.User&&e.Process==savedWork.Observation.Process&&e.ProcessId==savedWork.Observation.ProcessId),"common original/completion retains exact observed actor: "+mode);
            if(returned!=null)Check(spool.Peek().Events.All(e=>e.Forensics!.ActorExecutable.LinuxNativeWork is {Version:2} n&&n.Method==returned.Method),"structured method/error facts survive journal and common spool unchanged: "+mode);
            File.WriteAllBytes(Path.Combine(s.Root,"events.json"),JsonSerializer.SerializeToUtf8Bytes(spool.Peek()));
        }
        var result=new{Passed=true,Checks=checks,Cases=modes.Length,Scope="Serial controller orchestration with injected native transport, real private files/journal/common spool; native controller integration remains pending"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static void Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();}
    private sealed class Port(SnapshotAdmissionChecks.Port inner):ILinuxActorLeaseTransport
    {
        internal ManualResetEventSlim? Entered,Release;
        internal bool DropError;
        internal bool CalledFromThreadPool;
        private bool paused;
        public void Control(uint command,byte[] request)
        {
            CalledFromThreadPool|=Thread.CurrentThread.IsThreadPoolThread;
            if(command==LinuxActorLeaseDevice.StatusCommand&&!paused&&Entered!=null)
            {paused=true;Entered.Set();if(!Release!.Wait(TimeSpan.FromSeconds(45)))throw new TimeoutException("Owned status pause not released");}
            if(command==LinuxActorLeaseDevice.DropCommand&&DropError)throw new IOException("Owned native drop error");
            inner.Control(command,request);
        }
        public int Read(byte[] destination,int count){CalledFromThreadPool|=Thread.CurrentThread.IsThreadPoolThread;return inner.Read(destination,count);}
        public void Dispose()=>inner.Dispose();
    }
}
