using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;

static class PreNativeFailureChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,LinuxActorSnapshot snapshot)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh isolated pre-native failure root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        var modes=new[]{"start-postcommit","start-unobserved-commit","abort-commit-failure","abort-postcommit","start-and-abort-failure","start-return-receipt-failure"};
        foreach(var mode in modes)
        {
            using var s=new NativePinChecks.Scope(Path.Combine(root,mode),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            var port=new SnapshotAdmissionChecks.Port(snapshot.NativeStatus,snapshot.Bytes.ToArray());using var device=new LinuxActorLeaseDevice(port);
            var startCut=mode=="start-unobserved-commit"?"native-start-commit-unobserved":mode is "start-postcommit" or "start-return-receipt-failure"?"native-start-committed":null;
            var worker=new LinuxSerialNativeWorker(s.Journal,s.Barrier,device,s.Id,
                startupCheckpoint:point=>{if(point==startCut)throw new IOException("Owned unobserved committed start");},
                abortCheckpoint:point=>{if(mode=="abort-postcommit"&&point=="native-abort-committed")throw new IOException("Owned unobserved committed abort");});
            if(mode.StartsWith("abort-",StringComparison.Ordinal))s.Barrier.RequestStop("OWNED_PRESTART_STOP",DateTimeOffset.UtcNow);
            if(mode is "abort-commit-failure" or "start-and-abort-failure")Sql(s.Root,"CREATE TRIGGER owned_abort_failure BEFORE UPDATE ON native_pins WHEN NEW.state='PIN_INTERRUPTED_PRESELECT' BEGIN SELECT RAISE(FAIL,'owned abort receipt failure'); END;");
            if(mode=="start-and-abort-failure")Sql(s.Root,"CREATE TRIGGER owned_start_failure BEFORE UPDATE ON native_pins WHEN NEW.state='NATIVE_STARTED' BEGIN SELECT RAISE(FAIL,'owned durable start failure'); END;");
            if(mode=="start-return-receipt-failure")Sql(s.Root,"CREATE TRIGGER owned_return_failure BEFORE UPDATE ON native_pins WHEN NEW.returned IS NOT NULL BEGIN SELECT RAISE(FAIL,'owned failed-start return receipt failure'); END;");
            try{await worker.RunAsync(claim);throw new Exception("Injected startup failure ignored");}catch(Exception ex)when(ex is IOException or SqliteException){Check(true,"failed start/abort reaches owner: "+mode);}
            Check(port.StatusReads==0&&port.Selects==0&&port.Drops==0,"failure before controller path makes zero native calls: "+mode);
            var pending=worker.PendingPreNativeFailures;
            var needsRetry=mode is "abort-commit-failure" or "start-and-abort-failure" or "start-return-receipt-failure";
            Check(pending.Length==(needsRetry?1:0),"exact failed receipt ownership retained: "+mode);
            DateTimeOffset? originalReturn=null;
            if(needsRetry)
            {
                originalReturn=pending.Single().ReturnedUtc;
                Check(!worker.FinishScheduling().IsCompleted&&s.Barrier.InFlight==1,"receipt-only failure cannot masquerade as drained native work: "+mode);
                Sql(s.Root,"DROP TRIGGER IF EXISTS owned_abort_failure; DROP TRIGGER IF EXISTS owned_start_failure; DROP TRIGGER IF EXISTS owned_return_failure;");
                await worker.RetryUncommittedReturnsAsync();
            }
            await worker.FinishScheduling();var pin=s.Journal.ReadNativePin(work.EventId)!;
            Check(s.Barrier.InFlight==0&&worker.PendingPreNativeFailures.Length==0&&worker.UncommittedReturns.Length==0,"actual receipt resolution releases one retained claim: "+mode);
            Check(port.StatusReads==0&&port.Selects==0&&port.Drops==0,"receipt recovery never invokes native methods: "+mode);
            if(startCut!=null)
            {
                Check(pin.State=="PIN_INTERRUPTED_UNKNOWN"&&pin.Start!=null&&pin.Return?.Method is {ControllerMethodAttempted:false,LastStep:"WORK_CONTEXT",ErrorDomain:"dotnet"},"committed start marker distinguished from uncalled device method: "+mode);
                if(originalReturn!=null)Check(pin.Return!.ActualReturnUtc==originalReturn,"receipt retry preserves original failed orchestration timestamp");
            }
            else Check(pin.State=="PIN_INTERRUPTED_PRESELECT"&&pin.Start==null&&pin.Return==null,"unstarted abort never invents native start or return: "+mode);
            var spool=new EventSpool(Path.Combine(s.Root,"spool"),sensor);var errors=new List<string>();
            await using(var pipeline=new ForensicPipeline(sensor,s.Root,errors.Add))Check(pipeline.TrySubmitPrepared(s.Journal,work.EventId,spool),"resolved failure enters existing delivery pipeline: "+mode);
            var observed=s.Journal.Read(work.EventId).Observation;
            Check(errors.Count==0&&spool.Count==2&&spool.Peek().Events.All(e=>e.ProcessId==observed.ProcessId&&e.Process==observed.Process&&e.User==observed.User&&e.Forensics!.ActorExecutable.Sha256==null),"original/completion retain actor user/process/PID without inventing a captured executable: "+mode);
            File.WriteAllBytes(Path.Combine(s.Root,"events.json"),JsonSerializer.SerializeToUtf8Bytes(spool.Peek()));
        }
        var result=new{Passed=true,Checks=checks,Cases=modes.Length,Schema=12,Scope="Uncalled native paths, ambiguous database commits and receipt-only drain using injected transport; no native controller execution"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static void Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();}
}
