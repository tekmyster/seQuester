using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

static class NativePinChecks
{
    internal static void Child(string root,string sensor,byte[] raw,string cut)
    {
        using var s=new Scope(root,sensor,raw);var work=s.Issue();
        File.WriteAllText(Path.Combine(root,"child-context.json"),JsonSerializer.Serialize(new{Session=s.Id,Event=work.EventId}));
        void Checkpoint(string point){if(point==cut)Environment.Exit(73);}
        var claim=s.Claim(work,Checkpoint);s.Journal.AuthorizeNativePin(claim,Checkpoint);s.Journal.MarkNativePinStarting(claim,Checkpoint);
        throw new Exception("Requested native-pin cut not reached");
    }
    internal static async Task Run(string root,string sensor,byte[] raw,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh native pin fixture root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action run,string label){try{run();}catch(Exception ex)when(ex is InvalidOperationException or InvalidDataException or SqliteException){Check(true,label);return;}throw new Exception("Unexpected native pin acceptance: "+label);}
        {
            using var s=new Scope(Path.Combine(root,"before-pin-fault"),sensor,raw);var work=s.Issue();s.Barrier.Fault("OWNED_FAULT",DateTimeOffset.UtcNow);
            Reject(()=>s.Claim(work),"fault before durable pin admits no work");
            Check(!s.Journal.HasWork(work.EventId)&&s.Journal.ReadNativePin(work.EventId)==null,"no partial work/pin after precommit interruption");s.Barrier.Return(work);
        }
        {
            using var s=new Scope(Path.Combine(root,"pin-failure"),sensor,raw);var work=s.Issue();
            Sql(s.Root,"CREATE TRIGGER owned_pin_fail BEFORE INSERT ON native_pins BEGIN SELECT RAISE(FAIL,'owned pin insertion failure'); END;");
            Reject(()=>s.Claim(work),"pin transaction failure remains visible");
            Check(!s.Journal.HasWork(work.EventId)&&s.Journal.ReadNativePin(work.EventId)==null,"work/completion identity and pin roll back atomically");
            Check(s.Bank.ReadRaw(s.Entry).SequenceEqual(raw),"failed pin leaves original raw evidence intact");s.Barrier.Return(work);
        }
        foreach(var kind in new[]{"after-pin","authorization-failure","fault-during-authorization"})
        {
            using var s=new Scope(Path.Combine(root,kind),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            Check(s.Journal.ReadNativePin(work.EventId)?.Intent.CompletionId==s.Journal.Read(work.EventId).CompletionId,"pin retains exact completion linkage: "+kind);
            if(kind=="authorization-failure")
            {
                Sql(s.Root,"CREATE TRIGGER owned_auth_fail BEFORE UPDATE ON native_pins WHEN NEW.state='SELECTION_AUTHORIZED' BEGIN SELECT RAISE(FAIL,'owned authorization failure'); END;");
                Reject(()=>s.Journal.AuthorizeNativePin(claim),"failed durable authorization cannot start native work");Sql(s.Root,"DROP TRIGGER owned_auth_fail;");
            }
            else if(kind=="after-pin")
            {s.Barrier.Fault("OWNED_AFTER_PIN",DateTimeOffset.UtcNow);Check(!s.Journal.AuthorizeNativePin(claim),"fault after pin but before authorization refuses device work");}
            else
            {Check(!s.Journal.AuthorizeNativePin(claim,point=>{if(point=="native-authorization-committed")s.Barrier.Fault("OWNED_DURING_COMMIT",DateTimeOffset.UtcNow);}),"visible fault after DB commit wins final authorization latch");}
            Reject(()=>s.Journal.MarkNativePinStarting(claim),"unconfirmed work cannot record a native start: "+kind);
            s.Journal.FinalizeSourceWorkUnavailable(s.Id,"OWNED_BROAD_FINALIZER");
            Check(s.Journal.Read(work.EventId).Acquisition==null,"broad finalizer cannot overwrite active pin: "+kind);
            s.Journal.AbortNativePinBeforeStart(claim);
            Check(s.Journal.ReadNativePin(work.EventId)?.State=="PIN_INTERRUPTED_PRESELECT"&&s.Barrier.InFlight==0&&s.Journal.Read(work.EventId).Acquisition?.Status.Reason=="ACTOR_ACQUISITION_UNAVAILABLE_INTERRUPTED_BEFORE_NATIVE_START","explicit prestart abort returns token without native-return fabrication: "+kind);
        }
        {
            using var s=new Scope(Path.Combine(root,"authorized-drain"),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            Check(s.Journal.AuthorizeNativePin(claim),"live pin obtains durable authorization and final confirmation");
            Reject(s.Journal.Dispose,"journal cannot release its owner lock while native work remains active");
            Check(s.Journal.ReadNativePin(work.EventId)?.State=="SELECTION_AUTHORIZED","refused disposal preserves a usable journal for the actual return");
            s.Barrier.Fault("OWNED_AFTER_AUTHORIZATION",DateTimeOffset.UtcNow);
            s.Journal.MarkNativePinStarting(claim);var pin=s.Journal.ReadNativePin(work.EventId)!;
            Check(pin.State=="NATIVE_STARTED"&&pin.Start?.Selection.Ordering=="AUTHORIZED_PREFAULT_SELECT_STARTING_AFTER_FAULT","authorized drain keeps exact fault/start ordering");
            Reject(()=>s.Journal.MarkNativePinStarting(claim),"native start is one-use");
            Reject(()=>s.Journal.AbortNativePinBeforeStart(claim),"started work cannot be mislabeled unstarted");
            var closing=s.Barrier.BeginClose("OWNED_CLOSE",DateTimeOffset.UtcNow);
            s.Journal.FinalizeSourceWorkUnavailable(s.Id,"OWNED_DURING_DRAIN");
            Check(!closing.IsCompleted&&s.Journal.Read(work.EventId).Acquisition==null,"close and finalizer wait for real outstanding work");
            s.Journal.CommitUnavailable(work.EventId,"OWNED_FIXTURE_TERMINAL");s.Journal.RecordDrop(work.EventId,"returned");
            var returned=DateTimeOffset.UtcNow;
            Sql(s.Root,"CREATE TRIGGER owned_return_fail BEFORE UPDATE ON native_pins BEGIN SELECT RAISE(FAIL,'owned return failure'); END;");
            Reject(()=>s.Journal.RecordNativePinReturn(claim,returned,"OWNED_RETURN"),"return receipt persistence failure cannot pretend drain completed");
            Check(!closing.IsCompleted&&s.Barrier.InFlight==1,"uncommitted return retains coordination ownership");
            Sql(s.Root,"DROP TRIGGER owned_return_fail;");s.Journal.RecordNativePinReturn(claim,returned,"OWNED_RETURN");await closing;
            Check(s.Journal.ReadNativePin(work.EventId)?.Return?.ActualReturnUtc==returned&&s.Journal.ReadNativePin(work.EventId)?.State=="NATIVE_RETURNED_UNAVAILABLE_COMMITTED"&&s.Barrier.InFlight==0,"receipt retry preserves actual-return timestamp and frees one token");
            Reject(()=>s.Journal.RecordNativePinReturn(claim,returned,"OWNED_SECOND_RETURN"),"returned claim cannot finish twice");
        }
        {
            using var s=new Scope(Path.Combine(root,"unknown-return"),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            s.Journal.AuthorizeNativePin(claim);s.Journal.MarkNativePinStarting(claim);s.Journal.RecordNativePinReturn(claim,DateTimeOffset.UtcNow,"OWNED_NATIVE_ERROR");
            s.Journal.FinalizeSourceWorkUnavailable(s.Id,"OWNED_LATER_FINALIZER");
            Check(s.Journal.ReadNativePin(work.EventId)?.State=="PIN_INTERRUPTED_UNKNOWN"&&s.Journal.Read(work.EventId).Acquisition==null&&s.Barrier.InFlight==0,"actual method return without committed acquisition retains unknown outcome");
        }
        {
            using var s=new Scope(Path.Combine(root,"duplicate-claim"),sensor,raw);var work=s.Issue();var claim=s.Claim(work);
            Reject(()=>s.Claim(work),"same work token cannot create another durable pin");
            s.Journal.AbortNativePinBeforeStart(claim);var later=s.Issue();Reject(()=>s.Claim(later),"returned or historical pin cannot be reissued using a new token");s.Barrier.Return(later);
            Check((long)Sql(s.Root,"SELECT count(*) FROM native_pins;")! ==1,"duplicates retain exactly one immutable pin");
        }
        async Task ExitChild(string mode,string directory,string cut)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(NativePinChecks).Assembly.Location);
            foreach(var arg in new[]{mode,seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual child exit: "+cut+" "+await stdout+await stderr);
        }
        foreach(var cut in new[]{"native-pin-before-commit","native-pin-committed","native-authorization-committed","native-start-committed"})
        {
            var directory=Path.Combine(root,cut);await ExitChild("native-pin-child",directory,cut);
            var context=JsonNode.Parse(File.ReadAllBytes(Path.Combine(directory,"child-context.json")))!;var id=context["Event"]!.GetValue<string>();
            using var journal=new LinuxForensicJournal(directory,sensor);var pin=journal.ReadNativePin(id);
            if(cut=="native-pin-before-commit")Check(pin==null&&!journal.HasWork(id),"interrupted pin transaction rolls back work and pin");
            else
            {
                Check(pin?.State=="PIN_INTERRUPTED_UNKNOWN"&&pin.Return==null,"restart marks unresolved durable pin unknown without actual-return timestamp: "+cut);
                Check(journal.Read(id).Acquisition==null,"restart finalizer preserves unknown acquisition: "+cut);
            }
            Check(journal.ReadSource(context["Session"]!.GetValue<string>()).State=="CONTINUITY_FAULTED","restart cannot revive a live source claim: "+cut);
            Check(Sql(directory,"PRAGMA foreign_key_check;")==null,"native pin/raw/work foreign keys remain consistent: "+cut);
        }
        foreach(var cut in new[]{"native-pin-migration-before-commit","native-pin-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var initial=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; PRAGMA user_version=9;");await ExitChild("migration-child",directory,cut);
            Check((long)Sql(directory,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?9:10),"native pin migration is atomic");
            using var migrated=new LinuxForensicJournal(directory,sensor);Check((long)Sql(directory,"SELECT count(*) FROM native_pins;")! ==0,"migration fabricates no native work pin");
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Durable ordering/finalizer exclusion with actual child exits; source/device and native results are fixture metadata only; no native I/O or runtime activation"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    internal sealed class Scope:IDisposable
    {
        internal string Root {get;}
        internal LinuxForensicJournal Journal {get;}
        internal LinuxRawIngressReserve Bank {get;}
        internal LinuxSourceWorkBarrier Barrier {get;}=new();
        internal LinuxRawIngressReserve.Entry Entry {get;}
        internal string Id {get;}
        private readonly string eventId;
        internal Scope(string root,string sensor,byte[] raw,bool acknowledge=true,bool writeReceipt=true,bool prepareActivation=true)
        {
            Root=root;var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>();
            Journal=new(root,sensor);Bank=new(Path.Combine(root,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch.ToString(System.Globalization.CultureInfo.InvariantCulture),5,true);
            Id=Journal.PrepareControlledSource(Bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
            Journal.RecordSourceOwnerOpenAttempt(Id,DateTimeOffset.UtcNow);Journal.RecordOwnerMethodReturn(Id,ActivationFixture.OwnerReturn(Id));
            var ready=JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=epoch,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=0,activationFrame="one-command-then-eof"});
            Journal.CommitSourceControlLink(Id,ready,DateTimeOffset.UtcNow);
            if(prepareActivation){ActivationFixture.BeforeWrite(Journal,Id);Journal.MarkSourceControlWriteStarted(Id,DateTimeOffset.UtcNow);}
            if(writeReceipt)Journal.RecordSourceActivationWrite(Id,ActivationFixture.Returned(Journal,Id));
            if(acknowledge)Journal.RecordSourceControlActivated(Id,JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=1,sessionId=Id,providerEpoch=epoch,activationNonce=new string('a',32),attachedProgramIds=new[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=0}));
            Entry=Bank.Commit(raw,Barrier.Current,DateTimeOffset.UtcNow).Entry!;eventId=Journal.IndexRawIngress(Id,Bank,Entry).CanonicalEventId!;
        }
        internal LinuxSourceWorkBarrier.Work Issue()=>Barrier.TryIssue(eventId)!;
        internal LinuxForensicJournal.NativePinClaim Claim(LinuxSourceWorkBarrier.Work work,Action<string>? checkpoint=null)=>Journal.CommitNativePin(Id,Bank,Entry,Barrier,work,checkpoint);
        public void Dispose(){Bank.Dispose();Journal.Dispose();}
    }
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
