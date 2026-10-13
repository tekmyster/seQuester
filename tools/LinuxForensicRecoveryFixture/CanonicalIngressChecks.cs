using System.Text.Json;
using System.Text.Json.Nodes;
using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

static class CanonicalIngressChecks
{
    internal static async Task DiskPressure(string root,string sensor,byte[] raw)
    {
        if(!OperatingSystem.IsLinux()||Directory.Exists(root)||!root.StartsWith("/var/tmp/sequester-linux-canonical-",StringComparison.Ordinal))throw new ArgumentException("Fresh owned Linux qualification root required");
        var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var scope=new Scope(root,sensor,epoch);
        var entry=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
        // Keep the WAL open across the real filesystem pressure injection.
        // This fixture owns the database and does not hold a write transaction.
        using var keeper=Connection(scope.Root);
        using(var setup=keeper.CreateCommand()){setup.CommandText="CREATE TABLE owned_pressure_marker(value INTEGER); INSERT INTO owned_pressure_marker VALUES(1);";setup.ExecuteNonQuery();}
        Console.WriteLine(JsonSerializer.Serialize(new{Ready=true,scope.Bank.PhysicalAllocationEstablished}));
        if(await Console.In.ReadLineAsync()!="index")throw new InvalidDataException("Owned ENOSPC handshake failed");
        int code,extended;
        try{scope.Index(entry);throw new Exception("Expected real database pressure failure");}
        catch(SqliteException ex){code=ex.SqliteErrorCode;extended=ex.SqliteExtendedErrorCode;}
        if(scope.Bank.FirstBoundary?.Reason!="INGRESS_INDEX_UNCOMMITTED"||!scope.Bank.ReadRaw(entry).SequenceEqual(raw))throw new Exception("Raw/emergency evidence lost under database pressure");
        Console.WriteLine(JsonSerializer.Serialize(new{IndexFailed=true,SqliteError=code,SqliteExtendedError=extended,Boundary=scope.Bank.FirstBoundary,RawRetained=true}));
        if(await Console.In.ReadLineAsync()!="recover")throw new InvalidDataException("Owned pressure recovery handshake failed");
        if(scope.Count("source_ingress")!=0||scope.Count("canonical_events")!=0)throw new Exception("Failed index retained a partial transaction");
        var indexed=scope.Index(entry);var replay=scope.Index(entry);
        if(indexed.Status!="RAW_VALID"||!replay.AlreadyIndexed||indexed.CanonicalEventId!=replay.CanonicalEventId||scope.Count("canonical_events")!=1)throw new Exception("Historical indexing recovery failed");
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,Source=scope.Id,EventId=indexed.CanonicalEventId,NoPartialIndex=true,RawRetained=true,NoNativeCalls=true}));
    }
    internal static void Child(string root,string sensor,byte[] raw,string cut)
    {
        var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        using var scope=new Scope(root,sensor,epoch);
        if(cut=="raw-diagnostic-indexed")raw=[255,0];
        var entry=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
        File.WriteAllText(Path.Combine(root,"child-context.json"),JsonSerializer.Serialize(new{Session=scope.Id,Collector=scope.Bank.CollectorInstance,Epoch=epoch}));
        scope.Journal.IndexRawIngress(scope.Id,scope.Bank,entry,point=>{if(point==cut)Environment.Exit(73);});
        throw new Exception("Requested canonical crash cut not reached");
    }
    internal static async Task Run(string root,string sensor,byte[] raw,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("New isolated canonical index fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        var epoch=JsonNode.Parse(raw)!["providerEpoch"]!.GetValue<ulong>().ToString(System.Globalization.CultureInfo.InvariantCulture);
        byte[] Change(string field,ulong value){var n=JsonNode.Parse(raw)!;n[field]=value;return JsonSerializer.SerializeToUtf8Bytes(n);}
        {
            using var scope=new Scope(Path.Combine(root,"canonical"),sensor,epoch);var now=DateTimeOffset.UtcNow;
            var first=scope.Bank.Commit(raw,scope.Barrier.Current,now).Entry!;var second=scope.Bank.Commit(raw,scope.Barrier.Current,now.AddSeconds(1)).Entry!;
            var outOfOrder=scope.Index(second);Check(outOfOrder.Status=="INDEX_PREDECESSOR_PENDING"&&scope.Count("source_ingress")==0,"later delivery cannot win canonical identity before the received prefix");
            var a=scope.Index(first);var b=scope.Index(second);
            Check(a.Status=="RAW_VALID"&&b.Status=="DUPLICATE"&&a.CanonicalEventId==b.CanonicalEventId&&a.CanonicalEvent==b.CanonicalEvent,"same positive cookie and exact raw bytes retain first event and receive time");
            Check(a.CanonicalEvent!.ObservedUtc==now&&a.CanonicalEvent.Attribution!.LinuxKernel!.CollectorSequence==1,"canonical event retains first actual ingress context");
            Check(scope.Index(first).AlreadyIndexed&&scope.Count("source_ingress")==2&&scope.Count("canonical_events")==1,"reindex is idempotent and does not create duplicate work");
            scope.Barrier.Fault("OWNED_TEST_FAULT",DateTimeOffset.UtcNow);var after=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var residual=scope.Index(after);
            Check(residual.Status=="RAW_AFTER_FAULT"&&residual.CanonicalEventId==a.CanonicalEventId&&residual.CanonicalEvent==null&&residual.Diagnostic!=null,"post-fault duplicate links historical identity without returning another operation");
            var changed=scope.Bank.Commit(Change("pid",12345),scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var conflict=scope.Index(changed);
            Check(conflict.Status=="CANONICAL_KEY_CONTRADICTION"&&conflict.RequiresSourceStop&&conflict.CanonicalEvent==null,"changed bytes under same native key are retained as a contradiction");
            Check(scope.Count("canonical_events")==1&&scope.Count("source_ingress")==4&&scope.Journal.ReadSource(scope.Id).State=="CONTINUITY_FAULTED","contradiction cannot rewrite first canonical evidence and faults source");
            Check(Sql(scope.Root,"PRAGMA foreign_key_check;")==null,"canonical/ingress/policy foreign keys are consistent");
        }
        {
            using var scope=new Scope(Path.Combine(root,"zero-cookie"),sensor,epoch);var zero=Change("cookie",0);
            var first=scope.Bank.Commit(zero,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var second=scope.Bank.Commit(zero,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            var a=scope.Index(first);var b=scope.Index(second);
            Check(a.Status=="RAW_VALID"&&b.Status=="RAW_VALID"&&a.CanonicalEventId!=b.CanonicalEventId&&scope.Count("canonical_events")==2,"zero-cookie copies retain separate delivery identities");
        }
        {
            using var scope=new Scope(Path.Combine(root,"unsigned-cookie"),sensor,epoch);var high=Change("cookie",ulong.MaxValue);
            var first=scope.Bank.Commit(high,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            var next=scope.Bank.Commit(high,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            var a=scope.Index(first);var b=scope.Index(next);
            Check(a.Status=="RAW_VALID"&&b.Status=="DUPLICATE"&&a.CanonicalEventId==b.CanonicalEventId,"full unsigned 64-bit cookie deduplicates without signed conversion");
            Check((string)Sql(scope.Root,"SELECT typeof(positive_cookie)||':'||positive_cookie FROM canonical_events;")! =="text:18446744073709551615","full unsigned cookie persists as exact decimal text");
            Check(scope.Index(next).CanonicalEventId==a.CanonicalEventId,"unsigned duplicate retains original identity on replay");
        }
        foreach(var kind in new[]{"invalid","foreign","after-stop","missing-policy","invalid-policy"})
        {
            using var scope=new Scope(Path.Combine(root,kind),sensor,epoch);
            if(kind=="after-stop")scope.Barrier.RequestStop("OWNED_STOP",DateTimeOffset.UtcNow);
            if(kind=="missing-policy")Sql(scope.Root,"DELETE FROM source_policy;");
            if(kind=="invalid-policy")Sql(scope.Root,"UPDATE source_policy SET sha256='"+new string('0',64)+"';");
            var bytes=kind=="invalid"?new byte[]{255,0}:kind=="foreign"?Change("providerEpoch",42):raw;
            var entry=scope.Bank.Commit(bytes,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var result=scope.Index(entry);
            var expected=kind switch{"invalid"=>"RAW_INVALID","foreign"=>"RAW_FOREIGN_EPOCH","after-stop"=>"RAW_AFTER_STOP","missing-policy"=>"POLICY_EVIDENCE_MISSING",_=>"POLICY_EVIDENCE_INVALID"};
            Check(result.Status==expected&&result.Diagnostic?.Classification==expected&&result.CanonicalEvent==null&&scope.Count("canonical_events")==0,"diagnostic only, no fabricated credentials or event: "+kind);
            Check(scope.Bank.ReadRaw(entry).SequenceEqual(bytes)&&scope.Count("source_ingress")==1,"diagnostic retains exact original raw and immutable ingress: "+kind);
            Check(result.RequiresSourceStop==(kind!="after-stop"),"raw diagnostic interruption requirement explicit: "+kind);
        }
        {
            using var scope=new Scope(Path.Combine(root,"transaction-failure"),sensor,epoch);var entry=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            Sql(scope.Root,"CREATE TRIGGER owned_canonical_fail BEFORE INSERT ON canonical_events BEGIN SELECT RAISE(FAIL,'owned canonical insert failure'); END;");
            try{scope.Index(entry);throw new Exception("Expected transaction failure");}catch(SqliteException){}
            Check(scope.Count("source_ingress")==0&&scope.Count("canonical_events")==0,"failed canonical insertion rolls back both index records");
            Check(scope.Bank.ReadRaw(entry).SequenceEqual(raw)&&scope.Bank.FirstBoundary?.Reason=="INGRESS_INDEX_UNCOMMITTED","failed index retains raw and records fixed emergency diagnostic");
            Sql(scope.Root,"DROP TRIGGER owned_canonical_fail;");Check(scope.Index(entry).Status=="RAW_VALID"&&scope.Count("canonical_events")==1,"transaction retry creates one index without re-observing an actor");
        }
        foreach(var corruption in new[]{"missing-policy","invalid-policy","canonical-time","ingress-classification"})
        {
            using var scope=new Scope(Path.Combine(root,"replay-"+corruption),sensor,epoch);
            var entry=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;var original=scope.Index(entry);
            // Simulate damaged offline storage explicitly; normal database
            // writes must enforce the existing canonical policy reference.
            if(corruption=="missing-policy")
            {
                try{Sql(scope.Root,"DELETE FROM source_policy;");throw new Exception("Expected reference protection");}
                catch(SqliteException ex){Check(ex.SqliteErrorCode==19,"canonical policy cannot be removed through normal constrained writes");}
                Sql(scope.Root,"PRAGMA foreign_keys=OFF; DELETE FROM source_policy;");
            }
            else if(corruption=="invalid-policy")Sql(scope.Root,"PRAGMA foreign_keys=OFF; UPDATE source_policy SET sha256='"+new string('0',64)+"';");
            else if(corruption=="canonical-time")
            {
                var altered=original.CanonicalEvent! with{ObservedUtc=original.CanonicalEvent!.ObservedUtc.AddMinutes(1)};
                using var c=Connection(scope.Root);using var q=c.CreateCommand();q.CommandText="UPDATE canonical_events SET decoded=$bytes";
                q.Parameters.AddWithValue("$bytes",RansomFree.Client.EventSpool.Encode(altered));q.ExecuteNonQuery();
            }
            else Sql(scope.Root,"UPDATE source_ingress SET reason='OWNED_INVALID_REASON';");
            if(corruption.EndsWith("policy",StringComparison.Ordinal))
            {
                var replay=scope.Index(entry);Check(replay.CanonicalEvent==null&&replay.RequiresSourceStop&&replay.AlreadyIndexed,"missing or damaged policy cannot return an operational event on replay: "+corruption);
                Check(scope.Journal.ReadSource(scope.Id).State=="CONTINUITY_FAULTED"&&scope.Count("canonical_events")==1,"policy replay failure records durable fault without deleting original canonical evidence: "+corruption);
            }
            else
            {
                try{scope.Index(entry);throw new Exception("Expected evidence rejection");}catch(InvalidDataException){}
                Check(scope.Bank.FirstBoundary?.Reason=="INGRESS_INDEX_UNCOMMITTED","canonical replay rejects altered stored context/classification: "+corruption);
            }
            Check(scope.Bank.ReadRaw(entry).SequenceEqual(raw),"replay corruption retains original raw bytes: "+corruption);
        }
        {
            using var scope=new Scope(Path.Combine(root,"sqlite-busy"),sensor,epoch);var entry=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            using(var blocker=Connection(scope.Root))
            using(var held=blocker.BeginTransaction())
            {
                try{scope.Index(entry);throw new Exception("Expected SQLite lock failure");}catch(SqliteException ex){Check(ex.SqliteErrorCode==5,"real held SQLite write transaction reports BUSY");}
                Check(scope.Bank.FirstBoundary?.Reason=="INGRESS_INDEX_UNCOMMITTED"&&scope.Bank.ReadRaw(entry).SequenceEqual(raw),"database lock failure leaves raw and preallocated emergency evidence intact");
                held.Rollback();
            }
            Check(scope.Count("source_ingress")==0&&scope.Count("canonical_events")==0,"database lock timeout cannot partially index a delivery");
            Check(scope.Index(entry).Status=="RAW_VALID","historical indexing resumes once database lock actually releases");
        }
        {
            using var scope=new Scope(Path.Combine(root,"concurrent"),sensor,epoch);var first=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            var duplicate=scope.Bank.Commit(raw,scope.Barrier.Current,DateTimeOffset.UtcNow).Entry!;
            await Task.WhenAll(Task.Run(()=>scope.Index(first)),Task.Run(()=>scope.Index(duplicate)),Task.Run(()=>scope.Index(first)));
            var a=scope.Index(first);var b=scope.Index(duplicate);
            Check(a.CanonicalEventId==b.CanonicalEventId&&scope.Count("canonical_events")==1&&scope.Count("source_ingress")==2,"competing index calls converge without duplicate canonical identity");
        }
        async Task ExitChild(string mode,string directory,string cut)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(CanonicalIngressChecks).Assembly.Location);
            foreach(var arg in new[]{mode,seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual child interruption: "+cut+" "+await stdout+await stderr);
        }
        foreach(var cut in new[]{"ingress-index-inserted","canonical-event-inserted","ingress-index-committed","raw-diagnostic-indexed"})
        {
            var directory=Path.Combine(root,cut);await ExitChild("canonical-child",directory,cut);
            var context=JsonNode.Parse(File.ReadAllBytes(Path.Combine(directory,"child-context.json")))!;var session=context["Session"]!.GetValue<string>();
            using var journal=new LinuxForensicJournal(directory,sensor);using var bank=new LinuxRawIngressReserve(Path.Combine(directory,"bank"),sensor,context["Collector"]!.GetValue<string>(),context["Epoch"]!.GetValue<string>(),5,true);
            Check((long)Sql(directory,"SELECT count(*) FROM canonical_events;")! ==(cut=="ingress-index-committed"?1:0),"raw/canonical transaction is all-or-nothing after actual exit: "+cut);
            var result=journal.IndexRawIngress(session,bank,bank.Entries.Single());var again=journal.IndexRawIngress(session,bank,bank.Entries.Single());
            Check(result.CanonicalEventId==again.CanonicalEventId&&again.AlreadyIndexed&&(long)Sql(directory,"SELECT count(*) FROM canonical_events;")! ==(cut=="raw-diagnostic-indexed"?0:1),"historical reindex after crash preserves canonical/diagnostic distinction without native calls: "+cut);
            if(cut=="raw-diagnostic-indexed")Check(result.Status=="RAW_INVALID"&&result.CanonicalEvent==null&&bank.ReadRaw(bank.Entries.Single()).SequenceEqual(new byte[]{255,0}),"interrupted diagnostic retains invalid bytes without fabricating an event");
            Check(journal.ReadSource(session).State=="CONTINUITY_FAULTED"&&journal.ReadSourceOwnership(session)?.Phase=="PREPARED_NO_OWNER","reindex never revives source ownership: "+cut);
        }
        foreach(var cut in new[]{"canonical-ingress-migration-before-commit","canonical-ingress-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var initial=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; PRAGMA user_version=8;");await ExitChild("migration-child",directory,cut);
            Check((long)Sql(directory,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?8:9),"canonical migration has atomic old/new schema");
            using var migrated=new LinuxForensicJournal(directory,sensor);Check((long)Sql(directory,"SELECT count(*) FROM canonical_events;")! ==0,"migration creates no artificial canonical event");
        }
        var resultSummary=new{Passed=true,Checks=checks,Schema=12,Scope="Historical raw-to-canonical indexing and diagnostics only; no native pin, source activation, dispatcher or deployment"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(resultSummary));Console.WriteLine(JsonSerializer.Serialize(resultSummary));
    }
    private sealed class Scope:IDisposable
    {
        internal string Root {get;}
        internal LinuxForensicJournal Journal {get;}
        internal LinuxRawIngressReserve Bank {get;}
        internal LinuxSourceWorkBarrier Barrier {get;}=new();
        internal string Id {get;}
        internal Scope(string root,string sensor,string epoch)
        {
            Root=root;Journal=new(root,sensor);Bank=new(Path.Combine(root,"bank"),sensor,Guid.NewGuid().ToString("N"),epoch,5,true);
            Id=Journal.PrepareControlledSource(Bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
        }
        internal LinuxForensicJournal.IndexedIngress Index(LinuxRawIngressReserve.Entry entry)=>Journal.IndexRawIngress(Id,Bank,entry);
        internal long Count(string table)=>(long)Sql(Root,"SELECT count(*) FROM "+table+";")!;
        public void Dispose(){Bank.Dispose();Journal.Dispose();}
    }
    private static SqliteConnection Connection(string root)
    {var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();return c;}
    private static object? Sql(string root,string sql)
    {using var c=Connection(root);using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
