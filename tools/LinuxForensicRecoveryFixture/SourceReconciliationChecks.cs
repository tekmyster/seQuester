using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

static class SourceReconciliationChecks
{
    internal static void Child(string root,string sensor,string cut)
    {
        using var journal=new LinuxForensicJournal(root,sensor);
        var source=new LinuxSourceSession(journal,Path.Combine(root,"bank"),sensor,5,"123",cut=="loss-unavailable"?new(null,"owned-read-error"):new(9),layoutReplayForTest:true);
        if(cut=="faulted")source.SampleLoss(new(10));
        if(cut is "linked" or "write-started" or "active")
        {
            var ready=JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=123,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=9,activationFrame="one-command-then-eof"});
            journal.CommitSourceControlLink(source.Id,ready,DateTimeOffset.UtcNow);
            if(cut is "write-started" or "active")journal.MarkSourceControlWriteStarted(source.Id,DateTimeOffset.UtcNow);
            if(cut=="active")journal.RecordSourceControlActivated(source.Id,JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=1,sessionId=source.Id,providerEpoch=123,activationNonce=new string('a',32),attachedProgramIds=new[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=9}));
        }
        void Exit(){File.WriteAllText(Path.Combine(root,"before.json"),JsonSerializer.Serialize(journal.ReadSource(source.Id)));Environment.Exit(73);}
        if(cut=="close-unknown")source.CloseForTest(new(9),Exit);else Exit();
    }
    internal static async Task Run(string root,string sensor,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("New isolated reconciliation test root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is InvalidOperationException or InvalidDataException or SqliteException){Check(true,label);return;}throw new Exception("Unexpected reconciliation acceptance: "+label);}
        async Task ExitChild(string mode,string directory,string cut)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(SourceReconciliationChecks).Assembly.Location);
            foreach(var arg in new[]{mode,seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual child exit: "+cut+" "+await stdout+await stderr);
        }
        foreach(var cut in new[]{"open","linked","write-started","active","faulted","loss-unavailable","close-unknown"})
        {
            var directory=Path.Combine(root,cut);await ExitChild("reconciliation-child",directory,cut);
            var before=JsonSerializer.Deserialize<LinuxForensicJournal.SourceLifecycle>(File.ReadAllBytes(Path.Combine(directory,"before.json")))!;
            string bankPath=(string)Sql(directory,"SELECT path FROM source_banks;")!;
            // Receipt collection must use saved identity and succeed even when
            // the original bank is absent. Never recover by pathname guessing.
            var retained=bankPath+".retained-by-test";File.Move(bankPath,retained);
            LinuxForensicJournal.SourceReconciliation first;
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                first=journal.ReadSourceReconciliation(before.Id)!;
                Check(first is {SchemaVersion:1,Status:"RECONCILIATION_REQUIRED",Reason:"COLLECTOR_RESTART_UNKNOWN"}&&first.SessionId==before.Id&&first.BankId==before.BankId&&first.CollectorInstance==before.CollectorInstance&&first.ProviderEpoch==before.ProviderEpoch,"receipt binds exact historical source: "+cut);
                Check(first.LastKnownLost==before.LatestLost&&first.PriorLifecycleState==before.State&&first.FirstObservedUtc>=before.OpenedUtc,"first pre-restart state and actual loss retained: "+cut);
                Check(first.StoredBankPath==bankPath&&first.StoredBankStableId.Length>0&&first.StoredBankBytes==new FileInfo(retained).Length&&!File.Exists(bankPath),"stored bank metadata is not a fabricated live file observation: "+cut);
                var after=journal.ReadSource(before.Id);
                Check(after.CloseReturnedUtc==null&&after.State==(cut=="close-unknown"?"CLOSE_UNKNOWN_OPEN":"CONTINUITY_FAULTED")&&after.LatestLost==null,"receipt never invents historical close or current loss: "+cut);
                Reject(()=>new LinuxSourceSession(journal,Path.Combine(directory,"new-bank"),sensor,5,"456",new(0),layoutReplayForTest:true),"receipt never authorizes a replacement source: "+cut);
            }
            using(var journal=new LinuxForensicJournal(directory,sensor))Check(journal.ReadSourceReconciliation(before.Id)==first,"repeated restart preserves first receipt unchanged: "+cut);
        }
        foreach(var failedTable in new[]{"source_reconciliation","source_boundaries"})
        {
            var directory=Path.Combine(root,failedTable+"-write-failure");await ExitChild("reconciliation-child",directory,"open");
            var before=JsonSerializer.Deserialize<LinuxForensicJournal.SourceLifecycle>(File.ReadAllBytes(Path.Combine(directory,"before.json")))!;
            Sql(directory,"CREATE TRIGGER owned_receipt_failure BEFORE INSERT ON "+failedTable+" BEGIN SELECT RAISE(FAIL,'owned restart write failure'); END;");
            Reject(()=>{using var journal=new LinuxForensicJournal(directory,sensor);},"receipt write failure stops reopen visibly");
            Check((long)Sql(directory,"SELECT count(*) FROM source_reconciliation;")! ==0&&(long)Sql(directory,"SELECT count(*) FROM source_boundaries;")! ==0&&(string)Sql(directory,"SELECT state FROM source_lifecycle;")! =="OPEN"&&(string)Sql(directory,"SELECT latest_lost FROM source_lifecycle;")! =="9","failed receipt or boundary rolls back receipt, lifecycle and loss");
            Sql(directory,"DROP TRIGGER owned_receipt_failure;");
            using var recovered=new LinuxForensicJournal(directory,sensor);
            Check(recovered.ReadSourceReconciliation(before.Id)!.LastKnownLost=="9","retry after storage recovery records actual original loss");
        }
        {
            var directory=Path.Combine(root,"actually-closed");string id;
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {var source=new LinuxSourceSession(journal,Path.Combine(directory,"bank"),sensor,5,"123",new(0),layoutReplayForTest:true);id=source.Id;source.CloseForTest(new(0),()=>{});}
            using var reopened=new LinuxForensicJournal(directory,sensor);Check(reopened.ReadSourceReconciliation(id)==null&&reopened.ReadSource(id).State=="CLOSED","actual closed source does not manufacture reconciliation work");
        }
        foreach(var cut in new[]{"reconciliation-migration-before-commit","reconciliation-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var journal=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; DROP TABLE source_reconciliation; PRAGMA user_version=6;");await ExitChild("migration-child",directory,cut);
            Check((long)Sql(directory,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?6:7),"actual migration exit preserves atomic old/new schema: "+cut);
            using var reopened=new LinuxForensicJournal(directory,sensor);Check(reopened.ReadSourceReconciliation(Guid.NewGuid().ToString("N"))==null,"migration recovery never creates a source receipt without a source: "+cut);
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Receipt-only interrupted owner and atomic migration; no native controller, activation, recovery opening or production deployment"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
