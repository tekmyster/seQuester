using RansomFree.Contracts;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;

static class SourceControlJournalChecks
{
    internal static async Task Run(string root,string sensor,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("New isolated control journal directory required");Directory.CreateDirectory(root);var checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is InvalidDataException or InvalidOperationException or SqliteException){Check(true,label);return;}throw new Exception("Unexpected control journal acceptance: "+label);}
        byte[] Ready(ulong epoch=123)=>JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=epoch,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=0,activationFrame="one-command-then-eof"});
        byte[] Active(string id,ulong lost=0)=>JsonSerializer.SerializeToUtf8Bytes(new{controlledActivated=true,controlVersion=1,sessionId=id,providerEpoch=123,activationNonce=new string('a',32),attachedProgramIds=new[]{2,3,4,1,5},observeAttached=true,denialAttached=true,lostAtActivation=lost});
        byte[] Complete(bool active=true,bool attempted=true)=>JsonSerializer.SerializeToUtf8Bytes(new{controlledComplete=true,controlVersion=1,activated=active,observerAttempted=attempted,reason=active?"CONTROLLED_STOPPED":"CONTROLLED_ACTIVATION_REJECTED",nativeError=0,retainedLinksDestroyed=active?5:3,drainResult=0,lost=0,lostError=(int?)null});
        LinuxSourceSession Source(LinuxForensicJournal journal,string dir)=>new(journal,Path.Combine(dir,"bank"),sensor,5,"123",new(0),layoutReplayForTest:true);
        var directory=Path.Combine(root,"link");string sourceId;byte[] exact=Ready();DateTimeOffset linked=DateTimeOffset.UtcNow;
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var source=Source(journal,directory);sourceId=source.Id;
            Reject(()=>journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow),"write attempt requires previously committed source link");
            Reject(()=>journal.CommitSourceControlLink(sourceId,Ready(124),linked),"ready epoch cannot attach to a different source session");
            journal.CommitSourceControlLink(sourceId,exact,linked);
            var link=journal.ReadSourceControl(sourceId)!;Check(link.Ready.SequenceEqual(exact)&&link.LinkedUtc==linked&&link.WriteStartedUtc==null&&link.Activated==null&&link.Completion==null,"new session link is exact and makes no activation claim");
            Reject(()=>journal.CommitSourceControlLink(sourceId,exact,linked),"duplicate link cannot reset one-use startup state");
            Reject(()=>journal.RecordSourceControlActivated(sourceId,Active(sourceId)),"success acknowledgement requires a recorded write attempt");
            Reject(()=>journal.RecordSourceControlCompletion(sourceId,Complete()),"observer completion cannot precede recorded activation attempt");
            journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow);
            Reject(()=>journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow),"write attempt is one-use even without acknowledgment");
            Reject(()=>journal.RecordSourceControlActivated(sourceId,Active(new string('f',32))),"foreign session acknowledgment rejected");
            var ack=Active(sourceId);journal.RecordSourceControlActivated(sourceId,ack);journal.RecordSourceControlActivated(sourceId,ack);
            Check(journal.ReadSourceControl(sourceId)!.Activated!.SequenceEqual(ack),"identical acknowledgment is idempotent and retains exact bytes");
            Reject(()=>journal.RecordSourceControlActivated(sourceId,Active(sourceId,1)),"changed acknowledgment does not rewrite lost counter history");
            Reject(()=>journal.RecordSourceControlCompletion(sourceId,Complete(false,false)),"disabled completion cannot contradict activated acknowledgment");
            var completed=Complete();journal.RecordSourceControlCompletion(sourceId,completed);journal.RecordSourceControlCompletion(sourceId,completed);
            Check(journal.ReadSourceControl(sourceId)!.Completion!.SequenceEqual(completed),"identical completion is immutable and idempotent");
            Reject(()=>journal.RecordSourceControlActivated(sourceId,ack),"completed loader cannot accept a later activation acknowledgment");
            source.CloseForTest(new(0),()=>{});
        }
        using(var reopened=new LinuxForensicJournal(directory,sensor))
        {var link=reopened.ReadSourceControl(sourceId)!;Check(link.Ready.SequenceEqual(exact)&&link.Activated!=null&&link.Completion!=null&&link.LinkedUtc==linked,"control evidence survives closed-source database reopen unchanged");}
        directory=Path.Combine(root,"v2-link");
        var v2Ready=ControlledProtocolV2Checks.Encode(ControlledProtocolV2Checks.Ready(32));
        byte[] Version2(byte[] value)
        {var node=System.Text.Json.Nodes.JsonNode.Parse(value)!.AsObject();node["controlVersion"]=2;return JsonSerializer.SerializeToUtf8Bytes(node);}
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var source=Source(journal,directory);sourceId=source.Id;
            journal.CommitSourceControlLink(sourceId,v2Ready,DateTimeOffset.UtcNow);
            journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow);
            Reject(()=>journal.RecordSourceControlActivated(sourceId,Active(sourceId)),"v2 source rejects a v1 acknowledgment");
            journal.RecordSourceControlActivated(sourceId,Version2(Active(sourceId)));
            Reject(()=>journal.RecordSourceControlCompletion(sourceId,Complete()),"v2 source rejects a v1 completion");
            journal.RecordSourceControlCompletion(sourceId,Version2(Complete()));
            source.CloseForTest(new(0),()=>{});
        }
        using(var reopened=new LinuxForensicJournal(directory,sensor))
        {
            var control=reopened.ReadSourceControl(sourceId)!;
            var parsed=LinuxControlledLoaderProtocol.ParseReady(control.Ready);
            Check(control.Ready.SequenceEqual(v2Ready)&&parsed.Targets!.Targets.Length==32&&control.Activated!=null&&control.Completion!=null,"v2 exact target revision and control frames survive database reopen");
        }
        Sql(directory,"UPDATE source_control SET completion=CAST(replace(CAST(completion AS TEXT),'\"controlVersion\":2','\"controlVersion\":1') AS BLOB);");
        using(var reopened=new LinuxForensicJournal(directory,sensor))
        {Reject(()=>reopened.ReadSourceControl(sourceId),"stored cross-version completion is rejected on reopen");}
        directory=Path.Combine(root,"missing-ack");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var source=Source(journal,directory);sourceId=source.Id;journal.CommitSourceControlLink(sourceId,exact,DateTimeOffset.UtcNow);journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow);journal.RecordSourceControlCompletion(sourceId,Complete());
            Check(journal.ReadSourceControl(sourceId)!.Activated==null,"successful final observation never manufactures a missing activation acknowledgment");
        }
        using(var reopened=new LinuxForensicJournal(directory,sensor))
        {
            Check(reopened.ReadSource(sourceId).State=="CONTINUITY_FAULTED"&&reopened.ReadSourceControl(sourceId)!.Activated==null,"actual restart retains unknown source ownership and missing acknowledgment");
            Reject(()=>reopened.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow),"restart never authorizes retransmission of old activation");
            Reject(()=>Source(reopened,Path.Combine(directory,"new")),"saved control completion is not a native controller-close receipt");
        }
        directory=Path.Combine(root,"storage-failure");
        using(var journal=new LinuxForensicJournal(directory,sensor))
        {
            var source=Source(journal,directory);sourceId=source.Id;
            Sql(directory,"CREATE TRIGGER owned_fail_link BEFORE INSERT ON source_control BEGIN SELECT RAISE(FAIL,'owned link failure'); END;");
            Reject(()=>journal.CommitSourceControlLink(sourceId,exact,DateTimeOffset.UtcNow),"failed link transaction is visible");
            Check(journal.ReadSourceControl(sourceId)==null,"failed link creates no activation authority or invented record");
            Reject(()=>journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow),"write remains unavailable after failed link commit");
            Sql(directory,"DROP TRIGGER owned_fail_link;");journal.CommitSourceControlLink(sourceId,exact,DateTimeOffset.UtcNow);
            Sql(directory,"CREATE TRIGGER owned_fail_write BEFORE UPDATE ON source_control BEGIN SELECT RAISE(FAIL,'owned write intent failure'); END;");
            Reject(()=>journal.MarkSourceControlWriteStarted(sourceId,DateTimeOffset.UtcNow),"failed write-intent transaction is visible");
            Check(journal.ReadSourceControl(sourceId)!.WriteStartedUtc==null,"write-intent failure cannot claim an attempted pipe write");
            source.CloseForTest(new(0),()=>{});
        }
        foreach(var cut in new[]{"control-migration-before-commit","control-migration-after-commit"})
        {
            directory=Path.Combine(root,cut);using(var journal=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; DROP TABLE source_reconciliation; DROP TABLE source_control; PRAGMA user_version=5;");
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(SourceControlJournalChecks).Assembly.Location);
            foreach(var arg in new[]{"migration-child",seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual child exit during control migration: "+cut+" "+await stdout+await stderr);
            using var reopened=new LinuxForensicJournal(directory,sensor);Check(reopened.ReadSourceControl(Guid.NewGuid().ToString("N"))==null,"migration recovery fabricates no control session: "+cut);
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Control-plane journal and migration only; no actual pipe write, attachment, activation or deployment"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static void Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();}
}
