using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class SourcePolicyChecks
{
    internal static byte[] Ready()=>JsonSerializer.SerializeToUtf8Bytes(new{controlledReady=true,controlVersion=1,schemaVersion=5,loadedProgramIds=new[]{1,2,3,4,5},attachedProgramIds=new[]{2,3,4},observeAttached=false,denialAttached=false,scratchMapFrozen=true,scratchMapId=11,configMapFrozen=true,configMapId=12,eventsMapId=13,lostMapId=14,providerEpoch=123,activationNonce=new string('a',32),targetInode=321,targetDevice=17,targetPinned=true,mode=0,lostAtReady=0,activationFrame="one-command-then-eof"});
    private static LinuxRawIngressReserve Bank(string directory,string sensor,string collector)=>new(Path.Combine(directory,"bank"),sensor,collector,"123",5,true);
    internal static void Child(string root,string sensor,string collector,string cut)
    {
        using var journal=new LinuxForensicJournal(root,sensor);using var bank=Bank(root,sensor,collector);
        var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);
        if(cut!="prepared")journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow);
        if(cut is "linked" or "write-started"){journal.RecordOwnerMethodReturn(source.Id,ActivationFixture.OwnerReturn(source.Id));journal.CommitSourceControlLink(source.Id,Ready(),DateTimeOffset.UtcNow);}
        if(cut=="write-started"){ActivationFixture.BeforeWrite(journal,source.Id);journal.MarkSourceControlWriteStarted(source.Id,DateTimeOffset.UtcNow);}
        File.WriteAllText(Path.Combine(root,"source-id.txt"),source.Id);Environment.Exit(73);
    }
    internal static async Task Run(string root,string sensor,string collector,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("New isolated source policy root required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks++;Console.WriteLine("PASS: "+label);}
        void Reject(Action action,string label){try{action();}catch(Exception ex)when(ex is InvalidDataException or InvalidOperationException or SqliteException){Check(true,label);return;}throw new Exception("Unexpected source policy acceptance: "+label);}
        {
            var directory=Path.Combine(root,"freeze");using var journal=new LinuxForensicJournal(directory,sensor);using var bank=Bank(directory,sensor,collector);
            var configured=new ForensicPolicy(true,"high",16,128,64);var saved=configured;
            var source=journal.PrepareControlledSource(bank,configured,"0",DateTimeOffset.UtcNow,512L*1024*1024);configured=new(false,"critical",1,64,1);
            Check(journal.ReadSourcePolicy(source.Id)!.Policy==saved&&journal.ReadSourcePolicy(source.Id)!.Policy!=configured,"source policy stays frozen when current settings change");
            Check(journal.ReadSourceOwnership(source.Id)?.Phase=="PREPARED_NO_OWNER"&&journal.ReadSourceBankFormat(source.Id)=="raw-ingress-v3","prepared bank identifies format and explicitly has no native owner");
            Reject(()=>journal.CommitSourceControlLink(source.Id,Ready(),DateTimeOffset.UtcNow),"preparation alone cannot authorize controller linkage");
            Reject(()=>journal.TransitionSource(source.Id,"CLOSE_UNKNOWN_OPEN",new("INVALID_UNOPENED_CLOSE",DateTimeOffset.UtcNow,null,"0","0",null,null,[])),"unopened source cannot manufacture controller close intent");
            Sql(directory,"CREATE TRIGGER owned_attempt_fail BEFORE UPDATE ON source_ownership BEGIN SELECT RAISE(FAIL,'owned attempt failure'); END;");
            Reject(()=>journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow),"failed attempt marker remains visible");
            Check(journal.ReadSourceOwnership(source.Id)?.Phase=="PREPARED_NO_OWNER","failed marker creates no opening attempt evidence");
            Sql(directory,"DROP TRIGGER owned_attempt_fail;");journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow);
            Reject(()=>journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow),"controller opening marker is one-use");
            journal.RecordOwnerMethodReturn(source.Id,ActivationFixture.OwnerReturn(source.Id));journal.CommitSourceControlLink(source.Id,Ready(),DateTimeOffset.UtcNow);
            Check(journal.ReadSourceOwnership(source.Id)?.Phase=="LINKED_OWNER"&&journal.ReadSourceControl(source.Id)!=null,"ready linkage and ownership phase commit together");
            Sql(directory,"UPDATE source_policy SET sha256='"+new string('0',64)+"';");
            Reject(()=>journal.ReadSourcePolicy(source.Id),"invalid frozen policy digest is never interpreted as current policy");
            Reject(()=>journal.MarkSourceControlWriteStarted(source.Id,DateTimeOffset.UtcNow),"invalid policy prevents activation-write marker");
            Check(journal.ReadSourceControl(source.Id)!.WriteStartedUtc==null,"missing policy evidence cannot claim activation attempt");
        }
        foreach(var failTable in new[]{"source_policy","source_ownership"})
        {
            var directory=Path.Combine(root,failTable+"-failure");using var journal=new LinuxForensicJournal(directory,sensor);using var bank=Bank(directory,sensor,collector);
            Sql(directory,"CREATE TRIGGER owned_prepare_fail BEFORE INSERT ON "+failTable+" BEGIN SELECT RAISE(FAIL,'owned preparation failure'); END;");
            Reject(()=>journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024),"preparation transaction failure is visible: "+failTable);
            Check((long)Sql(directory,"SELECT count(*) FROM source_lifecycle;")! ==0&&(long)Sql(directory,"SELECT count(*) FROM source_banks;")! ==0&&(long)Sql(directory,"SELECT count(*) FROM source_policy;")! ==0,"failed preparation leaves no partial bank/source/policy: "+failTable);
            Sql(directory,"DROP TRIGGER owned_prepare_fail;");var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);
            Check(journal.ReadSourceOwnership(source.Id)?.Phase=="PREPARED_NO_OWNER","actual transaction retry does not open native controller: "+failTable);
        }
        {
            var directory=Path.Combine(root,"missing-policy");using var journal=new LinuxForensicJournal(directory,sensor);using var bank=Bank(directory,sensor,collector);
            var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);Sql(directory,"DELETE FROM source_policy;");
            Reject(()=>journal.RecordSourceOwnerOpenAttempt(source.Id,DateTimeOffset.UtcNow),"missing policy row prevents even controller opening marker");
            Check(journal.ReadSourceOwnership(source.Id)?.Phase=="PREPARED_NO_OWNER","policy failure leaves no owner attempt");
        }
        {
            var directory=Path.Combine(root,"foreign-bank");using var journal=new LinuxForensicJournal(directory,sensor);using var bank=Bank(directory,new string('f',32),collector);
            Reject(()=>journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024),"different sensor bank cannot join this journal");
        }
        async Task ExitChild(string mode,string directory,string cut)
        {
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(SourcePolicyChecks).Assembly.Location);
            foreach(var arg in new[]{mode,seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual child exit: "+cut+" "+await stdout+await stderr);
        }
        foreach(var cut in new[]{"prepared","attempted","linked","write-started"})
        {
            var directory=Path.Combine(root,cut);await ExitChild("source-policy-child",directory,cut);var id=File.ReadAllText(Path.Combine(directory,"source-id.txt"));
            using var journal=new LinuxForensicJournal(directory,sensor);
            Check(journal.ReadSource(id).State=="CONTINUITY_FAULTED"&&journal.ReadSource(id).CloseReturnedUtc==null,"restart never invents native close: "+cut);
            Check((journal.ReadSourceReconciliation(id)==null)==(cut=="prepared"),"only a possible native owner requires owner reconciliation: "+cut);
            Check(journal.ReadSourcePolicy(id)!.Policy==new ForensicPolicy(),"frozen source policy survives process exit: "+cut);
            Reject(()=>journal.RecordSourceOwnerOpenAttempt(id,DateTimeOffset.UtcNow),"restart never retries native opening: "+cut);
        }
        foreach(var cut in new[]{"source-policy-migration-before-commit","source-policy-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var initial=new LinuxForensicJournal(directory,sensor)){}
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; PRAGMA user_version=7;");
            await ExitChild("migration-child",directory,cut);
            Check((long)Sql(directory,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?7:8),"source policy migration is atomic at actual process exit");
            using var journal=new LinuxForensicJournal(directory,sensor);Check(journal.ReadSourcePolicy(Guid.NewGuid().ToString("N"))==null,"migration creates no synthetic source policy");
        }
        {
            var directory=Path.Combine(root,"legacy-bank-migration");LinuxForensicJournal.SourceLifecycle original;
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                var legacy=new LinuxSourceSession(journal,Path.Combine(directory,"bank"),sensor,5,"123",new(0),layoutReplayForTest:true);
                legacy.CloseForTest(new(0),()=>{});original=journal.ReadSource(legacy.Id);
            }
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; PRAGMA user_version=7;");
            using var upgraded=new LinuxForensicJournal(directory,sensor);
            Check(upgraded.ReadSource(original.Id)==original&&upgraded.ReadSourceBankFormat(original.Id)=="raw-reserve-v2","migration classifies existing v2 bank without rewriting lifecycle");
            Check(upgraded.ReadSourcePolicy(original.Id)==null&&upgraded.ReadSourceOwnership(original.Id)==null,"legacy per-record policy never receives fabricated controlled-source ownership or policy");
        }
        var result=new{Passed=true,Checks=checks,Schema=12,Scope="Frozen source policy and explicit preparation/open-attempt phase; no descriptor opened, canonical index, runtime activation or deployment"};
        File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
