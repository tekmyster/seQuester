using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

static class OwnerMethodChecks
{
    internal static async Task Run(string root,string sensor,string seedPath)
    {
        if(Directory.Exists(root))throw new ArgumentException("Fresh owner method fixture required");Directory.CreateDirectory(root);int checks=0;
        void Check(bool ok,string name){if(!ok)throw new Exception(name);checks++;Console.WriteLine("PASS: "+name);}
        void Reject(Action action,string label){try{action();throw new Exception("Invalid owner receipt accepted: "+label);}catch(Exception e)when(e is InvalidOperationException or InvalidDataException or SqliteException){Check(true,label);}}
        foreach(var mode in new[]{"normal","open-error","open-postcommit","link-failure","close-error","close-receipt-failure","close-state-failure"})
        {
            var dir=Path.Combine(root,mode);using var journal=new LinuxForensicJournal(dir,sensor);journal.AdmitOwnedRuntime();
            Reject(journal.AdmitOwnedRuntime,"same journal cannot launch overlapping owned runtimes: "+mode);
            using var bank=new LinuxRawIngressReserve(Path.Combine(dir,"bank"),sensor,Guid.NewGuid().ToString("N"),"123",5,true);
            var source=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024);var id=source.Id;
            var opened=ActivationFixture.OwnerReturn(id,success:mode!="open-error");
            Reject(()=>journal.RecordOwnerMethodReturn(id,opened),"open return cannot precede recorded owner attempt: "+mode);
            journal.RecordSourceOwnerOpenAttempt(id,DateTimeOffset.UtcNow);
            Reject(()=>journal.CommitSourceControlLink(id,SourcePolicyChecks.Ready(),DateTimeOffset.UtcNow),"attempt alone cannot establish successful opened linkage: "+mode);
            if(mode=="open-postcommit")
            {try{journal.RecordOwnerMethodReturn(id,opened,_=>throw new IOException("Owned unobserved open receipt commit"));throw new Exception("Open postcommit injection missed");}catch(IOException){Check(journal.ReadOwnerMethodReturn(id,"OPEN")==opened,"unobserved committed open retains exact returned fact");}}
            journal.RecordOwnerMethodReturn(id,opened);journal.RecordOwnerMethodReturn(id,opened);
            Check(journal.ReadOwnerMethodReturn(id,"OPEN")==opened,"original opening outcome retained exactly: "+mode);
            Reject(()=>journal.RecordOwnerMethodReturn(id,opened with{ReceiptId=Guid.NewGuid().ToString("N")}),"opening receipt identity cannot be regenerated: "+mode);
            if(mode=="open-error")
            {
                Reject(()=>journal.CommitSourceControlLink(id,SourcePolicyChecks.Ready(),DateTimeOffset.UtcNow),"thrown opening outcome cannot activate linked source");
                Check(journal.ReadSourceControl(id)==null&&journal.ReadSource(id).CloseReturnedUtc==null,"failed opening has no invented link or close return");
                Reject(()=>journal.ReleaseOwnedRuntime(id),"failed opening must receive a durable no-controller terminal record before release");
                var finished=DateTimeOffset.UtcNow;
                Reject(()=>journal.RecordSourceNoController(id,null,finished),"failed actual open cannot be replaced by not-called proof");
                journal.RecordSourceNoController(id,opened,finished);journal.RecordSourceNoController(id,opened,finished);
                Check(journal.ReadSource(id).State=="CLOSED"&&journal.ReadSource(id).CloseReturnedUtc==null&&journal.ReadOwnerMethodReturn(id,"CLOSE")==null,"failed opening closes only source lifecycle without inventing native close");
                Reject(()=>journal.RecordSourceNoController(id,opened,finished.AddTicks(1)),"no-controller terminal timestamp cannot be regenerated");
                bank.SealInput(DateTimeOffset.UtcNow);bank.Dispose();journal.ReleaseOwnedRuntime(id);journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
                Check(true,"failed opening permits fresh explicit admission only after terminal proof");continue;
            }
            Reject(()=>journal.RecordSourceNoController(id,opened,DateTimeOffset.UtcNow),"successful opening cannot use no-controller completion: "+mode);
            if(mode=="link-failure")
            {
                Sql(dir,"CREATE TRIGGER owned_link_failure BEFORE INSERT ON source_control BEGIN SELECT RAISE(FAIL,'owned post-open link failure'); END;");
                Reject(()=>journal.CommitSourceControlLink(id,SourcePolicyChecks.Ready(),DateTimeOffset.UtcNow),"failed link leaves successful opening receipt visible");
                Check(journal.ReadSourceControl(id)==null&&journal.ReadOwnerMethodReturn(id,"OPEN")==opened,"opened but unlinked owner retains exact evidence");
            }
            else journal.CommitSourceControlLink(id,SourcePolicyChecks.Ready(),DateTimeOffset.UtcNow);
            var closed=ActivationFixture.OwnerReturn(id,"CLOSE",mode!="close-error");
            Reject(()=>journal.RecordOwnerMethodReturn(id,closed),"close result cannot precede durable close intent: "+mode);
            journal.TransitionSource(id,"CLOSE_UNKNOWN_OPEN",new("OWNED_CLOSE_INTENT",DateTimeOffset.UtcNow,null,"0","0",null,null,[]));
            Reject(()=>journal.RecordSourceCloseReturned(id,closed.ReturnedUtc),"close intent alone cannot invent returned success: "+mode);
            Reject(()=>journal.RecordOwnerMethodReturn(id,closed with{AttemptedMonotonic=opened.AttemptedMonotonic-1}),"close cannot precede original open in monotonic order: "+mode);
            if(mode=="close-receipt-failure")
            {
                Sql(dir,"CREATE TRIGGER owned_close_receipt_failure BEFORE INSERT ON source_owner_returns WHEN NEW.method='CLOSE' BEGIN SELECT RAISE(FAIL,'owned close receipt failure'); END;");
                Reject(()=>journal.RecordOwnerMethodReturn(id,closed),"close receipt failure remains explicit");
                Check(journal.ReadSource(id).CloseReturnedUtc==null,"uncommitted close result does not mark source closed");Sql(dir,"DROP TRIGGER owned_close_receipt_failure;");
            }
            journal.RecordOwnerMethodReturn(id,closed);journal.RecordOwnerMethodReturn(id,closed);
            Check(journal.ReadOwnerMethodReturn(id,"CLOSE")==closed,"exact returned close method fact preserved: "+mode);
            if(mode=="close-error")
            {
                Reject(()=>journal.RecordSourceCloseReturned(id,closed.ReturnedUtc),"failed native close cannot finalize successful source closure");
                Reject(()=>journal.ReleaseOwnedRuntime(id),"failed close keeps source unavailable for reopening");continue;
            }
            if(mode=="close-state-failure")
            {
                Sql(dir,"CREATE TRIGGER owned_closed_state_failure BEFORE UPDATE ON source_lifecycle WHEN NEW.state='CLOSED' BEGIN SELECT RAISE(FAIL,'owned close state failure'); END;");
                Reject(()=>journal.RecordSourceCloseReturned(id,closed.ReturnedUtc),"close state failure does not discard original method receipt");
                Check(journal.ReadOwnerMethodReturn(id,"CLOSE")==closed&&journal.ReadSource(id).State=="CLOSE_UNKNOWN_OPEN","returned close and uncommitted lifecycle stay distinct");Sql(dir,"DROP TRIGGER owned_closed_state_failure;");
            }
            Reject(()=>journal.RecordSourceCloseReturned(id,closed.ReturnedUtc.AddTicks(1)),"receipt recovery cannot regenerate actual close time: "+mode);
            journal.RecordSourceCloseReturned(id,closed.ReturnedUtc);journal.RecordSourceCloseReturned(id,closed.ReturnedUtc);
            Check(journal.ReadSource(id).State=="CLOSED"&&journal.ReadSource(id).CloseReturnedUtc==closed.ReturnedUtc,"only exact successful return finalizes source: "+mode);
            bank.SealInput(DateTimeOffset.UtcNow);bank.Dispose();journal.ReleaseOwnedRuntime(id);journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
            Check(true,"confirmed closure releases exclusive runtime admission: "+mode);
        }
        foreach(var attempted in new[]{false,true})
        {
            var dir=Path.Combine(root,"never-called-"+attempted);using var journal=new LinuxForensicJournal(dir,sensor);journal.AdmitOwnedRuntime();
            using var bank=new LinuxRawIngressReserve(Path.Combine(dir,"bank"),sensor,Guid.NewGuid().ToString("N"),"123",5,true);
            var id=journal.PrepareControlledSource(bank,new(),"0",DateTimeOffset.UtcNow,512L*1024*1024).Id;
            if(attempted)journal.RecordSourceOwnerOpenAttempt(id,DateTimeOffset.UtcNow);
            var time=DateTimeOffset.UtcNow;
            Sql(dir,"CREATE TRIGGER owned_no_controller_failure BEFORE UPDATE ON source_lifecycle WHEN NEW.state='CLOSED' BEGIN SELECT RAISE(FAIL,'owned terminal failure'); END;");
            Reject(()=>journal.RecordSourceNoController(id,null,time),"failed terminal commit cannot release no-controller lifecycle: "+attempted);
            Check(journal.ReadSource(id).State=="OPEN"&&journal.ReadSourceBoundaries(id).Length==0,"no-controller terminal boundary and state commit atomically: "+attempted);
            Sql(dir,"DROP TRIGGER owned_no_controller_failure;");journal.RecordSourceNoController(id,null,time);journal.RecordSourceNoController(id,null,time);
            Check(journal.ReadSource(id).CloseReturnedUtc==null&&journal.ReadOwnerMethodReturn(id,"OPEN")==null&&journal.ReadOwnerMethodReturn(id,"CLOSE")==null,"not-called opening fabricates neither method result: "+attempted);
            bank.SealInput(DateTimeOffset.UtcNow);bank.Dispose();journal.ReleaseOwnedRuntime(id);journal.AdmitOwnedRuntime();journal.ReleaseOwnedRuntime(null);
            Reject(()=>journal.RecordSourceNoController(id,null,time),"historical terminal proof cannot impersonate live runtime ownership: "+attempted);
        }
        foreach(var cut in new[]{"owner-method-migration-before-commit","owner-method-migration-after-commit"})
        {
            var dir=Path.Combine(root,cut);using(var initial=new LinuxForensicJournal(dir,sensor)){}
            Sql(dir,"DROP TABLE source_owner_returns; PRAGMA user_version=11;");
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};if(Path.GetFileNameWithoutExtension(Environment.ProcessPath)=="dotnet")start.ArgumentList.Add(typeof(OwnerMethodChecks).Assembly.Location);
            foreach(var arg in new[]{"migration-child",seedPath,dir,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            Check(child.ExitCode==73,"actual owner migration exit: "+cut+" "+await stdout+await stderr);
            Check((long)Sql(dir,"PRAGMA user_version;")! ==(cut.EndsWith("before-commit",StringComparison.Ordinal)?11:12),"owner receipt migration is atomic: "+cut);
            using var upgraded=new LinuxForensicJournal(dir,sensor);Check((long)Sql(dir,"SELECT count(*) FROM source_owner_returns;")! ==0,"upgrade invents no historical native method return: "+cut);
        }
        var result=new{Passed=true,Checks=checks,Cases=11,Schema=12,Scope="Immutable owner open/close receipts, no-controller terminal proof and database failure/migration gates, injected method outcomes only; no native controller execution"};File.WriteAllText(Path.Combine(root,"RESULTS.json"),JsonSerializer.Serialize(result));Console.WriteLine(JsonSerializer.Serialize(result));
    }
    private static object? Sql(string root,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(root,"linux-forensic-intake/journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return q.ExecuteScalar();}
}
