using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class NativeProgressChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,string seedPath,Action<bool,string> check)
    {
        var ready=snapshot.NativeStatus;var failed=ready with{State=4,Error=-5,Bytes=0};
        var draining=ready with{State=5,Error=-110,FinishedNs=0,WriteLease=1,Bytes=0};
        var cases=new (string Name,LinuxActorLeaseStatus Status,string Disposition,bool Final)[]{
            ("failed",failed,"ACTOR_COPY_UNAVAILABLE_NATIVE_FAILED",true),
            ("complete-short",ready with{Bytes=ready.Size-1},"ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS",true),
            ("complete-error",ready with{Error=-5},"ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS",true),
            ("complete-late",ready with{FinishedNs=ready.DeadlineNs},"ACTOR_COPY_UNAVAILABLE_INVALID_NATIVE_STATUS",true),
            ("complete-unfinished",ready with{FinishedNs=0},"NATIVE_INVALID_STATUS_UNRELEASED",false),
            ("complete-held",ready with{WriteLease=1},"NATIVE_INVALID_STATUS_UNRELEASED",false),
            ("failed-unfinished",failed with{FinishedNs=0},"NATIVE_INVALID_STATUS_UNRELEASED",false),
            ("failed-held",failed with{WriteLease=1},"NATIVE_INVALID_STATUS_UNRELEASED",false),
            ("failed-zero-error",failed with{Error=0},"NATIVE_INVALID_STATUS_UNRELEASED",false),
            ("expired-draining",draining,"NATIVE_EXPIRED_DRAINING_UNRELEASED",false),
            ("expired-publishing",draining with{WriteLease=0},"NATIVE_EXPIRED_DRAINING_UNRELEASED",false),
            ("pending",ready with{State=1,FinishedNs=0,WriteLease=1,Bytes=0},"NATIVE_PENDING_UNRELEASED",false),
            ("copying",ready with{State=2,FinishedNs=0,WriteLease=1,Bytes=0},"NATIVE_PENDING_UNRELEASED",false),
            ("provisional",ready with{State=6,FinishedNs=0,WriteLease=1,Bytes=0},"NATIVE_PENDING_UNRELEASED",false)};
        void Reject(Action action,string name)
        {try{action();}catch(Exception ex)when(ex is IOException or InvalidDataException or InvalidOperationException or SqliteException){check(true,name);return;}throw new Exception("Expected rejection: "+name);}
        LinuxSourceSession Source(LinuxForensicJournal j,string directory)=>new(j,Path.Combine(directory,"bank"),sensor,5,observation.Attribution!.LinuxKernel!.ProviderEpoch,new(0),layoutReplayForTest:true);
        foreach(var test in cases)
        {
            var directory=Path.Combine(root,"native-progress-"+test.Name);using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            var e=s.Admit(raw,new(),observation.ObservedUtc).Record!.Observation;var port=new SnapshotAdmissionChecks.Port(test.Status,snapshot.Bytes.ToArray());
            using var device=s.TakeOpenPermit().OpenForTest(()=>new LinuxActorLeaseDevice(port));
            check(s.Capture(device,e.EventId)==test.Final,"native state has explicit terminal/nonterminal disposition: "+test.Name);
            var progress=j.ReadNativeProgress(e.EventId)!;
            check(progress.Status==test.Status&&progress.Disposition==test.Disposition,"full native tuple/error retained in bounded progress row: "+test.Name);
            var before=progress.ObservedUtc;s.Capture(device,e.EventId);
            check(j.ReadNativeProgress(e.EventId)!.ObservedUtc==before,"unchanged native progress does not invent new observation time: "+test.Name);
            var a=j.Read(e.EventId).Acquisition;
            check(test.Final?a?.Status.Reason==test.Disposition&&a.NativeStatus==test.Status.ToEvidence():a==null,"only finished/released native state becomes finalized unavailable: "+test.Name);
            check(port.Selects==0&&port.Drops==0&&j.ReadSnapshotIntent(e.EventId)==null,"unavailable or pending native state does not SELECT/create snapshot/drop: "+test.Name);
            if(test.Final)
            {
                check(s.Release(device,e.EventId)&&s.Release(device,e.EventId)&&port.Drops==1,"exact terminal requery permits one drop and durable replay prevents another: "+test.Name);
            }
            else
            {
                Reject(()=>s.Release(device,e.EventId),"nonterminal native work cannot authorize release: "+test.Name);
                check(port.Drops==0,"no timeout-based drop for unreleased status: "+test.Name);
                if(test.Name=="expired-draining")
                {
                    port.CurrentStatus=failed with{Error=-110,FinishedNs=ready.DeadlineNs+1};
                    check(s.Capture(device,e.EventId)&&j.Read(e.EventId).Acquisition?.NativeStatus?.State==4,"expired worker finalizes only after observed actual FAILED status");
                    check(s.Release(device,e.EventId)&&port.Drops==1,"drained failure releases only after actual terminal tuple is committed");
                }
            }
            s.Close(new(0));
            if(!test.Final&&test.Name!="expired-draining")check(j.Read(e.EventId).Acquisition is {} closed&&closed.Status.Reason=="ACTOR_COPY_UNAVAILABLE_CONTROLLER_CLOSED"&&closed.NativeStatus==test.Status.ToEvidence(),"actual controller close finalizes retained pending acquisition without inventing native completion: "+test.Name);
        }
        foreach(var which in new[]{"requery-change","drop-exact-change","release-commit-failure"})
        {
            var directory=Path.Combine(root,"native-progress-"+which);using var j=new LinuxForensicJournal(directory,sensor);var s=Source(j,directory);
            var e=s.Admit(raw,new(),observation.ObservedUtc).Record!.Observation;var port=new SnapshotAdmissionChecks.Port(failed,snapshot.Bytes.ToArray());using var device=s.TakeOpenPermit().OpenForTest(()=>new LinuxActorLeaseDevice(port));
            s.Capture(device,e.EventId);
            if(which=="requery-change")port.CurrentStatus=failed with{Error=-12};
            if(which=="drop-exact-change")port.Responses=new(new[]{failed,failed with{Error=-12}});
            if(which=="release-commit-failure")Sql(directory,"CREATE TRIGGER owned_fail_drop BEFORE UPDATE ON work WHEN NEW.drop_state='returned' BEGIN SELECT RAISE(FAIL,'owned release journal failure'); END;");
            Reject(()=>s.Release(device,e.EventId),"terminal release cannot hide mismatch or record failure: "+which);
            var drops=port.Drops;
            check(drops==(which=="release-commit-failure"?1:0)&&s.State.State=="CONTINUITY_FAULTED","release mismatch/failure retains exact native call count and source unknown state: "+which);
            Reject(()=>s.Release(device,e.EventId),"uncertain native release has no automatic numeric-ID retry: "+which);check(port.Drops==drops,"retry rejection never repeats DROP: "+which);s.Close(new(0));
        }
        foreach(var cut in new[]{"native-progress-migration-before-commit","native-progress-migration-after-commit"})
        {
            var directory=Path.Combine(root,cut);using(var j=new LinuxForensicJournal(directory,sensor))j.CommitObservation(raw,observation,new());
            Sql(directory,"DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; DROP TABLE source_reconciliation; DROP TABLE source_control; DROP TABLE native_progress; PRAGMA user_version=4;");
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(NativeProgressChecks).Assembly.Location);
            foreach(var arg in new[]{"migration-child",seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();await FixtureProcessTiming.Wait(child);
            check(child.ExitCode==73,"actual child exit at native progress migration: "+cut+" "+await stdout+await stderr);
            using var migrated=new LinuxForensicJournal(directory,sensor);check(migrated.Read(observation.EventId).Observation==observation&&migrated.ReadNativeProgress(observation.EventId)==null,"schema5 migration recovery retains raw and invents no native progress");
        }
    }
    private static void Sql(string directory,string sql)
    {using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"linux-forensic-intake","journal.db"),Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;q.ExecuteNonQuery();}
}
