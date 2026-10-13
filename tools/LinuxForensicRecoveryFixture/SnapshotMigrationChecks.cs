using System.Diagnostics;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Client.Forensics;
using RansomFree.Contracts;

static class SnapshotMigrationChecks
{
    internal static async Task Run(string root,string sensor,byte[] raw,AgentEvent observation,LinuxActorSnapshot snapshot,string seedPath,Action<bool,string> check)
    {
        foreach(var version in new[]{1,2})foreach(var cut in new[]{"migration-before-commit","migration-after-commit"})
        {
            var directory=Path.Combine(root,"snapshot-schema-"+version+"-"+cut);
            LinuxForensicJournal.SnapshotIntent? before=null;
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                journal.CommitObservation(raw,observation,new());
                if(version==2){using var admission=journal.AdmitSnapshot(observation.EventId,snapshot.NativeStatus);before=journal.ReadSnapshotIntent(observation.EventId);}
            }
            var connection=new SqliteConnectionStringBuilder{DataSource=Path.Combine(directory,"linux-forensic-intake","journal.db"),Pooling=false}.ToString();
            using(var c=new SqliteConnection(connection))
            {
                c.Open();using var t=c.BeginTransaction();using var q=c.CreateCommand();q.Transaction=t;
                var lifecycleDrop="DROP TABLE source_owner_returns; DROP TABLE source_activation; DROP TABLE native_pins; DROP TABLE source_ingress; DROP TABLE canonical_events; DROP TABLE source_ownership; DROP TABLE source_policy; DROP TABLE source_bank_formats; DROP TABLE source_reconciliation; DROP TABLE source_control; DROP TABLE native_progress; DROP TABLE source_boundaries; DROP TABLE source_lifecycle; DROP TABLE source_banks; ";
                q.CommandText=lifecycleDrop+(version==1?"DROP TABLE snapshot_intents; PRAGMA user_version=1;":"""
                    CREATE TABLE snapshot_intents_v2(event_id TEXT PRIMARY KEY REFERENCES work(event_id),snapshot_id TEXT NOT NULL UNIQUE,
                      expected_status BLOB NOT NULL,reserved_file BLOB NOT NULL,verified_hash TEXT,verified_file BLOB,
                      state TEXT NOT NULL DEFAULT 'write-intent' CHECK(state IN ('write-intent','bytes-verified','manifest-committed','unavailable')));
                    INSERT INTO snapshot_intents_v2 SELECT * FROM snapshot_intents;
                    DROP TABLE snapshot_intents;
                    ALTER TABLE snapshot_intents_v2 RENAME TO snapshot_intents;
                    PRAGMA user_version=2;
                    """);
                q.ExecuteNonQuery();t.Commit();
            }
            var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardError=true,RedirectStandardOutput=true};
            if(string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath),"dotnet",StringComparison.OrdinalIgnoreCase))start.ArgumentList.Add(typeof(SnapshotMigrationChecks).Assembly.Location);
            foreach(var arg in new[]{"migration-child",seedPath,directory,cut})start.ArgumentList.Add(arg);
            using var child=Process.Start(start)!;var output=child.StandardOutput.ReadToEndAsync();var errors=child.StandardError.ReadToEndAsync();
            await FixtureProcessTiming.Wait(child);File.WriteAllText(Path.Combine(root,"migration-"+version+"-"+cut+".log"),await output+await errors);
            check(child.ExitCode==73,"actual process exit during schema "+version+" upgrade: "+cut);
            using(var c=new SqliteConnection(connection))
            {
                c.Open();using var q=c.CreateCommand();q.CommandText="PRAGMA user_version;";
                check(Convert.ToInt64(q.ExecuteScalar())==(cut=="migration-before-commit"?version:3),"migration crash retains atomic old/new schema version: "+version+"/"+cut);
                q.CommandText="SELECT count(*) FROM sqlite_master WHERE name='snapshot_intents_v3';";
                check(Convert.ToInt64(q.ExecuteScalar())==0,"no partially migrated temporary table survives process exit");
            }
            using(var journal=new LinuxForensicJournal(directory,sensor))
            {
                check(journal.Read(observation.EventId).Observation==observation,"raw event remains identical after migration recovery");
                check(version==1?journal.ReadSnapshotIntent(observation.EventId)==null:journal.ReadSnapshotIntent(observation.EventId)==before,"snapshot intent remains absent or byte-equivalent to older schema receipt");
            }
        }
    }
}
