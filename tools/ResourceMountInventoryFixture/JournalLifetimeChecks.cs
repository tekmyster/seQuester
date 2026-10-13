using System.Diagnostics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client.Forensics;

internal static class JournalLifetimeChecks
{
    internal static void Run(string root,bool baseline)
    {
        if(Directory.Exists(root))throw new IOException("Unique resource fixture directory required");
        Directory.CreateDirectory(root);
        var sensor=Guid.NewGuid().ToString("N");var checks=new List<string>();
        void Check(bool value,string label){if(!value)throw new Exception(label);checks.Add(label);}
        var db=Path.Combine(root,"linux-forensic-intake","journal.db");
        SqliteConnection Connection(){var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=db,Pooling=false}.ToString());c.Open();return c;}
        long Scalar(string sql){using var c=Connection();using var q=c.CreateCommand();q.CommandText=sql;return Convert.ToInt64(q.ExecuteScalar());}
        long? Written(){if(!OperatingSystem.IsLinux())return null;return long.Parse(File.ReadLines("/proc/self/io").Single(x=>x.StartsWith("write_bytes:",StringComparison.Ordinal)).Split(':')[1].Trim());}
        using(var journal=new LinuxForensicJournal(root,sensor))
        {
            Check(Scalar("PRAGMA user_version")==12,"existing journal schema unchanged");
            Check(journal.PendingNativeExports(4).Length==0&&journal.PendingNativeImportRetirements().Length==0,"empty export and retirement inventories stay empty");
            if(!baseline)Check(File.Exists(db+"-wal")&&File.Exists(db+"-shm"),"journal lifetime retains WAL/index between fresh operation connections");
            var written=Written();var cpu=Process.GetCurrentProcess().TotalProcessorTime;var elapsed=Stopwatch.StartNew();
            for(var i=0;i<100;i++)if(journal.PendingNativeExports(4).Length!=0||journal.PendingNativeImportRetirements().Length!=0)throw new Exception("Idle polling changed inventory");
            var cpuMs=(Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds;elapsed.Stop();var after=Written();
            var writes=after-written;
            if(!baseline&&writes.HasValue)Check(writes.Value<65536,"100 idle poll pairs do not repeatedly rewrite WAL/index files");
            Check(Scalar("PRAGMA wal_autocheckpoint")==1000,"automatic checkpoint threshold unchanged");
            using(var c=Connection())using(var q=c.CreateCommand()){
                q.CommandText="PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; SELECT 1;";q.ExecuteScalar();
                q.CommandText="PRAGMA synchronous";Check(Convert.ToInt64(q.ExecuteScalar())==2,"FULL write durability remains available");
                q.CommandText="PRAGMA foreign_keys";Check(Convert.ToInt64(q.ExecuteScalar())==1,"foreign key enforcement remains available");
                q.CommandText="CREATE TABLE resource_fixture_state(value INTEGER NOT NULL); INSERT INTO resource_fixture_state VALUES(7);";q.ExecuteNonQuery();
            }
            Check(Scalar("SELECT value FROM resource_fixture_state")==7,"fresh read observes committed external write with lifetime connection held");
            using(var c=Connection())using(var t=c.BeginTransaction())using(var q=c.CreateCommand()){
                q.Transaction=t;q.CommandText="UPDATE resource_fixture_state SET value=9";q.ExecuteNonQuery();t.Rollback();
            }
            Check(Scalar("SELECT value FROM resource_fixture_state")==7,"rolled back external write remains invisible");
            Check(Scalar("SELECT count(*) FROM work")==0,"resource polls create no synthetic file events");
            try{using var other=new LinuxForensicJournal(root,sensor);throw new Exception("Owner lock was bypassed");}catch(IOException){Check(true,"exclusive journal owner remains enforced");}
            File.WriteAllText(Path.Combine(root,"POLL-METRICS.json"),JsonSerializer.Serialize(new{Baseline=baseline,Iterations=100,CpuMilliseconds=cpuMs,ElapsedMilliseconds=elapsed.Elapsed.TotalMilliseconds,PhysicalWriteBytes=writes}));
        }
        Check(!File.Exists(db+"-wal")&&!File.Exists(db+"-shm"),"normal final disposal closes and retires WAL/index");
        using(var reopened=new LinuxForensicJournal(root,sensor)){
            Check(Scalar("SELECT value FROM resource_fixture_state")==7,"committed state survives normal disposal and reopen");
            using var c=Connection();using var q=c.CreateCommand();q.CommandText="PRAGMA integrity_check";Check((string?)q.ExecuteScalar()=="ok","journal integrity after repeated polls and restart");
        }
        var metrics=JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(Path.Combine(root,"POLL-METRICS.json")));
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,BaselineMeasurementOnly=baseline,Checks=checks.Count,ChecksPassed=checks,Metrics=metrics,Root=root,NoNativeActivation=true,NoServiceChanged=true}));
    }
}
