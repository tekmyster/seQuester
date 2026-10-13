using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Client;
using RansomFree.Contracts;

internal static class QueueLifetimeChecks
{
    internal static void Run(string root,bool baseline)
    {
        if(Directory.Exists(root))throw new IOException("Unique queue fixture root required");
        Directory.CreateDirectory(root);
        var sensor=Guid.NewGuid().ToString("N");var db=Path.Combine(root,"events-"+sensor+".db");
        var checks=new List<string>();
        void Check(bool ok,string label){if(!ok)throw new Exception(label);checks.Add(label);}
        var retain=OperatingSystem.IsLinux()&&!baseline;
        EventSpool Queue()=>new(root,sensor,retain);
        AgentEvent Event()=>new(Guid.NewGuid().ToString("N"),DateTimeOffset.UtcNow,"fixture-read","/fixture-target",null,null,null,"queue-lifetime-fixture");
        long? Written()=>OperatingSystem.IsLinux()?long.Parse(File.ReadLines("/proc/self/io").Single(x=>x.StartsWith("write_bytes:",StringComparison.Ordinal)).Split(':')[1].Trim()):null;
        long Scalar(string sql){using var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=db,Pooling=false}.ToString());c.Open();using var q=c.CreateCommand();q.CommandText=sql;return Convert.ToInt64(q.ExecuteScalar());}
        object metrics;
        using(var queue=Queue())
        {
            Check(Scalar("PRAGMA user_version")==4,"existing queue schema unchanged");
            Check(queue.Count==0&&queue.Peek().Events.Length==0,"empty inventories remain empty");
            if(retain)Check(File.Exists(db+"-wal")&&File.Exists(db+"-shm"),"owned queue keeps WAL/index lifetime between polls");
            var written=Written();var cpu=Process.GetCurrentProcess().TotalProcessorTime;var elapsed=Stopwatch.StartNew();
            for(var i=0;i<100;i++)if(queue.Status.Pending!=0||queue.Peek().Events.Length!=0)throw new Exception("Idle queue poll changed evidence");
            var cpuMs=(Process.GetCurrentProcess().TotalProcessorTime-cpu).TotalMilliseconds;elapsed.Stop();var writes=Written()-written;
            if(retain)Check(writes.HasValue&&writes.Value<65536,"100 idle poll pairs avoid repeated WAL/index physical writes");
            metrics=new{BaselineMeasurementOnly=baseline,Iterations=100,CpuMilliseconds=cpuMs,ElapsedMilliseconds=elapsed.Elapsed.TotalMilliseconds,PhysicalWriteBytes=writes};
            var open=typeof(EventSpool).GetMethod("Open",BindingFlags.NonPublic|BindingFlags.Instance)!;
            using(var c=(SqliteConnection)open.Invoke(queue,null)!)using(var q=c.CreateCommand())
            {
                q.CommandText="PRAGMA synchronous";Check(Convert.ToInt64(q.ExecuteScalar())==2,"actual operation connections keep FULL durability");
                q.CommandText="PRAGMA foreign_keys";Check(Convert.ToInt64(q.ExecuteScalar())==1,"actual operation connections keep foreign keys enabled");
                q.CommandText="PRAGMA wal_autocheckpoint";Check(Convert.ToInt64(q.ExecuteScalar())==1000,"checkpoint threshold unchanged");
            }
            var item=Event();queue.Enqueue(item);var saved=EventSpool.Encode(item);
            Check(queue.Status.Pending==1&&queue.Status.PayloadBytes==saved.Length,"committed evidence counters exact");
            queue.Enqueue(item);Check(queue.Count==1,"identical replay is idempotent");
            try{queue.Enqueue(item with{Operation="different"});throw new Exception("Conflict accepted");}catch(InvalidOperationException){Check(queue.Count==1,"conflicting event retained without replacement");}
            var batch=queue.Peek();try{queue.Acknowledge(batch,new(0,0));throw new Exception("Invalid receipt accepted");}catch(InvalidDataException){Check(queue.Count==1,"invalid receipt cannot remove evidence");}
            using(var other=Queue())
            {
                Check(other.Count==1&&EventSpool.Encode(other.Peek().Events[0]).AsSpan().SequenceEqual(saved),"second queue owner sees exact committed bytes");
                var second=Event();other.Enqueue(second);Check(queue.Count==2,"fresh polls observe another owner's commit");
                using(var c=(SqliteConnection)open.Invoke(queue,null)!)using(var t=c.BeginTransaction())using(var q=c.CreateCommand())
                {
                    q.Transaction=t;q.CommandText="UPDATE queue_state SET pending=99 WHERE id=1";q.ExecuteNonQuery();t.Rollback();
                }
                Check(queue.Count==2,"rolled back transaction stays invisible");
                other.Dispose();Check(queue.Count==2,"one owner closes without breaking the remaining owner");
            }
            Parallel.For(0,4,_=>{for(var n=0;n<50;n++)if(queue.Status.Pending!=2||queue.Peek().Events.Length!=2)throw new Exception("Concurrent inventory changed");});
            Check(queue.Count==2,"concurrent fresh readers preserve evidence and counters");
            queue.Acknowledge(queue.Peek(),new(2,0));Check(queue.Count==0&&queue.Status.PayloadBytes==0,"valid exact-prefix receipt retires both events");
            queue.Enqueue(item);Check(queue.Count==1,"event requeued for restart persistence check");
        }
        Check(!File.Exists(db+"-wal")&&!File.Exists(db+"-shm"),"last owner disposal retires WAL/index normally");
        using(var reopened=Queue())
        {
            Check(reopened.Count==1,"committed evidence survives owner disposal and reopen");
            reopened.Dispose();reopened.Dispose();
            try{_=reopened.Status;throw new Exception("Disposed queue reopened");}catch(ObjectDisposedException){Check(true,"disposed queue refuses reads");}
            try{reopened.Configure(new());throw new Exception("Disposed queue configured");}catch(ObjectDisposedException){Check(true,"disposed queue refuses configuration");}
        }
        using(var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=db,Pooling=false}.ToString()))
        {c.Open();using var q=c.CreateCommand();q.CommandText="PRAGMA integrity_check";Check((string?)q.ExecuteScalar()=="ok","queue integrity after polling, concurrency and restart");}
        if(!OperatingSystem.IsLinux())
        {try{using var wrong=new EventSpool(root,sensor,true);throw new Exception("Non-Linux retention admitted");}catch(PlatformNotSupportedException){Check(true,"non-Linux retention refused; legacy constructor unchanged");}}
        Console.WriteLine(JsonSerializer.Serialize(new{Passed=true,BaselineMeasurementOnly=baseline,Checks=checks.Count,ChecksPassed=checks,Metrics=metrics,Root=root,NoNativeActivation=true,NoServiceChanged=true}));
    }
}
