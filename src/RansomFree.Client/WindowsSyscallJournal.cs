using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;
using RansomFree.Client.Forensics;

namespace RansomFree.Client;

// Native acknowledgement is allowed only after Put returns. Publication retains
// the same completion ID across crashes; completed rows cannot be re-enriched.
internal sealed class WindowsSyscallJournal:IDisposable
{
    private readonly string connection;
    private readonly string sensor;
    // Retain WAL/index lifetime across fresh operation connections. Closing the
    // last connection on every polling read or commit forces repeated checkpoint
    // and sidecar deletion/recreation. FULL commit durability is unchanged.
    private readonly SqliteConnection lifetime;
    private bool disposed;
    internal WindowsSyscallJournal(string directory,string sensor)
    {
        if(!Guid.TryParseExact(sensor,"N",out var id)||id==Guid.Empty)throw new ArgumentException("Invalid sensor identity");
        this.sensor=sensor;directory=Path.GetFullPath(Path.Combine(directory,"syscall-intake"));EvidenceStore.EnsurePrivate(directory);
        var file=Path.Combine(directory,"syscall-intake-"+sensor+".db");
        foreach(var name in new[]{directory,file,file+"-wal",file+"-shm",file+"-journal"})
            for(string? p=name;p!=null;p=Path.GetDirectoryName(p))
                if(Path.Exists(p)&&(File.GetAttributes(p)&FileAttributes.ReparsePoint)!=0)throw new IOException("Syscall intake cannot traverse links");
        connection=new SqliteConnectionStringBuilder{DataSource=file,Pooling=false,DefaultTimeout=5}.ToString();
        using var c=Open();using var cmd=c.CreateCommand();
        cmd.CommandText="PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS intake(id TEXT PRIMARY KEY,raw BLOB NOT NULL CHECK(length(raw)=408),observation BLOB NOT NULL CHECK(length(observation)<=16384),prepared BLOB CHECK(length(prepared)<=262144),delivered INTEGER NOT NULL DEFAULT 0 CHECK(delivered IN(0,1)));";cmd.ExecuteNonQuery();
        lifetime=Open();
    }
    private SqliteConnection Open(){ObjectDisposedException.ThrowIf(disposed,this);var c=new SqliteConnection(connection);try{c.Open();using var cmd=c.CreateCommand();cmd.CommandText="PRAGMA synchronous=FULL;";cmd.ExecuteNonQuery();return c;}catch{c.Dispose();throw;}}
    public void Dispose(){if(disposed)return;disposed=true;lifetime.Dispose();}
    internal AgentEvent Put(byte[] raw,WindowsSyscallObservation observation)
    {
        Validate(raw,observation);var value=WindowsSyscallEvent.Create(sensor,observation);
        using var c=Open();using var t=c.BeginTransaction();using var cmd=c.CreateCommand();cmd.Transaction=t;
        cmd.CommandText="SELECT raw,observation FROM intake WHERE id=$id";cmd.Parameters.AddWithValue("$id",value.EventId);
        using(var r=cmd.ExecuteReader())if(r.Read()){
            var originalRaw=(byte[])r[0];var original=JsonSerializer.Deserialize<WindowsSyscallObservation>((byte[])r[1])??throw new InvalidDataException("Missing intake observation");
            Validate(originalRaw,original);
            if(!raw.AsSpan().SequenceEqual(originalRaw)||original.SourceInstance!=observation.SourceInstance)throw new InvalidDataException("Syscall ID collision");
            return WindowsSyscallEvent.Create(sensor,original);
        }
        cmd.CommandText="SELECT COUNT(*) FROM intake WHERE delivered=0";cmd.Parameters.Clear();if((long)cmd.ExecuteScalar()!>=8192)throw new IOException("Syscall intake capacity reached; native record retained");
        cmd.CommandText="DELETE FROM intake WHERE id IN (SELECT id FROM intake WHERE delivered=1 ORDER BY rowid DESC LIMIT -1 OFFSET 4096)";cmd.ExecuteNonQuery();
        // Reserve room for the immutable pair before admitting another raw
        // record. Completed tombstones retain only original raw observation.
        cmd.CommandText="SELECT COALESCE(SUM(length(raw)+length(observation)+CASE WHEN delivered=0 THEN 65536 ELSE 0 END),0) FROM intake";
        if((long)cmd.ExecuteScalar()!+81920>128L*1024*1024)throw new IOException("Syscall intake byte capacity reached; native record retained");
        cmd.CommandText="INSERT INTO intake(id,raw,observation) VALUES($id,$raw,$observation)";
        cmd.Parameters.AddWithValue("$id",value.EventId);cmd.Parameters.AddWithValue("$raw",raw);cmd.Parameters.AddWithValue("$observation",JsonSerializer.SerializeToUtf8Bytes(observation));cmd.ExecuteNonQuery();t.Commit();return value;
    }
    private static void Validate(byte[] raw,WindowsSyscallObservation observation)
    {
        var decoded=WindowsSyscallDecoder.Decode(raw);
        if(!observation.IsValid()||JsonSerializer.Serialize(decoded)!=JsonSerializer.Serialize(observation.Native))throw new InvalidDataException("Raw syscall evidence differs from observation");
    }
    internal AgentEvent[] Pending()
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT id,raw,observation FROM intake WHERE delivered=0 ORDER BY rowid LIMIT 32";using var r=cmd.ExecuteReader();var list=new List<AgentEvent>();
        while(r.Read()){
            var o=JsonSerializer.Deserialize<WindowsSyscallObservation>((byte[])r[2])??throw new InvalidDataException("Missing intake observation");Validate((byte[])r[1],o);
            var e=WindowsSyscallEvent.Create(sensor,o);if(e.EventId!=r.GetString(0))throw new InvalidDataException("Intake sensor/event linkage differs");list.Add(e);
        }return list.ToArray();
    }
    internal PreparedForensicPublication? Prepared(string id)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT prepared FROM intake WHERE id=$id";cmd.Parameters.AddWithValue("$id",id);
        if(cmd.ExecuteScalar() is not byte[] bytes)return null;
        var p=JsonSerializer.Deserialize<PreparedForensicPublication>(bytes)??throw new InvalidDataException("Missing prepared evidence");CheckPublication(p,id);return p;
    }
    private static void CheckPublication(PreparedForensicPublication p,string id)
    {
        EventSpool.Encode(p.Original);EventSpool.Encode(p.Completion);
        if(p.Original.EventId!=id||p.Completion.EventId==id||p.Original.Source!="Windows syscall"||p.Completion.Source!="Forensic enrichment"||
            p.Original.Forensics==null||p.Completion.Forensics?.RelatedEventId!=id||!WindowsSyscallObservation.Matches(p.Original)||!WindowsSyscallObservation.Matches(p.Completion)||
            !p.Original.Forensics.IsValid()||!p.Completion.Forensics.IsValid()||
            JsonSerializer.Serialize(p.Original.Attribution)!=JsonSerializer.Serialize(p.Completion.Attribution))throw new InvalidDataException("Prepared syscall publication linkage invalid");
    }
    internal void Prepare(PreparedForensicPublication publication)
    {
        CheckPublication(publication,publication.Original.EventId);var bytes=JsonSerializer.SerializeToUtf8Bytes(publication);
        using var c=Open();using var t=c.BeginTransaction();using var cmd=c.CreateCommand();cmd.Transaction=t;
        cmd.CommandText="SELECT raw,observation,prepared FROM intake WHERE id=$id";cmd.Parameters.AddWithValue("$id",publication.Original.EventId);
        using(var r=cmd.ExecuteReader()){
            if(!r.Read())throw new InvalidDataException("Unjournaled syscall publication");
            var observation=JsonSerializer.Deserialize<WindowsSyscallObservation>((byte[])r[1])!;Validate((byte[])r[0],observation);
            if(JsonSerializer.Serialize(publication.Original.Attribution?.WindowsSyscall)!=JsonSerializer.Serialize(observation))throw new InvalidDataException("Prepared observation changed");
            if(!r.IsDBNull(2)){if(!bytes.AsSpan().SequenceEqual((byte[])r[2]))throw new InvalidDataException("Prepared publication collision");return;}
        }
        cmd.CommandText="UPDATE intake SET prepared=$bytes WHERE id=$id";cmd.Parameters.AddWithValue("$bytes",bytes);cmd.ExecuteNonQuery();t.Commit();
    }
    // Caller has durably enqueued BOTH records before removing local intake.
    internal void Complete(string id)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="UPDATE intake SET delivered=1,prepared=NULL WHERE id=$id AND prepared IS NOT NULL AND delivered=0";cmd.Parameters.AddWithValue("$id",id);
        if(cmd.ExecuteNonQuery()!=1)throw new InvalidDataException("Cannot retire unprepared syscall evidence");
    }
}
