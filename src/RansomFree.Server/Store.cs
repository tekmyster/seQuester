using System.Data.Common;
using RansomFree.Persistence;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed class EventConflictException : Exception;

public sealed partial class Store
{
    private readonly string connectionString;
    private readonly bool sqlServer;
    public string Provider=>sqlServer?"SqlServer":"Sqlite";
    public Store(string directory,DatabaseSettings? database=null)
    {
        sqlServer=database?.SqlServer==true;
        if(sqlServer){connectionString=database!.Connection("Management");SqlServerSchema.Require(connectionString,"management",1);return;}
        Directory.CreateDirectory(directory);
        connectionString=new SqliteConnectionStringBuilder {DataSource=Path.Combine(directory,"management.db"),ForeignKeys=true,DefaultTimeout=10}.ToString();
        using var c=Open();
        using(var version=c.CreateCommand())
        {
            version.CommandText="PRAGMA user_version";
            if(Convert.ToInt64(version.ExecuteScalar())>6)throw new InvalidOperationException("Database schema is newer than this server. Refusing to modify it.");
        }
        using var command=c.CreateCommand();
        command.CommandText="""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS enrollment(hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS endpoints(id TEXT PRIMARY KEY, credential_hash TEXT UNIQUE NOT NULL, machine TEXT NOT NULL, version TEXT NOT NULL, health TEXT NOT NULL, last_seen INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, endpoint TEXT NOT NULL REFERENCES endpoints(id), event_id TEXT NOT NULL, received INTEGER NOT NULL, payload TEXT NOT NULL, UNIQUE(endpoint,event_id));
            CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_received ON events(received,endpoint);
            -- Count snapshot rows without reading the wide event payload table.
            CREATE INDEX IF NOT EXISTS events_history_sequence ON events(sequence);
            CREATE INDEX IF NOT EXISTS events_history_endpoint ON events(endpoint,sequence);
            -- Process filters scan this compact evidence value rather than
            -- repeatedly decoding each sensor's large forensic payload.
            CREATE INDEX IF NOT EXISTS events_history_endpoint_process ON events(
                endpoint,NULLIF(json_extract(payload,'$.Process'),'') COLLATE BINARY,sequence);
            -- Exact actor filtering must not scan every wide forensic payload
            -- belonging to an endpoint. PID remains a filter, never an identity.
            CREATE INDEX IF NOT EXISTS events_history_pid ON events(
                CAST(json_extract(payload,'$.ProcessId') AS INTEGER),endpoint,sequence);
            CREATE INDEX IF NOT EXISTS events_history_endpoint_notification ON events(
                endpoint,
                CASE WHEN NULLIF(json_extract(payload,'$.Source'),'') COLLATE BINARY IN ('Forensic enrichment','Evidence transfer') OR NULLIF(json_extract(payload,'$.Forensics.Detection.Severity'),'') COLLATE BINARY='informational' THEN 'info'
                     WHEN NULLIF(json_extract(payload,'$.Forensics.Detection.Severity'),'') COLLATE BINARY IN ('normal','alert') THEN 'alert'
                     WHEN NULLIF(json_extract(payload,'$.Forensics.Detection.Severity'),'') COLLATE BINARY IN ('warning','high','critical') THEN NULLIF(json_extract(payload,'$.Forensics.Detection.Severity'),'') COLLATE BINARY ELSE 'unclassified' END,
                CASE WHEN CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) IS NULL THEN 1 ELSE 0 END,
                CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) DESC,sequence DESC,event_id DESC);
            -- Match history's observed-time ordering exactly, including nulls and identity ties.
            -- Timestamp parsing stays out of repeated page loads; replacement payloads update the index.
            CREATE INDEX IF NOT EXISTS events_history_observed_desc ON events(
                CASE WHEN CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) IS NULL THEN 1 ELSE 0 END ASC,
                CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) DESC,sequence DESC,event_id DESC);
            CREATE INDEX IF NOT EXISTS events_history_observed_asc ON events(
                CASE WHEN CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) IS NULL THEN 1 ELSE 0 END ASC,
                CAST(ROUND((julianday(json_extract(payload,'$.ObservedUtc'))-2440587.5)*86400000) AS INTEGER) ASC,sequence DESC,event_id DESC);
            CREATE TABLE IF NOT EXISTS endpoint_contact(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),address TEXT NOT NULL,observed INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,owner TEXT NOT NULL,created INTEGER NOT NULL,payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS reports_owner_created ON reports(owner,created DESC,id DESC);
            CREATE TABLE IF NOT EXISTS endpoint_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE COLLATE NOCASE,revision INTEGER NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS policy_revisions(revision INTEGER PRIMARY KEY AUTOINCREMENT,group_id TEXT NOT NULL REFERENCES endpoint_groups(id),created INTEGER NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS endpoint_groups_binding(endpoint TEXT PRIMARY KEY REFERENCES endpoints(id),group_id TEXT REFERENCES endpoint_groups(id),applied_revision INTEGER,reported INTEGER);
            CREATE INDEX IF NOT EXISTS group_members ON endpoint_groups_binding(group_id);
            CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,version INTEGER NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,creator TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS incident_events(incident TEXT NOT NULL REFERENCES incidents(id),event_sequence INTEGER NOT NULL REFERENCES events(sequence),PRIMARY KEY(incident,event_sequence));
            CREATE TABLE IF NOT EXISTS incident_notes(sequence INTEGER PRIMARY KEY AUTOINCREMENT,incident TEXT NOT NULL REFERENCES incidents(id),time INTEGER NOT NULL,actor TEXT NOT NULL,note TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS incidents_updated ON incidents(updated DESC,id);
            CREATE INDEX IF NOT EXISTS incident_notes_case ON incident_notes(incident,sequence);
            CREATE TABLE IF NOT EXISTS response_commands(id TEXT PRIMARY KEY,endpoint TEXT NOT NULL REFERENCES endpoints(id),payload TEXT NOT NULL,status TEXT NOT NULL,result TEXT,expires INTEGER NOT NULL,reported INTEGER);
            CREATE INDEX IF NOT EXISTS response_commands_pending ON response_commands(endpoint,status,expires);
            CREATE TABLE IF NOT EXISTS incident_assignments(incident TEXT PRIMARY KEY REFERENCES incidents(id),owner TEXT);
            CREATE TABLE IF NOT EXISTS report_schedules(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,days INTEGER NOT NULL,hours INTEGER NOT NULL,next INTEGER NOT NULL,enabled INTEGER NOT NULL,version INTEGER NOT NULL,last_report TEXT,last_error TEXT);
            CREATE INDEX IF NOT EXISTS report_schedules_due ON report_schedules(enabled,next);
            PRAGMA user_version=6;
            """;
        command.ExecuteNonQuery();
        // Precompute the existing displayed action once on insertion/backfill,
        // instead of decoding wide forensic payloads for every page and count.
        var action=HistoryActionExpression(false);
        foreach(var direction in new[]{"asc","desc"})
        {
            var name="events_history_action_"+direction;
            var definition=$"CREATE INDEX {name} ON events(CASE WHEN ({action}) IS NULL THEN 1 ELSE 0 END ASC,({action}) {direction.ToUpperInvariant()},sequence DESC,event_id DESC,endpoint)";
            using var transaction=c.BeginTransaction();using var index=c.CreateCommand();index.Transaction=transaction;
            index.CommandText="SELECT sql FROM sqlite_master WHERE type='index' AND name=$name";var parameter=index.CreateParameter();parameter.ParameterName="$name";parameter.Value=name;index.Parameters.Add(parameter);
            var previous=index.ExecuteScalar() as string;index.Parameters.Clear();
            if(previous?.Replace("IF NOT EXISTS ","",StringComparison.Ordinal)!=definition){
                if(previous!=null){index.CommandText=$"DROP INDEX {name}";index.ExecuteNonQuery();}
                index.CommandText=definition;index.ExecuteNonQuery();
            }
            transaction.Commit();
        }
    }
    private DbConnection Open()=>Relational.Open(sqlServer,connectionString);
    public static string Secret()=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
    private static string Hash(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s)));
    private static long Now()=>DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    private static DbCommand Command(DbConnection c,DbTransaction? t,string sql,params (string,object)[] args)=>Relational.Command(c,t,sql,args);
    private static void Audit(DbConnection c,DbTransaction t,string action,string subject)
    {
        using var cmd=Command(c,t,"INSERT INTO audit(time,action,subject) VALUES($time,$action,$subject)",("$time",Now()),("$action",action),("$subject",subject));cmd.ExecuteNonQuery();
    }
    public EnrollmentCodeResponse CreateCode(string actor="bootstrap administrator")
    {
        var code=Secret();var expires=DateTimeOffset.UtcNow.AddMinutes(15);
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var clean=Command(c,t,"DELETE FROM enrollment WHERE expires<$now",("$now",Now())))clean.ExecuteNonQuery();
        using(var cmd=Command(c,t,"INSERT INTO enrollment(hash,expires) VALUES($hash,$expires)",("$hash",Hash(code)),("$expires",expires.ToUnixTimeMilliseconds())))cmd.ExecuteNonQuery();
        Audit(c,t,"Enrollment code issued",actor);t.Commit();
        return new(code,expires);
    }
    public EnrollmentResponse? Enroll(EnrollmentRequest request)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var consume=Command(c,t,"DELETE FROM enrollment WHERE hash=$hash AND expires>$now",("$hash",Hash(request.Code)),("$now",Now()));
        if(consume.ExecuteNonQuery()!=1)return null;
        var id=Guid.NewGuid().ToString("N");var credential=Secret();
        using(var insert=Command(c,t,"INSERT INTO endpoints(id,credential_hash,machine,version,health,last_seen) VALUES($id,$hash,$machine,$version,'Enrolled',$now)",("$id",id),("$hash",Hash(credential)),("$machine",request.MachineName),("$version",request.AgentVersion),("$now",Now())))insert.ExecuteNonQuery();
        Audit(c,t,"Endpoint enrolled",id);t.Commit();return new(id,credential);
    }
    public string? Authenticate(string credential)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT id FROM endpoints WHERE credential_hash=$hash AND revoked=0",("$hash",Hash(credential)));
        return cmd.ExecuteScalar() as string;
    }
    public bool Heartbeat(string id,HeartbeatRequest request)=>Heartbeat(id,request,null);
    public bool Heartbeat(string id,HeartbeatRequest request,System.Net.IPAddress? address)
    {
        if(request.OperatingSystem is not (null or "windows" or "linux" or "macos" or "unknown"))throw new ArgumentException("Invalid endpoint platform.");
        if(request.Protection!=null&&!request.Protection.IsValid())throw new ArgumentException("Invalid endpoint protection report.");
        if(address!=null&&sqlServer)SqlServerSchema.Require(connectionString,"endpoint-contact",1);
        var platform=HasPlatformStorage();if(request.OperatingSystem!=null&&!platform){InitializePlatformStorage();platform=true;}
        var protection=HasProtectionStorage();if(request.Protection!=null&&!protection){InitializeProtectionStorage();protection=true;}
        using var c=Open();using var transaction=c.BeginTransaction();using var cmd=Command(c,transaction,"UPDATE endpoints SET version=$version,health=$health,last_seen=$now WHERE id=$id AND revoked=0",("$id",id),("$version",request.AgentVersion),("$health",request.Health),("$now",Now()));if(cmd.ExecuteNonQuery()!=1)return false;
        if(platform)
        {
            using var update=Command(c,transaction,"UPDATE endpoint_platform SET os=$os WHERE endpoint=$id",("$id",id),("$os",request.OperatingSystem??"unknown"));
            if(update.ExecuteNonQuery()==0){using var insert=Command(c,transaction,"INSERT INTO endpoint_platform(endpoint,os) VALUES($id,$os)",("$id",id),("$os",request.OperatingSystem??"unknown"));insert.ExecuteNonQuery();}
        }
        if(protection&&request.Protection is {} reported)
        {
            using var update=Command(c,transaction,"UPDATE endpoint_protection SET deployed_items=$items,monitoring_state=$state,reported=$now WHERE endpoint=$id",("$id",id),("$items",reported.DeployedCanaryAndHoneypotFiles),("$state",reported.MonitoringState),("$now",Now()));
            if(update.ExecuteNonQuery()==0){using var insert=Command(c,transaction,"INSERT INTO endpoint_protection(endpoint,deployed_items,monitoring_state,reported) VALUES($id,$items,$state,$now)",("$id",id),("$items",reported.DeployedCanaryAndHoneypotFiles),("$state",reported.MonitoringState),("$now",Now()));insert.ExecuteNonQuery();}
        }
        WriteContact(c,transaction,id,address);
        transaction.Commit();return true;
    }
    public BatchReceipt? Ingest(string id,EventBatch batch)=>Ingest(id,batch,null);
    public BatchReceipt? Ingest(string id,EventBatch batch,System.Net.IPAddress? address)
    {
        if(batch.Events.Any(e=>e.ServiceContext!=null||e.Source is "Server service decoy" or "Evidence transfer"||e.Forensics?.Transfer!=null))throw new ArgumentException("Server-generated evidence cannot be submitted by endpoints.");
        if(address!=null&&sqlServer)SqlServerSchema.Require(connectionString,"endpoint-contact",1);
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var active=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",id)))
            if(Convert.ToInt64(active.ExecuteScalar())!=1)return null;
        int accepted=0;
        foreach(var item in batch.Events)
        {
            var payload=JsonSerializer.Serialize(item);
            using(var existing=Command(c,t,"SELECT payload FROM events WHERE endpoint=$id AND event_id=$event",("$id",id),("$event",item.EventId)))
            {
                if(existing.ExecuteScalar() is string prior)
                {
                    if(prior!=payload)throw new EventConflictException();
                    continue;
                }
            }
            using var cmd=Command(c,t,"INSERT INTO events(endpoint,event_id,received,payload) VALUES($id,$event,$now,$payload)",("$id",id),("$event",item.EventId),("$now",Now()),("$payload",payload));
            accepted+=cmd.ExecuteNonQuery();
        }
        WriteContact(c,t,id,address);
        t.Commit();return new(accepted,batch.Events.Length-accepted);
    }
    public bool Revoke(string id,string actor="bootstrap administrator")
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var cmd=Command(c,t,"UPDATE endpoints SET revoked=1 WHERE id=$id AND revoked=0",("$id",id));
        var changed=cmd.ExecuteNonQuery()==1;if(changed)Audit(c,t,"Endpoint revoked",actor+":"+id);t.Commit();return changed;
    }
    public void CancelEnrollmentCode(string code,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using var cmd=Command(c,t,"DELETE FROM enrollment WHERE hash=$hash",("$hash",Hash(code)));
        if(cmd.ExecuteNonQuery()==1)Audit(c,t,"Unused enrollment code cancelled",actor);
        t.Commit();
    }
    public IReadOnlyList<ManagementAuditEntry> ManagementAudit()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT sequence,time,action,subject FROM audit ORDER BY sequence DESC LIMIT 100");
        using var r=cmd.ExecuteReader();var entries=new List<ManagementAuditEntry>();
        while(r.Read())entries.Add(new(r.GetInt64(0),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(1)),r.GetString(2),r.GetString(3)));
        return entries;
    }
    public List<EndpointSummary> Inventory()
    {
        var platform=HasPlatformStorage();var protection=HasProtectionStorage();using var c=Open();var sql="SELECT e.id,e.machine,e.version,e.health,e.last_seen,e.revoked,"+(platform?"p.os":"NULL")+","+(protection?"q.deployed_items,q.monitoring_state":"NULL,NULL")+" FROM endpoints e "+(platform?"LEFT JOIN endpoint_platform p ON p.endpoint=e.id ":"")+(protection?"LEFT JOIN endpoint_protection q ON q.endpoint=e.id ":"")+"ORDER BY e.last_seen DESC,e.id LIMIT 1000";using var cmd=Command(c,null,sql);using var r=cmd.ExecuteReader();var result=new List<EndpointSummary>();
        while(r.Read())result.Add(new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetString(3),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(4)),Convert.ToBoolean(r.GetValue(5))){OperatingSystem=r.IsDBNull(6)?null:r.GetString(6),Protection=r.IsDBNull(7)?null:new(r.GetInt32(7),r.GetString(8))});return result;
    }
    public List<StoredEvent> Events(long after,int limit)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT sequence,endpoint,received,payload FROM events WHERE sequence>$after ORDER BY sequence LIMIT $limit",("$after",after),("$limit",limit));using var r=cmd.ExecuteReader();var result=new List<StoredEvent>();
        while(r.Read())result.Add(new(r.GetInt64(0),r.GetString(1),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)),JsonSerializer.Deserialize<AgentEvent>(r.GetString(3))!));return result;
    }
}
