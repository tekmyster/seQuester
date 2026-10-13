using Microsoft.Data.Sqlite;
using System.Data.Common;
using RansomFree.Persistence;

namespace RansomFree.Callbacks;

public sealed record CallbackToken(string Id,string Name,string Type,long Created,bool Revoked)
{
    public string? Destination {get;init;}
    public string Location {get;init;}="";
    public string Description {get;init;}="";
    public string Note {get;init;}="";
    public bool EmailAlerts {get;init;}
    public long EmailAfterSequence {get;init;}
}
public sealed record CallbackDetails(string Location="",string Description="",string Note="",bool EmailAlerts=false)
{
    public CallbackDetails Validate()
    {
        static bool Valid(string? value,int max,bool multiline)=>value!=null && value.Length<=max && !value.Any(c=>char.IsControl(c) && !(multiline && c is '\r' or '\n' or '\t'));
        if(!Valid(Location,256,false)||!Valid(Description,1000,true)||!Valid(Note,2000,true))throw new ArgumentException("Location is limited to 256 characters, description to 1,000 and note to 2,000; unsupported control characters are not allowed.");
        return this with{Location=Location.Trim(),Description=Description.Trim(),Note=Note.Trim()};
    }
}
public sealed record CallbackHit(long Sequence,string TokenId,long Received,string Transport,string SourceAddress,string Detail);
public sealed class CallbackStorage
{
    private readonly string registry,inbox;
    private readonly bool receiver;
    private readonly bool sqlServer;
    public CallbackStorage(string directory,bool receiver=false,DatabaseSettings? database=null)
    {
        this.receiver=receiver;
        sqlServer=database?.SqlServer==true;
        if(sqlServer)
        {
            registry=database!.Connection("CallbackRegistry");inbox=database.Connection("CallbackInbox");
            SqlServerSchema.Require(registry,"callback-registry",1);SqlServerSchema.Require(inbox,"callback-inbox",1);
            if(!receiver)SqlServerSchema.Require(registry,"callback-details",1);
            return;
        }
        if(!Path.IsPathFullyQualified(directory))throw new ArgumentException("Callback state directory must be absolute.");
        var registryDirectory=Path.Combine(directory,"registry");var inboxDirectory=Path.Combine(directory,"inbox");
        if(!receiver){Directory.CreateDirectory(registryDirectory);Directory.CreateDirectory(inboxDirectory);}
        registry=new SqliteConnectionStringBuilder{DataSource=Path.Combine(registryDirectory,"tokens.db"),Mode=receiver?SqliteOpenMode.ReadOnly:SqliteOpenMode.ReadWriteCreate,DefaultTimeout=5}.ToString();
        inbox=new SqliteConnectionStringBuilder{DataSource=Path.Combine(inboxDirectory,"hits.db"),Mode=receiver?SqliteOpenMode.ReadWrite:SqliteOpenMode.ReadWriteCreate,DefaultTimeout=5}.ToString();
        if(!receiver)
        {
            using var c=Open(registry);using var cmd=c.CreateCommand();
            cmd.CommandText="CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,type TEXT NOT NULL,created INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS token_options(id TEXT PRIMARY KEY,destination TEXT NOT NULL); CREATE TABLE IF NOT EXISTS token_details(id TEXT PRIMARY KEY,location TEXT NOT NULL,description TEXT NOT NULL,note TEXT NOT NULL,email_alerts INTEGER NOT NULL,email_after INTEGER NOT NULL);";cmd.ExecuteNonQuery();
            using var h=Open(inbox);using var hc=h.CreateCommand();hc.CommandText="PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS hits(sequence INTEGER PRIMARY KEY AUTOINCREMENT,token TEXT NOT NULL,received INTEGER NOT NULL,transport TEXT NOT NULL,source TEXT NOT NULL,detail TEXT NOT NULL); CREATE INDEX IF NOT EXISTS hits_dedup ON hits(token,source,transport,received);";hc.ExecuteNonQuery();
        }
    }
    private DbConnection Open(string connection)=>Relational.Open(sqlServer,connection);
    private static DbCommand Command(DbConnection c,DbTransaction? t,string sql,params (string,object)[] values)=>Relational.Command(c,t,sql,values);
    public static bool ValidId(string? id)=>id is {Length:48} && id.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    public CallbackToken Create(string name,string type,string? destination=null,CallbackDetails? details=null)
    {
        if(receiver)throw new InvalidOperationException("Receiver cannot provision tokens.");
        details=(details??new()).Validate();
        var after=details.EmailAlerts?LatestSequence():0;
        var token=new CallbackToken(Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24)).ToLowerInvariant(),name,type,DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),false){Destination=destination};
        using var c=Open(registry);using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var count=Command(c,t,"SELECT COUNT(*) FROM tokens"))if(Convert.ToInt64(count.ExecuteScalar())>=10000)throw new InvalidOperationException("Token capacity reached.");
        using(var insert=Command(c,t,"INSERT INTO tokens(id,name,type,created) VALUES($id,$name,$type,$created)",("$id",token.Id),("$name",name),("$type",type),("$created",token.Created)))insert.ExecuteNonQuery();
        if(destination!=null){using var option=Command(c,t,"INSERT INTO token_options(id,destination) VALUES($id,$destination)",("$id",token.Id),("$destination",destination));option.ExecuteNonQuery();}
        WriteDetails(c,t,token.Id,details,after);
        t.Commit();return token with{Location=details.Location,Description=details.Description,Note=details.Note,EmailAlerts=details.EmailAlerts,EmailAfterSequence=after};
    }
    public CallbackToken? Get(string id)
    {
        if(!ValidId(id))return null;using var c=Open(registry);
        var query=receiver?"SELECT t.id,t.name,t.type,t.created,t.revoked,o.destination FROM tokens t LEFT JOIN token_options o ON o.id=t.id WHERE t.id=$id":SelectDetails+" WHERE t.id=$id";
        using var cmd=Command(c,null,query,("$id",id));using var r=cmd.ExecuteReader();
        if(!r.Read())return null;
        var token=Read(r) with{Destination=r.IsDBNull(5)?null:r.GetString(5)};
        return receiver?token:ReadDetails(r,token);
    }
    private static CallbackToken Read(DbDataReader r)=>new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetInt64(3),Convert.ToBoolean(r.GetValue(4)));
    public List<CallbackToken> List()
    {
        if(receiver)throw new InvalidOperationException("Receiver cannot list management token details.");
        using var c=Open(registry);using var cmd=Command(c,null,SelectDetails+" ORDER BY t.created DESC,t.id LIMIT 1000");using var r=cmd.ExecuteReader();var list=new List<CallbackToken>();while(r.Read())list.Add(ReadDetails(r,Read(r) with{Destination=r.IsDBNull(5)?null:r.GetString(5)}));return list;
    }
    private const string SelectDetails="SELECT t.id,t.name,t.type,t.created,t.revoked,o.destination,d.location,d.description,d.note,d.email_alerts,d.email_after FROM tokens t LEFT JOIN token_options o ON o.id=t.id LEFT JOIN token_details d ON d.id=t.id";
    private static CallbackToken ReadDetails(DbDataReader r,CallbackToken token)=>token with{Location=r.IsDBNull(6)?"":r.GetString(6),Description=r.IsDBNull(7)?"":r.GetString(7),Note=r.IsDBNull(8)?"":r.GetString(8),EmailAlerts=!r.IsDBNull(9)&&Convert.ToBoolean(r.GetValue(9)),EmailAfterSequence=r.IsDBNull(10)?0:r.GetInt64(10)};
    private static void WriteDetails(DbConnection c,DbTransaction t,string id,CallbackDetails d,long after)
    {
        using(var delete=Command(c,t,"DELETE FROM token_details WHERE id=$id",("$id",id)))delete.ExecuteNonQuery();
        using var insert=Command(c,t,"INSERT INTO token_details(id,location,description,note,email_alerts,email_after) VALUES($id,$location,$description,$note,$email,$after)",("$id",id),("$location",d.Location),("$description",d.Description),("$note",d.Note),("$email",d.EmailAlerts?1:0),("$after",after));insert.ExecuteNonQuery();
    }
    public bool UpdateDetails(string id,CallbackDetails details)
    {
        if(receiver)throw new InvalidOperationException("Receiver cannot edit token details.");
        if(!ValidId(id))return false;details=details.Validate();var latest=LatestSequence();
        using var c=Open(registry);using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        bool enabled=false;long after=0;
        using(var read=Command(c,t,"SELECT t.revoked,d.email_alerts,d.email_after FROM tokens t LEFT JOIN token_details d ON d.id=t.id WHERE t.id=$id",("$id",id)))
        using(var r=read.ExecuteReader()){if(!r.Read())return false;enabled=!r.IsDBNull(1)&&Convert.ToBoolean(r.GetValue(1));after=r.IsDBNull(2)?0:r.GetInt64(2);}
        if(details.EmailAlerts&&!enabled)after=latest;
        WriteDetails(c,t,id,details,after);t.Commit();return true;
    }
    public long LatestSequence()
    {
        using var c=Open(inbox);using var cmd=Command(c,null,"SELECT COALESCE(MAX(sequence),0) FROM hits");return Convert.ToInt64(cmd.ExecuteScalar());
    }
    public bool Revoke(string id)
    {
        if(receiver)throw new InvalidOperationException("Receiver cannot revoke tokens.");
        using var c=Open(registry);using var cmd=Command(c,null,"UPDATE tokens SET revoked=1 WHERE id=$id AND revoked=0",("$id",id));return cmd.ExecuteNonQuery()==1;
    }
    public bool Record(string id,string transport,string address,string detail)
    {
        if(Get(id) is not {Revoked:false})return false;
        if(transport is not ("HTTPS" or "DNS" or "SMTP") || address.Length>64)throw new ArgumentException("Invalid callback metadata.");
        detail=new string(detail.Where(c=>!char.IsControl(c)).Take(256).ToArray());
        using var c=Open(inbox);using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var count=Command(c,t,"SELECT COUNT(*) FROM hits"))if(Convert.ToInt64(count.ExecuteScalar())>=100000)throw new IOException("Callback inbox capacity reached; archive before resuming.");
        var now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        using(var duplicate=Command(c,t,"SELECT COUNT(*) FROM hits WHERE token=$id AND source=$source AND transport=$transport AND received>$since",("$id",id),("$source",address),("$transport",transport),("$since",now-60000)))if(Convert.ToInt64(duplicate.ExecuteScalar())>0)return true;
        using(var insert=Command(c,t,"INSERT INTO hits(token,received,transport,source,detail) VALUES($id,$now,$transport,$source,$detail)",("$id",id),("$now",now),("$transport",transport),("$source",address),("$detail",detail)))insert.ExecuteNonQuery();t.Commit();return true;
    }
    public List<CallbackHit> Hits(long after,int limit=100)
    {
        using var c=Open(inbox);using var cmd=Command(c,null,"SELECT sequence,token,received,transport,source,detail FROM hits WHERE sequence>$after ORDER BY sequence LIMIT $limit",("$after",after),("$limit",Math.Clamp(limit,1,500)));using var r=cmd.ExecuteReader();var list=new List<CallbackHit>();while(r.Read())list.Add(new(r.GetInt64(0),r.GetString(1),r.GetInt64(2),r.GetString(3),r.GetString(4),r.GetString(5)));return list;
    }
}
