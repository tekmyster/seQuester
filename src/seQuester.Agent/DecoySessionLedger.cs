using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using Microsoft.Data.Sqlite;
using RansomFree.Contracts;

// Protected service state. A receipt is a user-session claim, never native attestation.
internal sealed class DecoySessionLedger(string path)
{
    public void SealManagedInterruption(ManagedDecoyJob job,string? sid=null,uint session=0,string? logon=null)
    {
        using var connection=Open();using var t=connection.BeginTransaction();using var cmd=connection.CreateCommand();cmd.Transaction=t;
        cmd.CommandText="SELECT digest,nonce,receipt FROM jobs WHERE id=$id";cmd.Parameters.AddWithValue("$id",job.Job.JobId);string nonce;
        var missing=false;
        using(var r=cmd.ExecuteReader()){missing=!r.Read();if(!missing){if(r.GetString(0)!=Digest(job.Job))throw new InvalidDataException("Retained assignment changed.");if(!r.IsDBNull(2))return;nonce=r.GetString(1);}else nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));}
        cmd.CommandText="CREATE TABLE IF NOT EXISTS managed_interruptions(id TEXT PRIMARY KEY);INSERT OR IGNORE INTO managed_interruptions(id) VALUES($id)";cmd.ExecuteNonQuery();
        if(missing)
        {
            if(sid==null||logon==null||sid!=job.Job.UserSid)throw new InvalidDataException("Retained assignment missing.");DecoyJobsProtocol.Identity(sid,session,logon);
            cmd.CommandText="INSERT INTO jobs VALUES($id,$digest,$sid,$session,$logon,$nonce,$expires,$payload,$receipt)";
            cmd.Parameters.AddWithValue("$digest",Digest(job.Job));cmd.Parameters.AddWithValue("$sid",sid);cmd.Parameters.AddWithValue("$session",session);cmd.Parameters.AddWithValue("$logon",logon);cmd.Parameters.AddWithValue("$nonce",nonce);cmd.Parameters.AddWithValue("$expires",job.ExpiresUtc.ToUnixTimeMilliseconds());cmd.Parameters.AddWithValue("$payload",JsonSerializer.Serialize(job.Job));cmd.Parameters.AddWithValue("$receipt",JsonSerializer.Serialize(new DecoySessionReceipt(job.Job.JobId,nonce,"Unconfirmed")));cmd.ExecuteNonQuery();t.Commit();return;
        }
        cmd.CommandText="UPDATE jobs SET receipt=$receipt WHERE id=$id AND receipt IS NULL";cmd.Parameters.AddWithValue("$receipt",JsonSerializer.Serialize(new DecoySessionReceipt(job.Job.JobId,nonce,"Unconfirmed")));cmd.ExecuteNonQuery();t.Commit();
    }
    public DecoyJobReport? ReadManagedReport(ManagedDecoyJob job)
    {
        if(!File.Exists(path))return null;
        using var connection=Open(true);using var cmd=connection.CreateCommand();
        cmd.CommandText="SELECT digest,sid,session,logon,receipt FROM jobs WHERE id=$id";cmd.Parameters.AddWithValue("$id",job.Job.JobId);
        using var r=cmd.ExecuteReader();if(!r.Read()||r.IsDBNull(4))return null;
        if(r.GetString(0)!=Digest(job.Job))throw new InvalidDataException("Retained job changed.");
        var report=new DecoyJobReport(job.Job.JobId,job.PolicyRevision,r.GetString(1),checked((uint)r.GetInt64(2)),r.GetString(3),DecoySessionProtocol.ReadReceipt(Encoding.UTF8.GetBytes(r.GetString(4))));r.Dispose();
        cmd.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='managed_interruptions'";
        if(Convert.ToInt64(cmd.ExecuteScalar())!=0){cmd.CommandText="SELECT COUNT(*) FROM managed_interruptions WHERE id=$id";if(Convert.ToInt64(cmd.ExecuteScalar())!=0)report=report with{Origin="Broker interruption"};}
        return report;
    }
    static string Digest<T>(T value)=>Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));
    static bool MatchesIssuedAction(DecoySessionJob issued,DecoySessionReceipt receipt)
    {
        if(receipt.State=="Observed")return issued.Action=="observe";
        if(receipt.State!="Applied")return true;
        return issued.Action switch
        {
            "create" or "disable"=>receipt.ResourceState=="Disabled",
            "activate"=>receipt.ResourceState=="Active",
            "retire"=>receipt.ResourceState=="Retired",
            "repair"=>receipt.ResourceState is "Active" or "Disabled",
            _=>false
        };
    }
    SqliteConnection Open(bool readOnly=false)
    {
        var connection=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false,DefaultTimeout=5,Mode=readOnly?SqliteOpenMode.ReadOnly:SqliteOpenMode.ReadWriteCreate}.ToString());
        try
        {
            connection.Open();using var cmd=connection.CreateCommand();cmd.CommandText="PRAGMA user_version";var version=Convert.ToInt32(cmd.ExecuteScalar());
            if(version==0)
            {
                if(readOnly)throw new InvalidDataException("Uninitialized broker ledger preserved.");
                cmd.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidDataException("Unrecognized broker ledger preserved.");
                cmd.CommandText="CREATE TABLE policy(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,digest TEXT NOT NULL); CREATE TABLE jobs(id TEXT PRIMARY KEY,digest TEXT NOT NULL,sid TEXT NOT NULL,session INTEGER NOT NULL,logon TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,payload TEXT NOT NULL,receipt TEXT NULL); PRAGMA user_version=1";cmd.ExecuteNonQuery();
            }
            else if(version!=1)throw new InvalidDataException("Unsupported broker ledger version.");
            return connection;
        }
        catch{connection.Dispose();throw;}
    }
    // Publication preflight is read-only; it never creates or repairs a ledger.
    public void ValidatePublication(DecoySessionPolicy policy)
    {
        DecoySessionProtocol.Validate(policy);using var connection=Open(true);using var transaction=connection.BeginTransaction();
        using(var query=connection.CreateCommand())
        {
            query.Transaction=transaction;query.CommandText="SELECT revision,digest FROM policy WHERE id=1";
            using var reader=query.ExecuteReader();if(reader.Read()&&(policy.Revision<reader.GetInt64(0)||policy.Revision==reader.GetInt64(0)&&Digest(policy)!=reader.GetString(1)))throw new InvalidDataException("Published policy conflicts with retained ledger revision.");
        }
        foreach(var job in policy.Jobs)
        {
            using var query=connection.CreateCommand();query.Transaction=transaction;query.CommandText="SELECT digest FROM jobs WHERE id=$id";query.Parameters.AddWithValue("$id",job.JobId);
            if(query.ExecuteScalar() is string old&&old!=Digest(job))throw new InvalidDataException("Issued job identity cannot be changed by publication.");
        }
        transaction.Commit();
    }
    public DecoySessionReply Handle(DecoySessionPolicy policy,string sid,uint session,string logon,DecoySessionRequest request)
    {
        DecoySessionProtocol.Validate(policy);DecoySessionProtocol.Validate(request);
        using var connection=Open();using var transaction=connection.BeginTransaction();
        SqliteCommand Command(string sql,params (string,object)[] args){var cmd=connection.CreateCommand();cmd.Transaction=transaction;cmd.CommandText=sql;foreach(var (name,value) in args)cmd.Parameters.AddWithValue(name,value);return cmd;}
        var digest=Digest(policy);
        using(var cmd=Command("SELECT revision,digest FROM policy WHERE id=1"))using(var r=cmd.ExecuteReader())if(r.Read()&&(policy.Revision<r.GetInt64(0)||policy.Revision==r.GetInt64(0)&&digest!=r.GetString(1)))throw new InvalidDataException("Session policy rollback or revision reuse refused.");
        using(var cmd=Command("INSERT INTO policy VALUES(1,$revision,$digest) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,digest=excluded.digest",("$revision",policy.Revision),("$digest",digest)))cmd.ExecuteNonQuery();
        if(request is {Operation:"receipt",Receipt:{} receipt})
        {
            DecoySessionProtocol.Validate(receipt);
            using var cmd=Command("SELECT nonce,receipt,payload FROM jobs WHERE id=$id AND sid=$sid AND session=$session AND logon=$logon",("$id",receipt.JobId),("$sid",sid),("$session",session),("$logon",logon));
            string nonce;string? old;DecoySessionJob issued;
            using(var r=cmd.ExecuteReader()){if(!r.Read())return new("Receipt refused");nonce=r.GetString(0);old=r.IsDBNull(1)?null:r.GetString(1);issued=DecoySessionProtocol.ReadJob(Encoding.UTF8.GetBytes(r.GetString(2)));}
            if(!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(nonce),Convert.FromHexString(receipt.Nonce)))return new("Receipt refused");
            if(!MatchesIssuedAction(issued,receipt))return new("Receipt refused");
            var json=JsonSerializer.Serialize(receipt);if(old!=null&&old!=json)return new("Receipt conflict");
            using var save=Command("UPDATE jobs SET receipt=$receipt WHERE id=$id",("$receipt",json),("$id",receipt.JobId));save.ExecuteNonQuery();transaction.Commit();return new("Session result recorded");
        }
        if(request is not {Operation:"poll",Receipt:null})return new("Request refused");
        if(policy.ExpiresUtc<=DateTimeOffset.UtcNow){transaction.Commit();return new("Policy expired");}
        foreach(var job in policy.Jobs.Where(j=>j.UserSid==sid))
        {
            var jobDigest=Digest(job);
            (string Digest,long Session,string Logon,string Nonce,long Expires,string? Receipt)? saved=null;
            using(var prior=Command("SELECT digest,session,logon,nonce,expires,receipt FROM jobs WHERE id=$id",("$id",job.JobId)))using(var r=prior.ExecuteReader())if(r.Read())saved=(r.GetString(0),r.GetInt64(1),r.GetString(2),r.GetString(3),r.GetInt64(4),r.IsDBNull(5)?null:r.GetString(5));
            if(saved is {} priorJob)
            {
                if(priorJob.Digest!=jobDigest)throw new InvalidDataException("Issued job identity cannot change.");
                if(priorJob.Receipt is {} result)
                {
                    var savedReceipt=DecoySessionProtocol.ReadReceipt(Encoding.UTF8.GetBytes(result));
                    if(savedReceipt.State is "Unconfirmed" or "Failed"){transaction.Commit();return new("Session result needs review");}
                    continue;
                }
                if(priorJob.Session!=session||priorJob.Logon!=logon){transaction.Commit();return new("Prior session needs review");}
                var expires=DateTimeOffset.FromUnixTimeMilliseconds(priorJob.Expires);
                var assignment=new DecoySessionAssignment(job,priorJob.Nonce,expires);transaction.Commit();return new(expires<=DateTimeOffset.UtcNow?"Unconfirmed action needs review":"Assignment",assignment);
            }
            using(var count=Command("SELECT COUNT(*) FROM jobs"))if(Convert.ToInt64(count.ExecuteScalar())>=4096)throw new InvalidDataException("Session ledger capacity reached; evidence preserved.");
            var nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));var deadline=DateTimeOffset.UtcNow.AddMinutes(1);if(policy.ExpiresUtc<deadline)deadline=policy.ExpiresUtc;
            deadline=DateTimeOffset.FromUnixTimeMilliseconds(deadline.ToUnixTimeMilliseconds());
            using(var insert=Command("INSERT INTO jobs VALUES($id,$digest,$sid,$session,$logon,$nonce,$expires,$payload,NULL)",("$id",job.JobId),("$digest",jobDigest),("$sid",sid),("$session",session),("$logon",logon),("$nonce",nonce),("$expires",deadline.ToUnixTimeMilliseconds()),("$payload",JsonSerializer.Serialize(job))))insert.ExecuteNonQuery();
            transaction.Commit();return new("Assignment",new(job,nonce,deadline));
        }
        transaction.Commit();return new("No assignments");
    }
}
