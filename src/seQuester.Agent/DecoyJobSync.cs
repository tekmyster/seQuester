using Microsoft.Data.Sqlite;
using RansomFree.Contracts;
using RansomFree.Client;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

// Called only behind the broker's protected-storage checks. No native action runs here.
internal sealed class DecoyJobLocalStore(string directory,string endpoint)
{
    string PathFor(string name)=>Path.Combine(directory,name);
    DecoySessionLedger Ledger=>new(PathFor("decoy-jobs-session.db"));
    SqliteConnection Open()
    {
        var c=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=PathFor("decoy-jobs.db"),Pooling=false,DefaultTimeout=10}.ToString());
        try
        {
            c.Open();using var cmd=c.CreateCommand();cmd.CommandText="PRAGMA user_version";var version=Convert.ToInt32(cmd.ExecuteScalar());
            if(version==0)
            {
                cmd.CommandText="SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'";if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidDataException("Unknown managed ledger preserved.");
                cmd.CommandText="CREATE TABLE identity(endpoint TEXT NOT NULL);CREATE TABLE jobs(id TEXT PRIMARY KEY,revision INTEGER NOT NULL UNIQUE,payload TEXT NOT NULL,challenge TEXT,observation TEXT,ack INTEGER NOT NULL DEFAULT 0);PRAGMA user_version=1";cmd.ExecuteNonQuery();
                cmd.CommandText="INSERT INTO identity VALUES($endpoint)";cmd.Parameters.AddWithValue("$endpoint",endpoint);cmd.ExecuteNonQuery();
            }
            else if(version!=1)throw new InvalidDataException("Unsupported managed ledger version.");
            cmd.CommandText="SELECT endpoint FROM identity";if(cmd.ExecuteScalar() as string!=endpoint)throw new InvalidDataException("Enrollment changed; retained jobs require review.");return c;
        }
        catch{c.Dispose();throw;}
    }
    public void Cache(ManagedDecoyJob job)
    {
        DecoyJobsProtocol.Validate(job);if(job.EndpointId!=endpoint)throw new InvalidDataException("Job belongs to another endpoint.");
        using var c=Open();using var t=c.BeginTransaction();using var cmd=c.CreateCommand();cmd.Transaction=t;
        cmd.CommandText="SELECT payload FROM jobs WHERE id=$id";cmd.Parameters.AddWithValue("$id",job.Job.JobId);var json=JsonSerializer.Serialize(job);
        if(cmd.ExecuteScalar() is string old){if(old!=json)throw new InvalidDataException("Managed job identity reused.");return;}
        cmd.CommandText="SELECT COUNT(*) FROM jobs WHERE ack=0";if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidDataException("Outstanding local work requires reconciliation first.");
        cmd.CommandText="SELECT COALESCE(MAX(revision),0) FROM jobs";if(Convert.ToInt64(cmd.ExecuteScalar())>=job.PolicyRevision)throw new InvalidDataException("Managed policy rollback refused.");
        cmd.CommandText="SELECT COUNT(*) FROM jobs";if(Convert.ToInt64(cmd.ExecuteScalar())>=4096)throw new InvalidDataException("Managed ledger full; retained evidence preserved.");
        cmd.CommandText="INSERT INTO jobs(id,revision,payload) VALUES($id,$revision,$payload)";cmd.Parameters.AddWithValue("$revision",job.PolicyRevision);cmd.Parameters.AddWithValue("$payload",json);cmd.ExecuteNonQuery();t.Commit();
    }
    public (ManagedDecoyJob Job,string? Challenge,DecoyNativeReport? Observation)? Current()
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText="SELECT payload,challenge,observation FROM jobs WHERE ack=0 ORDER BY revision LIMIT 1";using var r=cmd.ExecuteReader();
        return r.Read()?(JsonSerializer.Deserialize<ManagedDecoyJob>(r.GetString(0))!,r.IsDBNull(1)?null:r.GetString(1),r.IsDBNull(2)?null:JsonSerializer.Deserialize<DecoyNativeReport>(r.GetString(2))):null;
    }
    public DecoyJobReport? Report(ManagedDecoyJob job)=>Ledger.ReadManagedReport(job);
    void Update(string id,string field,object value)
    {
        using var c=Open();using var cmd=c.CreateCommand();cmd.CommandText=$"UPDATE jobs SET {field}=$value WHERE id=$id";cmd.Parameters.AddWithValue("$value",value);cmd.Parameters.AddWithValue("$id",id);if(cmd.ExecuteNonQuery()!=1)throw new InvalidDataException("Managed job missing.");
    }
    public void SetChallenge(ManagedDecoyJob job,string challenge)
    {
        if(!DecoyJobsProtocol.Nonce(challenge))throw new InvalidDataException("Invalid challenge.");var old=Current();if(old?.Job!=job||old?.Challenge is {} prior&&prior!=challenge)throw new InvalidDataException("Challenge changed.");Update(job.Job.JobId,"challenge",challenge);
    }
    public void Acknowledge(ManagedDecoyJob job)=>Update(job.Job.JobId,"ack",1);
    public DecoyJobSessionReply Handle(string sid,uint session,string logon,DecoyJobSessionRequest request)
    {
        DecoyJobsProtocol.Identity(sid,session,logon);var current=Current();if(current is not {} row||row.Job.Job.UserSid!=sid)return new("No managed assignments");
        var job=row.Job;var report=Report(job);
        if(request.Operation=="job-observation"&&request.Receipt==null&&request.Observation is {} observation)
        {
            DecoyJobsProtocol.Validate(observation);
            if(report==null||row.Challenge==null||observation.SessionId!=session||observation.UserSid!=sid||observation.LogonId!=logon||observation.Challenge!=row.Challenge||observation.JobId!=job.Job.JobId||observation.DecoyId!=job.Job.DecoyId||observation.PolicyRevision!=job.PolicyRevision||observation.ObservedUtc<job.ApprovedUtc||observation.ObservedUtc>DateTimeOffset.UtcNow.AddMinutes(1))throw new InvalidDataException("Observation binding mismatch.");
            if(row.Observation!=null&&row.Observation!=observation)throw new InvalidDataException("Conflicting observation preserved.");Update(job.Job.JobId,"observation",JsonSerializer.Serialize(observation));return new("Observation queued");
        }
        if(request.Observation!=null)throw new InvalidDataException("Unexpected observation.");
        if(request.Operation=="job-receipt"&&request.Receipt is {} receipt)
        {
            var reply=Ledger.Handle(new(1,job.PolicyRevision,job.ExpiresUtc,[job.Job]),sid,session,logon,new("receipt",receipt));return new(reply.State);
        }
        if(request.Operation!="job-poll"||request.Receipt!=null)throw new InvalidDataException("Unknown managed request.");
        if(report!=null)
        {
            if(row.Observation!=null)return new("Observation queued");
            return row.Challenge==null?new("Receipt queued"):new("Reconcile",job,Challenge:row.Challenge,SessionId:session,LogonId:logon);
        }
        var offered=Ledger.Handle(new(1,job.PolicyRevision,job.ExpiresUtc,[job.Job]),sid,session,logon,new("poll"));
        if(offered.State is "Prior session needs review" or "Unconfirmed action needs review" or "Policy expired")
        {
            // Receipt and broker-interruption origin are committed together; the action is never replayed.
            Ledger.SealManagedInterruption(job,sid,session,logon);return new("Interrupted job queued for review");
        }
        return new(offered.State,job,offered.Assignment);
    }
}
internal sealed class DecoyJobSync
{
    readonly string directory;readonly string endpoint;readonly ManagementClient client;public readonly DecoyJobLocalStore Store;
    public DecoyJobSync(string directory)
    {
        this.directory=directory;
        var connection=JsonSerializer.Deserialize<AgentConnection>(File.ReadAllText(Path.Combine(directory,"connection.json")))??throw new InvalidDataException("Enrollment missing.");
        endpoint=connection.EndpointId;var credential=Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(connection.ProtectedCredential),null,DataProtectionScope.LocalMachine));
        client=new(connection.Server,credential);Store=new(directory,endpoint);
    }
    public async Task RunOnce(CancellationToken ct)
    {
        if(Store.Current() is {} row)
        {
            if(Store.Report(row.Job) is {} report)
            {
                var ack=await client.SendDecoyReceiptAsync(report,ct);Store.SetChallenge(row.Job,ack.Challenge);
                if(row.Observation is {} observation){await client.SendDecoyObservationAsync(observation,ct);Store.Acknowledge(row.Job);}
            }
        }
        var exchange=await client.PollDecoyJobsAsync(ct);if(exchange.Assignment is {} job)Store.Cache(job);
    }
    public void Dispose()=>client.Dispose();
}
