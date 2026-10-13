using System.Data.Common;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using RansomFree.Contracts;
namespace RansomFree.Server;

public sealed record ApproveDecoyJob(string EndpointId,DecoySessionJob Job,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed record ReviewDecoyJob(string EndpointId,string JobId,long PolicyRevision,string ObservationDigest,string Reason,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed record DecoyJobHistory(string JobId,string EndpointId,string State,ManagedDecoyJob Assignment,string? Receipt,string? Observation)
{public string? ObservationDigest=>Observation==null?null:DecoyJobsProtocol.Digest(JsonSerializer.Deserialize<DecoyNativeReport>(Observation)!);}
public sealed class DecoyJobConflictException:Exception;
public sealed partial class Store
{
    public void InitializeDecoyJobs()
    {
        if(sqlServer){RansomFree.Persistence.SqlServerSchema.Require(connectionString,"decoy-jobs",1);return;}
        using var c=Open();using var cmd=Command(c,null,"""
            CREATE TABLE IF NOT EXISTS decoy_jobs(id TEXT PRIMARY KEY,endpoint TEXT NOT NULL REFERENCES endpoints(id),revision INTEGER NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT,observation TEXT,challenge TEXT,UNIQUE(endpoint,revision));
            CREATE TABLE IF NOT EXISTS decoy_job_history(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL REFERENCES decoy_jobs(id),kind TEXT NOT NULL,created INTEGER NOT NULL,actor TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(id,kind));
            """);cmd.ExecuteNonQuery();
    }
    static void JobHistory(DbConnection c,DbTransaction t,string id,string kind,string actor,object value)
    {
        using var cmd=Command(c,t,"INSERT INTO decoy_job_history(id,kind,created,actor,payload) VALUES($id,$kind,$now,$actor,$payload)",("$id",id),("$kind",kind),("$now",Now()),("$actor",actor),("$payload",JsonSerializer.Serialize(value)));cmd.ExecuteNonQuery();
    }
    static void LockDecoyEndpoint(DbConnection c,DbTransaction t,string endpoint)
    {
        // Obtain the same write lock before any read on every coordinator path, including SQL Server.
        using var cmd=Command(c,t,"UPDATE endpoints SET revoked=revoked WHERE id=$id AND revoked=0",("$id",endpoint));
        if(cmd.ExecuteNonQuery()!=1)throw new KeyNotFoundException("Endpoint unavailable.");
    }
    public ManagedDecoyJob ApproveDecoy(ApproveDecoyJob body,string actor)
    {
        DecoySessionProtocol.Validate(body.Job);if(!DecoyJobsProtocol.Id(body.EndpointId))throw new ArgumentException("Endpoint required.");InitializeDecoyJobs();
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);LockDecoyEndpoint(c,t,body.EndpointId);
        using(var read=Command(c,t,"SELECT payload FROM decoy_jobs WHERE id=$id",("$id",body.Job.JobId)))if(read.ExecuteScalar() is string old)
        {
            var prior=JsonSerializer.Deserialize<ManagedDecoyJob>(old)!;if(prior.EndpointId!=body.EndpointId||prior.Job!=body.Job)throw new DecoyJobConflictException();return prior;
        }
        using(var count=Command(c,t,"SELECT COUNT(*) FROM decoy_jobs"))if(Convert.ToInt64(count.ExecuteScalar())>=10000)throw new InvalidOperationException("Job history full; evidence preserved.");
        long revision;using(var max=Command(c,t,"SELECT COALESCE(MAX(revision),0) FROM decoy_jobs WHERE endpoint=$endpoint",("$endpoint",body.EndpointId)))revision=checked(Convert.ToInt64(max.ExecuteScalar())+1);
        var now=DateTimeOffset.UtcNow;var job=new ManagedDecoyJob(body.EndpointId,revision,now,now.AddDays(7),body.Job);
        using(var insert=Command(c,t,"INSERT INTO decoy_jobs(id,endpoint,revision,payload,state) VALUES($id,$endpoint,$revision,$payload,'Pending')",("$id",body.Job.JobId),("$endpoint",body.EndpointId),("$revision",revision),("$payload",JsonSerializer.Serialize(job))))insert.ExecuteNonQuery();
        JobHistory(c,t,body.Job.JobId,"Approved",actor,job);t.Commit();return job;
    }
    public DecoyJobExchange PollDecoyJobs(string endpoint)
    {
        InitializeDecoyJobs();using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);LockDecoyEndpoint(c,t,endpoint);
        using(var unresolved=Command(c,t,"SELECT COUNT(*) FROM decoy_jobs WHERE endpoint=$endpoint AND state='Needs review'",("$endpoint",endpoint)))if(Convert.ToInt64(unresolved.ExecuteScalar())!=0){t.Commit();return new(null);}
        var pending=new List<(ManagedDecoyJob Job,string State)>();
        using(var read=Command(c,t,"SELECT payload,state FROM decoy_jobs WHERE endpoint=$endpoint AND state IN ('Pending','Offered','Receipt') ORDER BY revision",("$endpoint",endpoint)))using(var r=read.ExecuteReader())while(r.Read())pending.Add((JsonSerializer.Deserialize<ManagedDecoyJob>(r.GetString(0))!,r.GetString(1)));
        foreach(var (job,state) in pending)
        {
            // Once offered, do not silently release a job on expiry. It may have executed offline.
            if(state=="Pending"&&job.ExpiresUtc<=DateTimeOffset.UtcNow)
            {
                using var expire=Command(c,t,"UPDATE decoy_jobs SET state='Expired' WHERE id=$id",("$id",job.Job.JobId));expire.ExecuteNonQuery();JobHistory(c,t,job.Job.JobId,"Expired","coordinator",job);continue;
            }
            if(state=="Pending")
            {
                using var offer=Command(c,t,"UPDATE decoy_jobs SET state='Offered' WHERE id=$id",("$id",job.Job.JobId));offer.ExecuteNonQuery();JobHistory(c,t,job.Job.JobId,"Offered",endpoint,job);
            }
            t.Commit();return new(job);
        }
        t.Commit();return new(null);
    }
    public DecoyReportAcknowledgement ReceiveDecoyReport(string endpoint,DecoyJobReport report)
    {
        DecoyJobsProtocol.Validate(report);InitializeDecoyJobs();using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);LockDecoyEndpoint(c,t,endpoint);
        ManagedDecoyJob job;string state;string? prior,challenge;
        using(var read=Command(c,t,"SELECT payload,state,receipt,challenge FROM decoy_jobs WHERE id=$id AND endpoint=$endpoint",("$id",report.JobId),("$endpoint",endpoint)))using(var r=read.ExecuteReader())
        {if(!r.Read())throw new KeyNotFoundException();job=JsonSerializer.Deserialize<ManagedDecoyJob>(r.GetString(0))!;state=r.GetString(1);prior=r.IsDBNull(2)?null:r.GetString(2);challenge=r.IsDBNull(3)?null:r.GetString(3);}
        if(job.PolicyRevision!=report.PolicyRevision||job.Job.UserSid!=report.UserSid)throw new DecoyJobConflictException();
        var json=JsonSerializer.Serialize(report);if(prior!=null){if(prior!=json)throw new DecoyJobConflictException();return new(state,challenge!);}
        if(state!="Offered")throw new DecoyJobConflictException();
        var receipt=report.Receipt;
        if(receipt.State=="Observed"&&job.Job.Action!="observe"||receipt.State=="Applied"&&(job.Job.Action switch{"create" or "disable"=>receipt.ResourceState!="Disabled","activate"=>receipt.ResourceState!="Active","retire"=>receipt.ResourceState!="Retired","repair"=>receipt.ResourceState is not ("Active" or "Disabled"),_=>true}))throw new DecoyJobConflictException();
        challenge=Secret();using(var update=Command(c,t,"UPDATE decoy_jobs SET state='Receipt',receipt=$receipt,challenge=$challenge WHERE id=$id",("$receipt",json),("$challenge",challenge),("$id",report.JobId)))update.ExecuteNonQuery();
        JobHistory(c,t,report.JobId,"User receipt",endpoint,report);t.Commit();return new("Receipt",challenge);
    }
    public void ReceiveDecoyObservation(string endpoint,DecoyNativeReport report)
    {
        DecoyJobsProtocol.Validate(report);InitializeDecoyJobs();using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);LockDecoyEndpoint(c,t,endpoint);
        ManagedDecoyJob job;DecoyJobReport receipt;string challenge;string? old;
        using(var read=Command(c,t,"SELECT payload,receipt,challenge,observation FROM decoy_jobs WHERE id=$id AND endpoint=$endpoint",("$id",report.JobId),("$endpoint",endpoint)))using(var r=read.ExecuteReader())
        {if(!r.Read()||r.IsDBNull(1))throw new DecoyJobConflictException();job=JsonSerializer.Deserialize<ManagedDecoyJob>(r.GetString(0))!;receipt=JsonSerializer.Deserialize<DecoyJobReport>(r.GetString(1))!;challenge=r.GetString(2);old=r.IsDBNull(3)?null:r.GetString(3);}
        var json=JsonSerializer.Serialize(report);if(old!=null){if(old!=json)throw new DecoyJobConflictException();return;}
        using(var issued=Command(c,t,"SELECT created FROM decoy_job_history WHERE id=$id AND kind='User receipt'",("$id",report.JobId)))if(report.ObservedUtc.ToUnixTimeMilliseconds()<Convert.ToInt64(issued.ExecuteScalar())-60000)throw new DecoyJobConflictException();
        if(job.Job.DecoyId!=report.DecoyId||job.PolicyRevision!=report.PolicyRevision||job.Job.UserSid!=report.UserSid||challenge!=report.Challenge||report.ObservedUtc<job.ApprovedUtc||report.ObservedUtc>DateTimeOffset.UtcNow.AddMinutes(1))throw new DecoyJobConflictException();
        var confirmed=report.State is "Active" or "Disabled" or "Retired" && receipt.SessionId==report.SessionId&&receipt.LogonId==report.LogonId;
        if(receipt.Receipt.State is "Applied" or "Observed")confirmed &= report.Revision==receipt.Receipt.Revision&&report.State==receipt.Receipt.ResourceState;
        else confirmed=false;
        using(var update=Command(c,t,"UPDATE decoy_jobs SET state=$state,observation=$observation WHERE id=$id",("$state",confirmed?"Reconciled":"Needs review"),("$observation",json),("$id",report.JobId)))update.ExecuteNonQuery();
        JobHistory(c,t,report.JobId,"Native session observation",endpoint,report);t.Commit();
    }
    public IReadOnlyList<DecoyJobHistory> DecoyJobsHistory()
    {
        InitializeDecoyJobs();using var c=Open();using var read=Command(c,null,"SELECT id,endpoint,state,payload,receipt,observation FROM decoy_jobs ORDER BY endpoint,revision DESC LIMIT 500");using var r=read.ExecuteReader();var result=new List<DecoyJobHistory>();while(r.Read())result.Add(new(r.GetString(0),r.GetString(1),r.GetString(2),JsonSerializer.Deserialize<ManagedDecoyJob>(r.GetString(3))!,r.IsDBNull(4)?null:r.GetString(4),r.IsDBNull(5)?null:r.GetString(5)));return result;
    }
    public void ReviewDecoy(ReviewDecoyJob body,string actor)
    {
        if(!DecoyJobsProtocol.Id(body.EndpointId)||!DecoyJobsProtocol.Id(body.JobId)||body.Reason is not {Length:>0 and <=512}||string.IsNullOrWhiteSpace(body.Reason)||body.Reason.Any(char.IsControl))throw new ArgumentException("Review reason required.");
        InitializeDecoyJobs();using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);LockDecoyEndpoint(c,t,body.EndpointId);
        using(var read=Command(c,t,"SELECT state,revision,observation FROM decoy_jobs WHERE id=$id AND endpoint=$endpoint",("$id",body.JobId),("$endpoint",body.EndpointId)))using(var r=read.ExecuteReader())
        {
            if(!r.Read()||r.GetInt64(1)!=body.PolicyRevision||r.IsDBNull(2)||DecoyJobsProtocol.Digest(JsonSerializer.Deserialize<DecoyNativeReport>(r.GetString(2))!)!=body.ObservationDigest)throw new DecoyJobConflictException();
            if(r.GetString(0)=="Reviewed")return;if(r.GetString(0)!="Needs review")throw new DecoyJobConflictException();
        }
        using(var update=Command(c,t,"UPDATE decoy_jobs SET state='Reviewed' WHERE id=$id",("$id",body.JobId)))update.ExecuteNonQuery();
        JobHistory(c,t,body.JobId,"Administrator review",actor,new{body.PolicyRevision,body.ObservationDigest,body.Reason});t.Commit();
    }
    public object[] DecoyJobEvents(string id)
    {
        if(!DecoyJobsProtocol.Id(id))throw new ArgumentException("Job identity required.");InitializeDecoyJobs();using var c=Open();using var read=Command(c,null,"SELECT sequence,kind,created,actor,payload FROM decoy_job_history WHERE id=$id ORDER BY sequence",("$id",id));using var r=read.ExecuteReader();var rows=new List<object>();while(r.Read())rows.Add(new{Sequence=r.GetInt64(0),Kind=r.GetString(1),CreatedUtc=DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(2)),Actor=r.GetString(3),Payload=r.GetString(4)});return rows.ToArray();
    }
}
public static class DecoyJobsApi
{
    public static void MapDecoyJobs(this WebApplication app,Func<HttpContext,string?> authenticate)
    {
        app.MapGet("/api/v1/console/decoy-jobs",(Store store)=>Results.Ok(store.DecoyJobsHistory())).RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        app.MapGet("/api/v1/console/decoy-jobs/{id}/history",(string id,Store store)=>DecoyJobsProtocol.Id(id)?Results.Ok(store.DecoyJobEvents(id)):Results.BadRequest()).RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        app.MapPost("/api/v1/console/decoy-jobs/review",async(HttpContext c,IAntiforgery csrf,ReviewDecoyJob body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try{store.ReviewDecoy(body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!);return Results.NoContent();}catch(ArgumentException){return Results.BadRequest();}catch(DecoyJobConflictException){return Results.Conflict();}catch(KeyNotFoundException){return Results.NotFound();}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/console/decoy-jobs",async(HttpContext c,IAntiforgery csrf,ApproveDecoyJob body,Store store,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await NotificationAuthorization.Check(c,csrf,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            try{return Results.Ok(store.ApproveDecoy(body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!));}catch(ArgumentException){return Results.BadRequest();}catch(DecoyJobConflictException){return Results.Conflict();}catch(KeyNotFoundException){return Results.NotFound();}
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/agent/decoy-jobs",(HttpContext c,Store store)=>authenticate(c) is {} endpoint?Results.Ok(store.PollDecoyJobs(endpoint)):Results.Unauthorized());
        app.MapPost("/api/v1/agent/decoy-jobs/receipt",(HttpContext c,Store store,DecoyJobReport body)=>
        {
            if(authenticate(c) is not {} endpoint)return Results.Unauthorized();
            try{return Results.Ok(store.ReceiveDecoyReport(endpoint,body));}catch(ArgumentException){return Results.BadRequest();}catch(DecoyJobConflictException){return Results.Conflict();}catch(KeyNotFoundException){return Results.NotFound();}
        });
        app.MapPost("/api/v1/agent/decoy-jobs/observation",(HttpContext c,Store store,DecoyNativeReport body)=>
        {
            if(authenticate(c) is not {} endpoint)return Results.Unauthorized();
            try{store.ReceiveDecoyObservation(endpoint,body);return Results.NoContent();}catch(ArgumentException){return Results.BadRequest();}catch(DecoyJobConflictException){return Results.Conflict();}catch(KeyNotFoundException){return Results.NotFound();}
        });
    }
}
