using System.Data.Common;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Data.Sqlite;
using Microsoft.AspNetCore.Identity;
using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed record CreateGroupBody(string Name);
public sealed record PublishPolicyBody(long ExpectedRevision,MonitoringPolicy Settings,string? AdministratorPassword=null,string? Code=null,string? RecoveryCode=null);
public sealed record AssignGroupBody(string? GroupId,string? ExpectedGroupId);
public sealed record PolicyRevision(long Revision,DateTimeOffset CreatedUtc,string Actor,MonitoringPolicy Settings);
public sealed class GroupCapacityException : Exception;
public sealed partial class Store
{
    public EndpointGroup CreateGroup(string name,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var count=Command(c,t,"SELECT COUNT(*) FROM endpoint_groups"))if(Convert.ToInt64(count.ExecuteScalar())>=1000)throw new GroupCapacityException();
        var id=Guid.NewGuid().ToString("N");var payload=JsonSerializer.Serialize(MonitoringPolicy.Default);
        using(var add=Command(c,t,"INSERT INTO endpoint_groups VALUES($id,$name,0,$payload)",("$id",id),("$name",name),("$payload",payload)))add.ExecuteNonQuery();
        Audit(c,t,"Endpoint group created",actor+":"+id);t.Commit();return new(id,name,0,MonitoringPolicy.Default,0);
    }
    public IReadOnlyList<EndpointGroup> Groups()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT g.id,g.name,g.revision,g.payload,(SELECT COUNT(*) FROM endpoint_groups_binding b JOIN endpoints e ON e.id=b.endpoint WHERE b.group_id=g.id AND e.revoked=0) FROM endpoint_groups g ORDER BY g.name");
        using var r=cmd.ExecuteReader();var result=new List<EndpointGroup>();while(r.Read())result.Add(new(r.GetString(0),r.GetString(1),r.GetInt64(2),JsonSerializer.Deserialize<MonitoringPolicy>(r.GetString(3))!,r.GetInt64(4)));return result;
    }
    public bool PublishPolicy(string group,PublishPolicyBody body,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var current=Command(c,t,"SELECT revision FROM endpoint_groups WHERE id=$id",("$id",group)))
            if(current.ExecuteScalar() is not long revision || revision!=body.ExpectedRevision)return false;
        var payload=JsonSerializer.Serialize(body.Settings);
        using var add=Command(c,t,"INSERT INTO policy_revisions(group_id,created,actor,payload) VALUES($id,$now,$actor,$payload) RETURNING revision",("$id",group),("$now",Now()),("$actor",actor),("$payload",payload));
        var next=(long)add.ExecuteScalar()!;
        using(var update=Command(c,t,"UPDATE endpoint_groups SET revision=$revision,payload=$payload WHERE id=$id",("$revision",next),("$payload",payload),("$id",group)))update.ExecuteNonQuery();
        Audit(c,t,"Monitoring policy published",actor+":"+group+":"+next);t.Commit();return true;
    }
    public IReadOnlyList<PolicyRevision> PolicyHistory(string group)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT revision,created,actor,payload FROM policy_revisions WHERE group_id=$id ORDER BY revision DESC LIMIT 100",("$id",group));
        using var r=cmd.ExecuteReader();var result=new List<PolicyRevision>();while(r.Read())result.Add(new(r.GetInt64(0),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(1)),r.GetString(2),JsonSerializer.Deserialize<MonitoringPolicy>(r.GetString(3))!));return result;
    }
    public bool AssignGroup(string endpoint,AssignGroupBody body,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var active=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))if(Convert.ToInt64(active.ExecuteScalar())!=1)return false;
        if(body.GroupId!=null){using var group=Command(c,t,"SELECT COUNT(*) FROM endpoint_groups WHERE id=$id",("$id",body.GroupId));if(Convert.ToInt64(group.ExecuteScalar())!=1)return false;}
        using(var current=Command(c,t,"SELECT group_id FROM endpoint_groups_binding WHERE endpoint=$id",("$id",endpoint)))if((current.ExecuteScalar() as string)!=body.ExpectedGroupId)return false;
        using(var bind=Command(c,t,"UPDATE endpoint_groups_binding SET group_id=$group,applied_revision=NULL,reported=NULL WHERE endpoint=$id",("$id",endpoint),("$group",(object?)body.GroupId??DBNull.Value)))
            if(bind.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO endpoint_groups_binding(endpoint,group_id) VALUES($id,$group)",("$id",endpoint),("$group",(object?)body.GroupId??DBNull.Value));insert.ExecuteNonQuery();}
        Audit(c,t,"Endpoint group assigned",actor+":"+endpoint+":"+(body.GroupId??"unassigned"));t.Commit();return true;
    }
    private static AssignedPolicy ReadAssigned(DbConnection c,DbTransaction? t,string endpoint)
    {
        using var cmd=Command(c,t,"SELECT g.id,g.revision,g.payload FROM endpoint_groups_binding b JOIN endpoint_groups g ON g.id=b.group_id WHERE b.endpoint=$id",("$id",endpoint));using var r=cmd.ExecuteReader();
        return r.Read()?new(r.GetString(0),r.GetInt64(1),JsonSerializer.Deserialize<MonitoringPolicy>(r.GetString(2))!):new(null,0,MonitoringPolicy.Default);
    }
    public AssignedPolicy Assigned(string endpoint){using var c=Open();return ReadAssigned(c,null,endpoint);}
    public bool AcknowledgePolicy(string endpoint,PolicyReceipt receipt)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var active=Command(c,t,"SELECT COUNT(*) FROM endpoints WHERE id=$id AND revoked=0",("$id",endpoint)))if(Convert.ToInt64(active.ExecuteScalar())!=1)return false;
        var desired=ReadAssigned(c,t,endpoint);if(desired.GroupId!=receipt.GroupId || desired.Revision!=receipt.Revision)return false;
        if(desired.Settings.Forensics!=null&&receipt.ForensicsVersion!=1)return false;
        if(desired.Settings.AutomaticResponse.Enabled || desired.Settings.ActiveResponse is {Mode:not "observe"} || desired.Settings.Deployments.Length>0 || desired.Settings.Syslog!=null || desired.Settings.Allowlist.Length>0)
        {
            using var version=Command(c,t,"SELECT version FROM endpoints WHERE id=$id",("$id",endpoint));
            if(version.ExecuteScalar() is not string reported || !Version.TryParse(reported.Split('-')[0],out var parsed) || parsed<new Version(0,6,0))return false;
        }
        using(var cmd=Command(c,t,"UPDATE endpoint_groups_binding SET applied_revision=$revision,reported=$now WHERE endpoint=$id",("$id",endpoint),("$revision",receipt.Revision),("$now",Now())))
            if(cmd.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO endpoint_groups_binding(endpoint,group_id,applied_revision,reported) VALUES($id,$group,$revision,$now)",("$id",endpoint),("$group",(object?)receipt.GroupId??DBNull.Value),("$revision",receipt.Revision),("$now",Now()));insert.ExecuteNonQuery();}
        t.Commit();return true;
    }
    public IReadOnlyList<EndpointPolicyStatus> PolicyStatuses()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT e.id,b.group_id,COALESCE(g.revision,0),b.applied_revision,b.reported FROM endpoints e LEFT JOIN endpoint_groups_binding b ON b.endpoint=e.id LEFT JOIN endpoint_groups g ON g.id=b.group_id WHERE e.revoked=0 ORDER BY e.last_seen DESC,e.id LIMIT 1000");
        using var r=cmd.ExecuteReader();var result=new List<EndpointPolicyStatus>();while(r.Read())result.Add(new(r.GetString(0),r.IsDBNull(1)?null:r.GetString(1),r.GetInt64(2),r.IsDBNull(3)?null:r.GetInt64(3),r.IsDBNull(4)?null:DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(4))));return result;
    }
}
public static class Policies
{
    public static void MapPolicies(this WebApplication app,Func<HttpContext,string?> authenticate)
    {
        var read=app.MapGroup("/api/v1/console").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("/groups",(Store s)=>Results.Ok(s.Groups()));read.MapGet("/policy-status",(Store s)=>Results.Ok(s.PolicyStatuses()));
        read.MapGet("/groups/{id}/history",(string id,Store s)=>Guid.TryParseExact(id,"N",out _)?Results.Ok(s.PolicyHistory(id)):Results.BadRequest());
        var write=app.MapGroup("/api/v1/console").RequireAuthorization(p=>p.RequireRole("Administrator"));
        async Task<bool> Csrf(HttpContext c,IAntiforgery csrf){try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}}
        write.MapPost("/groups",async(HttpContext c,IAntiforgery csrf,CreateGroupBody body,Store s)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.Name) || body.Name.Length>100 || body.Name.Any(char.IsControl))return Results.BadRequest();
            try{return Results.Ok(s.CreateGroup(body.Name.Trim(),c.User.FindFirstValue(ClaimTypes.NameIdentifier)!));}
            catch(Exception ex) when(RansomFree.Persistence.Relational.UniqueViolation(ex)){return Results.Conflict(new {error="Group name already exists."});}
            catch(GroupCapacityException){return Results.Conflict(new {error="Group capacity reached. Existing groups are preserved."});}
        });
        write.MapPost("/groups/{id}/policy",async(HttpContext c,IAntiforgery csrf,string id,PublishPolicyBody body,Store s,CallbackConfiguration callbacks,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(id,"N",out _) || body.ExpectedRevision<0 || body.Settings is null || !body.Settings.IsValid())return Results.BadRequest();
            if((body.Settings.AutomaticResponse.Enabled||body.Settings.ActiveResponse is {Mode:not "observe"}) && !await HumanIdentity.ReauthenticateAdministrator(c,body.AdministratorPassword??"",body.Code,body.RecoveryCode,users,signIn,db))return Results.Unauthorized();
            var current=s.Groups().SingleOrDefault(g=>g.Id==id);if(current==null || current.Revision!=body.ExpectedRevision)return Results.Conflict();
            var resolved=new List<CanaryDeployment>();
            foreach(var deployment in body.Settings.Deployments)
            {
                var existing=current.Settings.Deployments.SingleOrDefault(x=>x.Id==deployment.Id);
                if(existing!=null)
                {
                    if((existing with{CallbackUrl=null})!=(deployment with{CallbackUrl=null}))return Results.BadRequest(new{error="Deployment IDs are immutable. Remove the old plan entry and create a new one for changed content or location."});
                    resolved.Add(existing);continue;
                }
                if(deployment.CallbackTokenId==null){if(deployment.CallbackUrl!=null)return Results.BadRequest();resolved.Add(deployment);continue;}
                if(callbacks.Storage?.Get(deployment.CallbackTokenId) is not {Revoked:false} token || token.Type!=deployment.FileType)return Results.BadRequest();
                resolved.Add(deployment with{CallbackUrl=callbacks.Url(token)});
            }
            body=body with{Settings=body.Settings with{Deployments=resolved.ToArray()}};
            return s.PublishPolicy(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict();
        });
        write.MapPost("/endpoints/{id}/group",async(HttpContext c,IAntiforgery csrf,string id,AssignGroupBody body,Store s)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(id,"N",out _) || body.GroupId!=null && !Guid.TryParseExact(body.GroupId,"N",out _) || body.ExpectedGroupId!=null && !Guid.TryParseExact(body.ExpectedGroupId,"N",out _))return Results.BadRequest();
            return s.AssignGroup(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict();
        });
        app.MapPost("/api/v1/agent/policy",(HttpContext c,Store s)=>authenticate(c) is { } id?Results.Ok(s.Assigned(id)):Results.Unauthorized());
        app.MapPost("/api/v1/agent/policy/receipt",(HttpContext c,PolicyReceipt receipt,Store s)=>authenticate(c) is { } id?s.AcknowledgePolicy(id,receipt)?Results.NoContent():Results.Conflict():Results.Unauthorized());
    }
}
