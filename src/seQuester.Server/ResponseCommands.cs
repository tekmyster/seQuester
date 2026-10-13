using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;
using RansomFree.Contracts;

namespace RansomFree.Server;

public sealed record CreateResponseBody(string RequestId,long EventSequence,string Reason,string AdministratorPassword,string? Code=null,string? RecoveryCode=null);
public sealed partial class Store
{
    public ResponseCommand? CreateResponse(CreateResponseBody body,string actor)
    {
        InitializeResponseCapabilities();
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);string endpoint;AgentEvent evidence;
        using(var cmd=Command(c,t,"SELECT e.endpoint,e.payload FROM events e JOIN endpoints p ON p.id=e.endpoint WHERE e.sequence=$sequence AND p.revoked=0",("$sequence",body.EventSequence)))
        using(var r=cmd.ExecuteReader()){if(!r.Read())return null;endpoint=r.GetString(0);evidence=JsonSerializer.Deserialize<AgentEvent>(r.GetString(1))!;}
        if(evidence.Source is not ("Windows minifilter" or "Windows audit 4663" or "Linux fanotify" or "macOS Endpoint Security") || evidence.ProcessId is null or <=4 || evidence.ObservedUtc<DateTimeOffset.UtcNow.AddMinutes(-5) || evidence.ObservedUtc>DateTimeOffset.UtcNow.AddMinutes(1))return null;
        using(var existing=Command(c,t,"SELECT payload,endpoint FROM response_commands WHERE id=$id",("$id",body.RequestId)))
        using(var r=existing.ExecuteReader())if(r.Read())
        {
            var prior=JsonSerializer.Deserialize<ResponseCommand>(r.GetString(0))!;
            return r.GetString(1)==endpoint && prior.EventId==evidence.EventId && prior.RequestedBy==actor && prior.Reason==body.Reason.Trim()?prior:null;
        }
        using(var count=Command(c,t,"SELECT COUNT(*) FROM response_commands WHERE endpoint=$endpoint AND status IN ('Pending','Offered') AND expires>$now",("$endpoint",endpoint),("$now",Now())))if(Convert.ToInt64(count.ExecuteScalar())>=20)return null;
        var now=DateTimeOffset.UtcNow;var command=new ResponseCommand(body.RequestId,evidence.EventId,"end-process",actor,body.Reason.Trim(),now,now.AddMinutes(2));
        if(evidence.Source=="Windows minifilter")
        {
            var assigned=ReadAssigned(c,t,endpoint);var options=assigned.Settings.ActiveResponse;
            if(options?.Mode!="manual"||!options.Actions.Contains("end-process"))return null;
            using(var support=Command(c,t,"SELECT COUNT(*) FROM response_capabilities WHERE endpoint=$id AND os='windows' AND process_version=1 AND reported>$fresh AND reported<=$now",("$id",endpoint),("$fresh",now.AddSeconds(-120).ToUnixTimeMilliseconds()),("$now",now.ToUnixTimeMilliseconds())))if(Convert.ToInt64(support.ExecuteScalar())!=1)return null;
            using(var rate=Command(c,t,"SELECT COUNT(*) FROM response_commands WHERE endpoint=$id AND expires>$recent",("$id",endpoint),("$recent",now.AddMinutes(1).ToUnixTimeMilliseconds())))if(Convert.ToInt64(rate.ExecuteScalar())>=options.MaximumActionsPerMinute)return null;
            var preview=PreviewActiveResponse(new(body.EventSequence,["end-process"],options.AccountPrincipal));
            if(preview?.Eligible!=true||preview.Target?.SensorId!=endpoint||preview.Target.EventId!=evidence.EventId)return null;
            command=command with{Target=preview.Target,PolicyRevision=assigned.Revision,PolicyDigest=ResponseCommandPolicy.Digest(assigned)};
        }
        using(var insert=Command(c,t,"INSERT INTO response_commands(id,endpoint,payload,status,expires) VALUES($id,$endpoint,$payload,'Pending',$expires)",("$id",command.Id),("$endpoint",endpoint),("$payload",JsonSerializer.Serialize(command)),("$expires",command.ExpiresUtc.ToUnixTimeMilliseconds())))insert.ExecuteNonQuery();
        Audit(c,t,"Remote process response requested",actor+":"+endpoint+":"+command.Id);t.Commit();return command;
    }
    public IReadOnlyList<ResponseCommand> PollResponses(string endpoint)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var commands=new List<ResponseCommand>();
        using(var cmd=Command(c,t,"SELECT c.payload FROM response_commands c JOIN endpoints e ON e.id=c.endpoint WHERE c.endpoint=$endpoint AND e.revoked=0 AND c.status IN ('Pending','Offered') AND c.expires>$now ORDER BY c.expires,c.id LIMIT 10",("$endpoint",endpoint),("$now",Now())))using(var r=cmd.ExecuteReader())while(r.Read())commands.Add(JsonSerializer.Deserialize<ResponseCommand>(r.GetString(0))!);
        foreach(var command in commands){using var offered=Command(c,t,"UPDATE response_commands SET status='Offered' WHERE id=$id AND status='Pending'",("$id",command.Id));offered.ExecuteNonQuery();}
        t.Commit();return commands;
    }
    public bool ReceiveResponse(string endpoint,ResponseReceipt receipt)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var current=Command(c,t,"SELECT c.status,c.result FROM response_commands c JOIN endpoints e ON e.id=c.endpoint WHERE c.id=$id AND c.endpoint=$endpoint AND e.revoked=0",("$id",receipt.Id),("$endpoint",endpoint)))
        using(var r=current.ExecuteReader())
        {if(!r.Read())return false;if(r.GetString(0)!="Offered")return r.GetString(0)==receipt.Outcome && !r.IsDBNull(1) && r.GetString(1)==receipt.Message;}
        using(var update=Command(c,t,"UPDATE response_commands SET status=$outcome,result=$result,reported=$now WHERE id=$id",("$outcome",receipt.Outcome),("$result",receipt.Message),("$now",Now()),("$id",receipt.Id)))update.ExecuteNonQuery();
        Audit(c,t,"Endpoint reported response: "+receipt.Outcome,endpoint+":"+receipt.Id);t.Commit();return true;
    }
    public IReadOnlyList<ResponseCommandStatus> ResponseStatuses()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT endpoint,payload,CASE WHEN status IN ('Pending','Offered') AND expires<$now THEN 'Expired / no final receipt' ELSE status END,result,reported FROM response_commands ORDER BY expires DESC,id LIMIT 100",("$now",Now()));using var r=cmd.ExecuteReader();var list=new List<ResponseCommandStatus>();
        while(r.Read())list.Add(new(r.GetString(0),JsonSerializer.Deserialize<ResponseCommand>(r.GetString(1))!,r.GetString(2),r.IsDBNull(3)?null:r.GetString(3),r.IsDBNull(4)?null:DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(4))));return list;
    }
    public bool CancelResponse(string id,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);using var cmd=Command(c,t,"UPDATE response_commands SET status='Cancelled' WHERE id=$id AND status='Pending'",("$id",id));
        if(cmd.ExecuteNonQuery()!=1)return false;Audit(c,t,"Pending response cancelled",actor+":"+id);t.Commit();return true;
    }
}
public static partial class HumanIdentity
{
    public static void MapResponseCommands(this WebApplication app,Func<HttpContext,string?> authenticate)
    {
        app.MapPost("/api/v1/agent/response-capabilities",(HttpContext c,NativeResponseCapabilities report,Store store)=>
        {
            if(authenticate(c) is not {} endpoint)return Results.Unauthorized();
            if(!report.IsValid())return Results.BadRequest();
            return store.RecordResponseCapabilities(endpoint,report)?Results.NoContent():Results.Unauthorized();
        });
        app.MapGet("/api/v1/console/responses",(Store store)=>Results.Ok(store.ResponseStatuses())).RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        app.MapPost("/api/v1/console/responses",async(HttpContext c,IAntiforgery csrf,CreateResponseBody body,UserManager<LocalUser> users,SignInManager<LocalUser> signIn,AuthDb db,Store store)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(body.RequestId,"N",out _) || body.EventSequence<1 || string.IsNullOrWhiteSpace(body.Reason) || body.Reason.Length>500 || body.Reason.Any(char.IsControl))return Results.BadRequest();
            if(!await ReauthenticateAdministrator(c,body.AdministratorPassword,body.Code,body.RecoveryCode,users,signIn,db) || !await StillAdministrator(c,db))return Results.Unauthorized();
            var command=store.CreateResponse(body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!);return command==null?Results.Conflict(new{error="Fresh actionable evidence, available capacity and an active endpoint are required."}):Results.Ok(command);
        }).RequireAuthorization(p=>p.RequireRole("Administrator")).RequireRateLimiting("identity");
        app.MapPost("/api/v1/console/responses/{id}/cancel",async(string id,HttpContext c,IAntiforgery csrf,Store store)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(id,"N",out _))return Results.BadRequest();return store.CancelResponse(id,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict(new{error="Only commands not yet offered to an agent can be cancelled."});
        }).RequireAuthorization(p=>p.RequireRole("Administrator"));
        app.MapPost("/api/v1/agent/responses",(HttpContext c,Store store)=>authenticate(c) is {} endpoint?Results.Ok(store.PollResponses(endpoint)):Results.Unauthorized());
        app.MapPost("/api/v1/agent/responses/receipt",(HttpContext c,ResponseReceipt body,Store store)=>
        {
            var endpoint=authenticate(c);if(endpoint==null)return Results.Unauthorized();
            if(!Guid.TryParseExact(body.Id,"N",out _) || body.Outcome is not ("Succeeded" or "Failed" or "Rejected" or "Indeterminate") || body.Message==null || body.Message.Length>512 || body.Message.Any(char.IsControl))return Results.BadRequest();
            return store.ReceiveResponse(endpoint,body)?Results.NoContent():Results.Conflict();
        });
    }
}
