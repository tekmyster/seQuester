using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed record AssignIncidentBody(long ExpectedVersion,string? AssignedTo,string Note);
public sealed partial class Store
{
    public bool AssignIncident(string id,AssignIncidentBody body,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var update=Command(c,t,"UPDATE incidents SET version=version+1,updated=$now WHERE id=$id AND version=$version",("$now",Now()),("$id",id),("$version",body.ExpectedVersion)))if(update.ExecuteNonQuery()!=1)return false;
        using(var assign=Command(c,t,"UPDATE incident_assignments SET owner=$owner WHERE incident=$id",("$id",id),("$owner",(object?)body.AssignedTo??DBNull.Value)))
            if(assign.ExecuteNonQuery()==0){using var insert=Command(c,t,"INSERT INTO incident_assignments(incident,owner) VALUES($id,$owner)",("$id",id),("$owner",(object?)body.AssignedTo??DBNull.Value));insert.ExecuteNonQuery();}
        using(var note=Command(c,t,"INSERT INTO incident_notes(incident,time,actor,note) VALUES($id,$now,$actor,$note)",("$id",id),("$now",Now()),("$actor",actor),("$note","Assigned to: "+(body.AssignedTo??"Unassigned")+"\n"+body.Note.Trim())))note.ExecuteNonQuery();
        Audit(c,t,"Incident assignment changed",actor+":"+id+":"+(body.AssignedTo??"unassigned"));t.Commit();return true;
    }
}
public static class IncidentAssignment
{
    public static void MapIncidentAssignment(this WebApplication app)
    {
        var read=app.MapGroup("/api/v1/console/incidents").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("/assignees",async(AuthDb db)=>Results.Ok(await (from user in db.Users join link in db.UserRoles on user.Id equals link.UserId join role in db.Roles on link.RoleId equals role.Id where (role.Name=="Administrator" || role.Name=="Operator") && !db.AccountControls.Any(c=>c.UserId==user.Id && c.Disabled) select new{user.Id,user.UserName}).Distinct().OrderBy(x=>x.UserName).Take(500).ToListAsync()));
        app.MapPost("/api/v1/console/incidents/{id}/assignment",async(string id,AssignIncidentBody body,HttpContext c,IAntiforgery csrf,AuthDb db,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(!Guid.TryParseExact(id,"N",out _) || body.ExpectedVersion<1 || body.AssignedTo?.Length>256 || string.IsNullOrWhiteSpace(body.Note) || body.Note.Length>500 || body.Note.Any(char.IsControl))return Results.BadRequest();
            if(body.AssignedTo!=null && !await (from link in db.UserRoles join role in db.Roles on link.RoleId equals role.Id where link.UserId==body.AssignedTo && (role.Name=="Administrator" || role.Name=="Operator") && !db.AccountControls.Any(x=>x.UserId==body.AssignedTo && x.Disabled) select link).AnyAsync())return Results.BadRequest();
            return store.AssignIncident(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict();
        }).RequireAuthorization(p=>p.RequireRole("Administrator","Operator"));
    }
}
