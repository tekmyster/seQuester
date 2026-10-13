using System.Data.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Data.Sqlite;

namespace RansomFree.Server;

public sealed record Incident(string Id,string Title,string Severity,string Status,long Version,DateTimeOffset CreatedUtc,DateTimeOffset UpdatedUtc,string CreatedBy)
{
    public string? AssignedTo {get;init;}
}
public sealed record IncidentNote(long Sequence,DateTimeOffset TimeUtc,string Actor,string Note);
public sealed record IncidentDetail(Incident Incident,IReadOnlyList<long> EventSequences,IReadOnlyList<IncidentNote> Notes)
{
    public IReadOnlyList<string> EventSequenceTexts=>EventSequences.Select(value=>value.ToString(System.Globalization.CultureInfo.InvariantCulture)).ToArray();
}
public sealed record IncidentSummary(long Open,long Investigating,long Resolved,long CriticalActive,DateTimeOffset AsOfUtc);
public sealed record CreateIncidentBody(string Title,string Severity,long EventSequence);
public sealed record UpdateIncidentBody(long ExpectedVersion,string Status,string Severity,string Note);
public sealed record LinkIncidentBody(long ExpectedVersion,long EventSequence);
public sealed partial class Store
{
    public IncidentSummary IncidentCounts()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT COALESCE(SUM(CASE WHEN status='Open' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status='Investigating' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status='Resolved' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status!='Resolved' AND severity='Critical' THEN 1 ELSE 0 END),0) FROM incidents");
        using var r=cmd.ExecuteReader();r.Read();return new(r.GetInt64(0),r.GetInt64(1),r.GetInt64(2),r.GetInt64(3),DateTimeOffset.UtcNow);
    }
    private static Incident ReadIncident(DbDataReader r)=>new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetString(3),r.GetInt64(4),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(5)),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(6)),r.GetString(7)){AssignedTo=r.FieldCount>8&&!r.IsDBNull(8)?r.GetString(8):null};
    public IReadOnlyList<Incident> Incidents(string? status)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT id,title,severity,status,version,created,updated,creator,(SELECT owner FROM incident_assignments WHERE incident=incidents.id) FROM incidents WHERE ($status='' OR status=$status) ORDER BY updated DESC,id LIMIT 100",("$status",status??""));
        using var r=cmd.ExecuteReader();var result=new List<Incident>();while(r.Read())result.Add(ReadIncident(r));return result;
    }
    public Incident? CreateIncident(CreateIncidentBody body,string actor)
    {
        if(!PrepareIncidentEvidence(body.EventSequence))return null;var evidenceTable=body.EventSequence<0?"service_evidence":"events";var linkTable=body.EventSequence<0?"incident_service_events":"incident_events";var number=Math.Abs(body.EventSequence);
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var exists=Command(c,t,$"SELECT COUNT(*) FROM {evidenceTable} WHERE sequence=$event",("$event",number)))if(Convert.ToInt64(exists.ExecuteScalar())!=1)return null;
        var id=Guid.NewGuid().ToString("N");var now=Now();
        using(var add=Command(c,t,"INSERT INTO incidents VALUES($id,$title,$severity,'Open',1,$now,$now,$actor)",("$id",id),("$title",body.Title.Trim()),("$severity",body.Severity),("$now",now),("$actor",actor)))add.ExecuteNonQuery();
        using(var link=Command(c,t,$"INSERT INTO {linkTable} VALUES($id,$event)",("$id",id),("$event",number)))link.ExecuteNonQuery();
        Audit(c,t,"Incident created",actor+":"+id);t.Commit();return new(id,body.Title.Trim(),body.Severity,"Open",1,DateTimeOffset.FromUnixTimeMilliseconds(now),DateTimeOffset.FromUnixTimeMilliseconds(now),actor);
    }
    public IncidentDetail? IncidentDetails(string id)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);Incident incident;
        using(var cmd=Command(c,t,"SELECT id,title,severity,status,version,created,updated,creator,(SELECT owner FROM incident_assignments WHERE incident=incidents.id) FROM incidents WHERE id=$id",("$id",id)))
        using(var r=cmd.ExecuteReader()){if(!r.Read())return null;incident=ReadIncident(r);}
        var events=new List<long>();var notes=new List<IncidentNote>();
        using(var cmd=Command(c,t,"SELECT event_sequence FROM incident_events WHERE incident=$id ORDER BY event_sequence LIMIT 1000",("$id",id)))using(var r=cmd.ExecuteReader())while(r.Read())events.Add(r.GetInt64(0));
        if(HasServiceIncidentLinks()&&events.Count<1000){using var serviceLinks=Command(c,t,"SELECT event_sequence FROM incident_service_events WHERE incident=$id ORDER BY event_sequence LIMIT $limit",("$id",id),("$limit",1000-events.Count));using var services=serviceLinks.ExecuteReader();while(services.Read())events.Add(-services.GetInt64(0));}
        using(var cmd=Command(c,t,"SELECT sequence,time,actor,note FROM incident_notes WHERE incident=$id ORDER BY sequence DESC LIMIT 100",("$id",id)))using(var r=cmd.ExecuteReader())while(r.Read())notes.Add(new(r.GetInt64(0),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(1)),r.GetString(2),r.GetString(3)));
        t.Commit();return new(incident,events,notes);
    }
    public bool UpdateIncident(string id,UpdateIncidentBody body,string actor)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var update=Command(c,t,"UPDATE incidents SET status=$status,severity=$severity,version=version+1,updated=$now WHERE id=$id AND version=$version",("$status",body.Status),("$severity",body.Severity),("$now",Now()),("$id",id),("$version",body.ExpectedVersion)))if(update.ExecuteNonQuery()!=1)return false;
        using(var note=Command(c,t,"INSERT INTO incident_notes(incident,time,actor,note) VALUES($id,$now,$actor,$note)",("$id",id),("$now",Now()),("$actor",actor),("$note",$"Status: {body.Status}; severity: {body.Severity}\n{body.Note.Trim()}")))note.ExecuteNonQuery();
        Audit(c,t,"Incident updated: "+body.Status+" / "+body.Severity,actor+":"+id);t.Commit();return true;
    }
    public bool LinkIncidentEvent(string id,LinkIncidentBody body,string actor)
    {
        if(!PrepareIncidentEvidence(body.EventSequence))return false;var evidenceTable=body.EventSequence<0?"service_evidence":"events";var linkTable=body.EventSequence<0?"incident_service_events":"incident_events";var number=Math.Abs(body.EventSequence);var hasServices=HasServiceIncidentLinks();
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var count=Command(c,t,(hasServices?"SELECT (SELECT COUNT(*) FROM incident_events WHERE incident=$id)+(SELECT COUNT(*) FROM incident_service_events WHERE incident=$id)":"SELECT COUNT(*) FROM incident_events WHERE incident=$id"),("$id",id)))if(Convert.ToInt64(count.ExecuteScalar())>=1000)return false;
        using(var exists=Command(c,t,$"SELECT COUNT(*) FROM {evidenceTable} WHERE sequence=$event",("$event",number)))if(Convert.ToInt64(exists.ExecuteScalar())!=1)return false;
        using(var update=Command(c,t,"UPDATE incidents SET version=version+1,updated=$now WHERE id=$id AND version=$version",("$now",Now()),("$id",id),("$version",body.ExpectedVersion)))if(update.ExecuteNonQuery()!=1)return false;
        using(var link=Command(c,t,$"INSERT INTO {linkTable}(incident,event_sequence) SELECT $id,$event WHERE NOT EXISTS(SELECT 1 FROM {linkTable} WHERE incident=$id AND event_sequence=$event)",("$id",id),("$event",number)))if(link.ExecuteNonQuery()!=1)return false;
        Audit(c,t,"Incident evidence linked",actor+":"+id+":"+body.EventSequence);t.Commit();return true;
    }
}
public static class IncidentRoutes
{
    private static bool Severity(string s)=>s is "Low" or "Medium" or "High" or "Critical";
    private static bool Status(string? s)=>s is "Open" or "Investigating" or "Resolved";
    public static void MapIncidents(this WebApplication app)
    {
        var read=app.MapGroup("/api/v1/console/incidents").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        read.MapGet("/summary",(Store s)=>Results.Ok(s.IncidentCounts()));
        read.MapGet("",(Store s,string? status=null)=>status!=null && !Status(status)?Results.BadRequest():Results.Ok(s.Incidents(status)));
        read.MapGet("/{id}",(string id,Store s)=>!Guid.TryParseExact(id,"N",out _)?Results.BadRequest():s.IncidentDetails(id) is { } detail?Results.Ok(detail):Results.NotFound());
        var write=app.MapGroup("/api/v1/console/incidents").RequireAuthorization(p=>p.RequireRole("Administrator","Operator"));
        async Task<bool> Csrf(HttpContext c,IAntiforgery csrf){try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}}
        write.MapPost("",async(HttpContext c,IAntiforgery csrf,CreateIncidentBody body,Store s)=>
        {
            if(!await Csrf(c,csrf) || string.IsNullOrWhiteSpace(body.Title) || body.Title.Length>200 || body.Title.Any(char.IsControl) || !Severity(body.Severity) || body.EventSequence is 0 or long.MinValue)return Results.BadRequest();
            var incident=s.CreateIncident(body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!);return incident==null?Results.NotFound():Results.Ok(incident);
        });
        write.MapPost("/{id}",async(HttpContext c,IAntiforgery csrf,string id,UpdateIncidentBody body,Store s)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(id,"N",out _) || body.ExpectedVersion<1 || !Status(body.Status) || !Severity(body.Severity) || string.IsNullOrWhiteSpace(body.Note) || body.Note.Length>4000 || body.Note.Any(ch=>char.IsControl(ch) && ch is not ('\r' or '\n' or '\t')))return Results.BadRequest();
            return s.UpdateIncident(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict();
        });
        write.MapPost("/{id}/events",async(HttpContext c,IAntiforgery csrf,string id,LinkIncidentBody body,Store s)=>
        {
            if(!await Csrf(c,csrf) || !Guid.TryParseExact(id,"N",out _) || body.ExpectedVersion<1 || body.EventSequence is 0 or long.MinValue)return Results.BadRequest();
            return s.LinkIncidentEvent(id,body,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.Conflict();
        });
    }
}
