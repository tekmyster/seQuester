using System.Data.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace RansomFree.Server;

public sealed record ReportSchedule(string Id,string Owner,string Name,int Days,int EveryHours,DateTimeOffset NextUtc,bool Enabled,long Version,string? LastReport,string? LastError);
public sealed record ReportScheduleBody(string Name,int Days,int EveryHours,bool Enabled,long ExpectedVersion=0);
public sealed partial class Store
{
    private static ReportSchedule ReadSchedule(DbDataReader r)=>new(r.GetString(0),r.GetString(1),r.GetString(2),r.GetInt32(3),r.GetInt32(4),DateTimeOffset.FromUnixTimeMilliseconds(r.GetInt64(5)),Convert.ToBoolean(r.GetValue(6)),r.GetInt64(7),r.IsDBNull(8)?null:r.GetString(8),r.IsDBNull(9)?null:r.GetString(9));
    public IReadOnlyList<ReportSchedule> Schedules(string owner)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT id,owner,name,days,hours,next,enabled,version,last_report,last_error FROM report_schedules WHERE owner=$owner ORDER BY name,id",("$owner",owner));using var r=cmd.ExecuteReader();var list=new List<ReportSchedule>();while(r.Read())list.Add(ReadSchedule(r));return list;
    }
    public string? SaveSchedule(string? id,string owner,ReportScheduleBody body)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var next=DateTimeOffset.UtcNow.AddHours(body.EveryHours).ToUnixTimeMilliseconds();
        if(id==null)
        {
            using(var count=Command(c,t,"SELECT COUNT(*) FROM report_schedules WHERE owner=$owner",("$owner",owner)))if(Convert.ToInt64(count.ExecuteScalar())>=10)return null;
            using(var count=Command(c,t,"SELECT COUNT(*) FROM report_schedules"))if(Convert.ToInt64(count.ExecuteScalar())>=200)return null;
            id=Guid.NewGuid().ToString("N");
            using var insert=Command(c,t,"INSERT INTO report_schedules(id,owner,name,days,hours,next,enabled,version) VALUES($id,$owner,$name,$days,$hours,$next,$enabled,1)",("$id",id),("$owner",owner),("$name",body.Name.Trim()),("$days",body.Days),("$hours",body.EveryHours),("$next",next),("$enabled",body.Enabled?1:0));insert.ExecuteNonQuery();
        }
        else
        {
            using var update=Command(c,t,"UPDATE report_schedules SET name=$name,days=$days,hours=$hours,next=$next,enabled=$enabled,version=version+1,last_error=NULL WHERE id=$id AND owner=$owner AND version=$version",("$name",body.Name.Trim()),("$days",body.Days),("$hours",body.EveryHours),("$next",next),("$enabled",body.Enabled?1:0),("$id",id),("$owner",owner),("$version",body.ExpectedVersion));if(update.ExecuteNonQuery()!=1)return null;
        }
        Audit(c,t,"Report schedule saved",owner+":"+id);t.Commit();return id;
    }
    public IReadOnlyList<ReportSchedule> DueSchedules()
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT id,owner,name,days,hours,next,enabled,version,last_report,last_error FROM report_schedules WHERE enabled=1 AND next<=$now ORDER BY next,id LIMIT 5",("$now",Now()));using var r=cmd.ExecuteReader();var list=new List<ReportSchedule>();while(r.Read())list.Add(ReadSchedule(r));return list;
    }
    public void PauseSchedule(ReportSchedule schedule,string reason)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);using var cmd=Command(c,t,"UPDATE report_schedules SET enabled=0,last_error=$error,version=version+1 WHERE id=$id AND version=$version",("$error",reason),("$id",schedule.Id),("$version",schedule.Version));if(cmd.ExecuteNonQuery()==1)Audit(c,t,"Report schedule paused: "+reason,schedule.Id);t.Commit();
    }
    public bool RunSchedule(ReportSchedule schedule)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        using(var current=Command(c,t,"SELECT COUNT(*) FROM report_schedules WHERE id=$id AND version=$version AND enabled=1 AND next<=$now",("$id",schedule.Id),("$version",schedule.Version),("$now",Now())))if(Convert.ToInt64(current.ExecuteScalar())!=1)return false;
        var report=CreateReportCore(c,t,schedule.Days,schedule.Owner);
        using(var update=Command(c,t,"UPDATE report_schedules SET next=$next,last_report=$report,last_error=NULL WHERE id=$id",("$next",DateTimeOffset.UtcNow.AddHours(schedule.EveryHours).ToUnixTimeMilliseconds()),("$report",report.Id),("$id",schedule.Id)))update.ExecuteNonQuery();
        Audit(c,t,"Scheduled report created",schedule.Id+":"+report.Id);t.Commit();return true;
    }
}
internal sealed class ReportScheduler(Store store,IServiceScopeFactory scopes,ILogger<ReportScheduler> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromMinutes(1));
        try
        {
            do
            {
                try
                {
                    foreach(var schedule in store.DueSchedules())
                    {
                        ct.ThrowIfCancellationRequested();using var scope=scopes.CreateScope();var db=scope.ServiceProvider.GetRequiredService<AuthDb>();
                        var enabled=await db.Users.AnyAsync(u=>u.Id==schedule.Owner && !db.AccountControls.Any(c=>c.UserId==u.Id&&c.Disabled),ct);
                        var role=await (from link in db.UserRoles join r in db.Roles on link.RoleId equals r.Id where link.UserId==schedule.Owner && (r.Name=="Administrator"||r.Name=="Operator"||r.Name=="Reader") select link).AnyAsync(ct);
                        if(!enabled || !role){store.PauseSchedule(schedule,"Owner access is unavailable");continue;}
                        var directory=scope.ServiceProvider.GetRequiredService<DirectorySessionValidator>();
                        if(directory.Enabled && await db.DirectoryIdentities.AsNoTracking().SingleOrDefaultAsync(x=>x.UserId==schedule.Owner,ct) is {} identity)
                        {
                            var state=await directory.ValidateAsync(identity,ct);
                            var assigned=await (from link in db.UserRoles join r in db.Roles on link.RoleId equals r.Id where link.UserId==schedule.Owner select r.Name).ToListAsync(ct);
                            if(!state.Active || directory.RoleRestrictions&&!assigned.Any(r=>r!=null&&state.AllowedRoles.Contains(r,StringComparer.Ordinal)))
                            {store.PauseSchedule(schedule,"Owner directory access is unavailable");continue;}
                        }
                        try{store.RunSchedule(schedule);}catch(ReportCapacityException){store.PauseSchedule(schedule,"Report capacity reached");}
                    }
                }
                catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
                catch(Exception ex){logger.LogWarning("Scheduled reporting failed ({Type}); no successful run is claimed.",ex.GetType().Name);}
            }while(await timer.WaitForNextTickAsync(ct));
        }
        catch(OperationCanceledException) when(ct.IsCancellationRequested){}
    }
}
public static class ReportSchedules
{
    public static void MapReportSchedules(this WebApplication app)
    {
        var routes=app.MapGroup("/api/v1/console/report-schedules").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        routes.MapGet("",(HttpContext c,Store store)=>Results.Ok(store.Schedules(c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)));
        static bool Valid(ReportScheduleBody body)=>!string.IsNullOrWhiteSpace(body.Name)&&body.Name.Length<=100&&!body.Name.Any(char.IsControl)&&body.Days is >=1 and <=90&&body.EveryHours is >=1 and <=168&&body.ExpectedVersion>=0;
        async Task<bool> Csrf(HttpContext c,IAntiforgery csrf){try{await csrf.ValidateRequestAsync(c);return true;}catch(AntiforgeryValidationException){return false;}}
        routes.MapPost("",async(HttpContext c,IAntiforgery csrf,ReportScheduleBody body,Store store)=>
        {
            if(!await Csrf(c,csrf)||!Valid(body)||body.ExpectedVersion!=0)return Results.BadRequest();var id=store.SaveSchedule(null,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,body);return id==null?Results.Conflict():Results.Ok(new{id});
        });
        routes.MapPost("/{id}",async(string id,HttpContext c,IAntiforgery csrf,ReportScheduleBody body,Store store)=>
        {
            if(!await Csrf(c,csrf)||!Valid(body)||!Guid.TryParseExact(id,"N",out _))return Results.BadRequest();return store.SaveSchedule(id,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,body)==null?Results.Conflict():Results.NoContent();
        });
    }
}
