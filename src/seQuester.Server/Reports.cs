using System.Data.Common;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;

namespace RansomFree.Server;

public sealed record ExecutiveSnapshot(DateTimeOffset AsOfUtc,int Days,long Registered,long Revoked,long RecentContact,long StaleContact,long Events,long PreviousEvents,long ReportingEndpoints)
{
    public long? OpenIncidents {get;init;}
    public long? InvestigatingIncidents {get;init;}
    public long? ResolvedIncidents {get;init;}
    public long? CriticalUnresolvedIncidents {get;init;}
    public long? ServiceEvents {get;init;}
    public long? PreviousServiceEvents {get;init;}
    public long? ProtectionReportingClients {get;init;}
    public long? ProtectionActiveClients {get;init;}
    public long? ProtectionNeedsAttentionClients {get;init;}
    public long? DeployedCanaryAndHoneypotFiles {get;init;}
    public long? NonWhitelistedAlerts {get;init;}
    public long? PolicyUnknownAlerts {get;init;}
    public long? InformationalActivity {get;init;}
    public long TotalEvents=>Events+(ServiceEvents??0);
    public long TotalPreviousEvents=>PreviousEvents+(PreviousServiceEvents??0);
    public string Scope=>ServiceEvents==null?"Client reports received by this management server":"Client reports and service-decoy evidence received by this management server";
    public string ProtectionEvidence=>ProtectionReportingClients==null?"Client protection evidence was not captured in this historical snapshot.":$"{ProtectionReportingClients} clients reported protection state: {ProtectionActiveClients} active and {ProtectionNeedsAttentionClients} needing attention, with {DeployedCanaryAndHoneypotFiles} deployed canary and honeypot files reported.";
    public string Incidents=>OpenIncidents==null?"Incident counts were not captured in this historical snapshot.":$"Current incident inventory: {OpenIncidents} open, {InvestigatingIncidents} investigating, {ResolvedIncidents} resolved; {CriticalUnresolvedIncidents} critical unresolved. These are snapshot counts, not activity-window totals.";
}
public sealed record SavedReport(string Id,ExecutiveSnapshot Snapshot);
public sealed record ReportRequest(int Days);
public sealed record ExportRequest(string Format);
public sealed class ReportCapacityException : Exception;

public sealed partial class Store
{
    private ExecutiveSnapshot ReadSnapshot(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction t,int days)
    {
        if(days is <1 or >90)throw new ArgumentOutOfRangeException(nameof(days));
        var now=DateTimeOffset.UtcNow;var end=now.ToUnixTimeMilliseconds();var start=now.AddDays(-days).ToUnixTimeMilliseconds();var previous=now.AddDays(-2*days).ToUnixTimeMilliseconds();
        using var counts=Command(c,t,"SELECT COUNT(*),COALESCE(SUM(revoked),0),COALESCE(SUM(CASE WHEN revoked=0 AND last_seen>=$fresh THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN revoked=0 AND last_seen<$fresh THEN 1 ELSE 0 END),0) FROM endpoints",("$fresh",end-300000));
        long total,revoked,fresh,stale;
        using(var r=counts.ExecuteReader()){r.Read();total=r.GetInt64(0);revoked=r.GetInt64(1);fresh=r.GetInt64(2);stale=r.GetInt64(3);}
        using var activity=Command(c,t,"SELECT COALESCE(SUM(CASE WHEN received>=$start THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN received<$start THEN 1 ELSE 0 END),0),COUNT(DISTINCT CASE WHEN received>=$start THEN endpoint END) FROM events WHERE received>=$previous AND received<$end",("$start",start),("$previous",previous),("$end",end));
        using var a=activity.ExecuteReader();a.Read();
        var snapshot=new ExecutiveSnapshot(now,days,total,revoked,fresh,stale,a.GetInt64(0),a.GetInt64(1),a.GetInt64(2)){ServiceEvents=0,PreviousServiceEvents=0};a.Close();
        if(HasProtectionStorage())
        {
            using var protection=Command(c,t,"SELECT COUNT(*),COALESCE(SUM(CASE WHEN q.monitoring_state='active' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN q.monitoring_state!='active' THEN 1 ELSE 0 END),0),COALESCE(SUM(q.deployed_items),0) FROM endpoint_protection q JOIN endpoints e ON e.id=q.endpoint WHERE e.revoked=0");
            using var p=protection.ExecuteReader();p.Read();snapshot=snapshot with{ProtectionReportingClients=p.GetInt64(0),ProtectionActiveClients=p.GetInt64(1),ProtectionNeedsAttentionClients=p.GetInt64(2),DeployedCanaryAndHoneypotFiles=p.GetInt64(3)};
        }
        else snapshot=snapshot with{ProtectionReportingClients=0,ProtectionActiveClients=0,ProtectionNeedsAttentionClients=0,DeployedCanaryAndHoneypotFiles=0};
        long alerts=0,unknown=0,informational=0;
        using(var evidence=Command(c,t,"SELECT sequence,endpoint,received,payload FROM events WHERE received>=$start AND received<$end",("$start",start),("$end",end)))
        using(var events=evidence.ExecuteReader())while(events.Read())
        {
            var item=JsonSerializer.Deserialize<RansomFree.Contracts.AgentEvent>(events.GetString(3));
            var classification=item==null?TrustEventClassification.PolicyUnknown:ClassifyTrust(new(events.GetInt64(0),events.GetString(1),DateTimeOffset.FromUnixTimeMilliseconds(events.GetInt64(2)),item));
            if(classification is TrustEventClassification.Informational or TrustEventClassification.LogOnly)informational++;
            else if(classification==TrustEventClassification.NonWhitelisted)alerts++;
            else unknown++;
        }
        snapshot=snapshot with{NonWhitelistedAlerts=alerts,PolicyUnknownAlerts=unknown,InformationalActivity=informational};
        using(var exists=Command(c,t,c is Microsoft.Data.Sqlite.SqliteConnection?"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='service_evidence'":"SELECT CASE WHEN OBJECT_ID(N'dbo.service_evidence',N'U') IS NULL THEN 0 ELSE 1 END"))
        if(Convert.ToInt64(exists.ExecuteScalar())==1)
        {
            using var service=Command(c,t,"SELECT COALESCE(SUM(CASE WHEN received>=$start THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN received<$start THEN 1 ELSE 0 END),0) FROM service_evidence WHERE received>=$previous AND received<$end",("$start",start),("$previous",previous),("$end",end));
            using var countsReader=service.ExecuteReader();countsReader.Read();snapshot=snapshot with{ServiceEvents=countsReader.GetInt64(0),PreviousServiceEvents=countsReader.GetInt64(1)};
        }
        using var incidents=Command(c,t,"SELECT COALESCE(SUM(CASE WHEN status='Open' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status='Investigating' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status='Resolved' THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status!='Resolved' AND severity='Critical' THEN 1 ELSE 0 END),0) FROM incidents");
        using var cases=incidents.ExecuteReader();cases.Read();return snapshot with{OpenIncidents=cases.GetInt64(0),InvestigatingIncidents=cases.GetInt64(1),ResolvedIncidents=cases.GetInt64(2),CriticalUnresolvedIncidents=cases.GetInt64(3)};
    }
    public ExecutiveSnapshot Snapshot(int days)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);var snapshot=ReadSnapshot(c,t,days);t.Commit();return snapshot;
    }
    public SavedReport CreateReport(int days,string owner)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);
        var report=CreateReportCore(c,t,days,owner);t.Commit();return report;
    }
    private SavedReport CreateReportCore(System.Data.Common.DbConnection c,System.Data.Common.DbTransaction t,int days,string owner)
    {
        using(var count=Command(c,t,"SELECT COUNT(*) FROM reports"))if(Convert.ToInt64(count.ExecuteScalar())>=5000)throw new ReportCapacityException();
        var report=new SavedReport(Guid.NewGuid().ToString("N"),ReadSnapshot(c,t,days));
        using(var cmd=Command(c,t,"INSERT INTO reports(id,owner,created,payload) VALUES($id,$owner,$time,$payload)",("$id",report.Id),("$owner",owner),("$time",report.Snapshot.AsOfUtc.ToUnixTimeMilliseconds()),("$payload",JsonSerializer.Serialize(report))))cmd.ExecuteNonQuery();
        Audit(c,t,"Executive report created",owner+":"+report.Id);return report;
    }
    public SavedReport? ReadReport(string id,string owner,bool administrator)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT payload FROM reports WHERE id=$id AND (owner=$owner OR $admin=1)",("$id",id),("$owner",owner),("$admin",administrator?1:0));
        return cmd.ExecuteScalar() is string json?JsonSerializer.Deserialize<SavedReport>(json):null;
    }
    public IReadOnlyList<SavedReport> ListReports(string owner)
    {
        using var c=Open();using var cmd=Command(c,null,"SELECT payload FROM reports WHERE owner=$owner ORDER BY created DESC,id DESC LIMIT 100",("$owner",owner));
        using var reader=cmd.ExecuteReader();var reports=new List<SavedReport>();
        while(reader.Read())reports.Add(JsonSerializer.Deserialize<SavedReport>(reader.GetString(0))!);
        return reports;
    }
    public void RecordExport(string id,string actor,string format)
    {
        using var c=Open();using var t=c.BeginTransaction(System.Data.IsolationLevel.Serializable);Audit(c,t,"Report export generated: "+format,actor+":"+id);t.Commit();
    }
}

internal sealed class ReportFonts : IFontResolver
{
    public FontResolverInfo ResolveTypeface(string familyName,bool bold,bool italic)=>new(bold?"VeraBd":"Vera");
    public byte[] GetFont(string faceName)
    {
        using var stream=typeof(ReportFonts).Assembly.GetManifestResourceStream("RansomFree.Server.Fonts."+faceName+".ttf")??throw new InvalidOperationException("Report font missing.");
        using var bytes=new MemoryStream();stream.CopyTo(bytes);return bytes.ToArray();
    }
}
public static class ReportRenderer
{
    internal static readonly object Gate=new();
    public static string Text(SavedReport r)
    {
        var s=r.Snapshot;
        return string.Join('\n',new[]{"seQuester | Quiver | EXECUTIVE SUMMARY","CONFIDENTIAL - INTERNAL",$"Report ID: {r.Id}",$"Snapshot: {s.AsOfUtc:yyyy-MM-dd HH:mm:ss} UTC",$"Scope: {s.Scope}",$"Activity window: {s.AsOfUtc.AddDays(-s.Days):yyyy-MM-dd HH:mm:ss} UTC to {s.AsOfUtc:yyyy-MM-dd HH:mm:ss} UTC (end exclusive)","","CLIENT-REPORTED PROTECTION",s.ProtectionEvidence,$"Non-whitelisted alerts: {s.NonWhitelistedAlerts?.ToString()??"Not captured"}",$"Policy unknown / legacy alerts: {s.PolicyUnknownAlerts?.ToString()??"Not captured"}",$"Whitelisted informational activity: {s.InformationalActivity?.ToString()??"Not captured"}","","CONTACT AND ACTIVITY",$"Clients reporting events in window: {s.ReportingEndpoints}",$"Events received in window: {s.TotalEvents}",$"Events received in preceding equal window: {s.TotalPreviousEvents}",$"Contact within 5 minutes (enrolled, non-revoked): {s.RecentContact}",$"Stale contact (enrolled, non-revoked): {s.StaleContact}","","INCIDENT INVENTORY",s.Incidents,"","DEFINITIONS","Protection state and deployed item totals come only from client reports. Missing reports remain Not reported; no expected client count, denominator, or inventory prerequisite is used.","A server-validated informational policy decision is retained as lower-level activity and is not counted as an alert. Missing, legacy, or invalid policy evidence remains visible and is counted separately.","Activity uses server receive time for the report window; event details retain client-observed time. Event volume is not incident severity or risk reduction.","A read may be copying or scanning. A file change alone does not prove ransomware.","No endpoint credentials or callback URLs are included.","Development report: not a compliance attestation or proof of protection.",""});
    }
    public static byte[] Pdf(SavedReport r)
    {
        lock(Gate)
        {
            GlobalFontSettings.FontResolver??=new ReportFonts();
            using var document=new PdfDocument();document.Info.Title="seQuester - Executive Summary";document.Info.Author="Quiver";
            var page=document.AddPage();page.Size=PdfSharp.PageSize.A4;
            using var g=XGraphics.FromPdfPage(page);
            var regular=new XFont("Report",10);var small=new XFont("Report",8);var bold=new XFont("Report",10,XFontStyleEx.Bold);var title=new XFont("Report",25,XFontStyleEx.Bold);
            var navy=new XSolidBrush(XColor.FromArgb(17,38,60));var muted=new XSolidBrush(XColor.FromArgb(77,96,115));var teal=new XSolidBrush(XColor.FromArgb(8,127,120));
            double width=page.Width.Point,left=44,body=width-88,y=46;
            void Draw(string text,XFont font,XBrush brush,double x,double top)=>g.DrawString(text,font,brush,new XPoint(x,top+font.Size));
            void Line(string text,XFont? font=null,XBrush? brush=null){Draw(text,font??regular,brush??navy,left,y);y+=17;}
            void Wrap(string text)
            {
                var line="";foreach(var word in text.Split(' ')){var next=line.Length==0?word:line+" "+word;if(g.MeasureString(next,regular).Width>body){Line(line);line=word;}else line=next;}if(line.Length>0)Line(line);
            }
            Draw("seQuester | Quiver",bold,teal,left,y);Draw("CONFIDENTIAL - INTERNAL",small,muted,width-187,y);y+=28;
            Line("Executive summary",title);y+=24;
            Line($"Snapshot {r.Snapshot.AsOfUtc:yyyy-MM-dd HH:mm:ss} UTC",regular,muted);
            Line($"Window: {r.Snapshot.Days} {(r.Snapshot.Days==1?"day":"days")} | Scope: {(r.Snapshot.ServiceEvents==null?"Endpoints":"Endpoints and service decoys")}",regular,muted);y+=16;
            g.DrawLine(new XPen(XColor.FromArgb(210,221,230)),left,y,width-left,y);y+=18;
            Line("Client-reported protection",bold);y+=8;
            var s=r.Snapshot;
            var metrics=new[]{("Reporting clients",s.ProtectionReportingClients),("Monitoring active",s.ProtectionActiveClients),("Needs attention",s.ProtectionNeedsAttentionClients),("Bait files",s.DeployedCanaryAndHoneypotFiles)};
            double tile=(body-24)/4;
            for(int i=0;i<4;i++)
            {
                var x=left+i*(tile+8);g.DrawRectangle(new XSolidBrush(XColor.FromArgb(240,245,249)),x,y,tile,68);Draw(metrics[i].Item1,small,muted,x+10,y+9);
                var number=metrics[i].Item2?.ToString(CultureInfo.InvariantCulture)??"Not captured";var size=25;var numberFont=title;
                while(g.MeasureString(number,numberFont).Width>tile-20 && size>8)numberFont=new XFont("Report",--size,XFontStyleEx.Bold);
                Draw(number,numberFont,navy,x+10,y+27);
            }y+=82;
            Wrap(s.ProtectionReportingClients==null?"This historical snapshot did not capture structured client protection reports.":"Values come only from clients that reported structured protection state. Missing reports are not treated as zero or healthy.");y+=12;
            Line("Alert activity",bold);y+=5;
            Line($"Non-whitelisted alerts: {s.NonWhitelistedAlerts?.ToString("N0")??"Not captured"}");
            Line($"Policy unknown / legacy alerts: {s.PolicyUnknownAlerts?.ToString("N0")??"Not captured"}");
            Line($"Whitelisted informational activity: {s.InformationalActivity?.ToString("N0")??"Not captured"}");
            Line($"Current {s.Days}-day window: {s.TotalEvents:N0} events");
            Line($"Previous {s.Days}-day window: {s.TotalPreviousEvents:N0} events");
            Line($"Endpoints reporting events in the current window: {s.ReportingEndpoints:N0}");y+=10;
            Wrap("Activity is measured by server receive time. A volume change does not establish an increase or decrease in risk.");y+=12;
            Line("Incident inventory",bold);y+=5;
            Wrap(s.Incidents);y+=10;
            Line("Interpretation",bold);y+=5;
            Wrap("Protection is derived only from client reports. Missing client protection reports remain Not reported and inventory totals never change health or alert state.");
            Wrap("A file read may be copying or scanning. A changed file does not prove ransomware. Event details retain host, bait path, actor, process/PID, activity and client-observed time.");
            Wrap("Development report - not a compliance attestation or proof of protection.");
            if(y>page.Height.Point-78)return PaginatedReport.Pdf("Executive summary",Text(r).Split('\n'));
            g.DrawLine(new XPen(XColor.FromArgb(210,221,230)),left,page.Height.Point-60,width-left,page.Height.Point-60);
            Draw("Report "+r.Id,small,muted,left,page.Height.Point-47);Draw("1 / 1",small,muted,width-70,page.Height.Point-47);
            using var output=new MemoryStream();document.Save(output,false);return output.ToArray();
        }
    }
    public static void MapReports(this WebApplication app)
    {
        var routes=app.MapGroup("/api/v1/console").RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
        routes.MapGet("/overview",(Store store,int days=7)=>days is <1 or >90?Results.BadRequest():Results.Ok(store.Snapshot(days)));
        routes.MapGet("/reports",(HttpContext c,Store store)=>Results.Ok(store.ListReports(c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)));
        routes.MapPost("/reports",async(HttpContext c,IAntiforgery csrf,ReportRequest request,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(request.Days is <1 or >90)return Results.BadRequest();
            try{return Results.Ok(store.CreateReport(request.Days,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!));}
            catch(ReportCapacityException){return Results.Problem(statusCode:409,title:"Report storage is full",detail:"Contact your administrator. Existing reports have been preserved.");}
        });
        routes.MapPost("/reports/{id}/export",async(HttpContext c,IAntiforgery csrf,string id,ExportRequest request,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(!Guid.TryParseExact(id,"N",out _) || request.Format is not ("txt" or "pdf"))return Results.BadRequest();
            var actor=c.User.FindFirstValue(ClaimTypes.NameIdentifier)!;var report=store.ReadReport(id,actor,c.User.IsInRole("Administrator"));if(report is null)return Results.NotFound();
            var bytes=request.Format=="pdf"?Pdf(report):Encoding.UTF8.GetBytes(Text(report));store.RecordExport(id,actor,request.Format);
            return Results.File(bytes,request.Format=="pdf"?"application/pdf":"text/plain; charset=utf-8",$"ransom-free-summary-{report.Snapshot.AsOfUtc:yyyyMMdd}-{id[..8]}.{request.Format}");
        });
    }
}
