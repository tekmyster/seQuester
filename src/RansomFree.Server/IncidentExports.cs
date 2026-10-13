using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using PdfSharp.Drawing;
using PdfSharp.Fonts;
using PdfSharp.Pdf;

namespace RansomFree.Server;

public static class IncidentExports
{
    public static void MapIncidentExports(this WebApplication app)
    {
        app.MapPost("/api/v1/console/incidents/{id}/export",async(string id,ExportRequest body,HttpContext c,IAntiforgery csrf,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(!Guid.TryParseExact(id,"N",out _) || body.Format is not ("txt" or "pdf"))return Results.BadRequest();
            var detail=store.IncidentDetails(id);if(detail==null)return Results.NotFound();var incident=detail.Incident;
            var lines=new List<string>{"seQuester | Quiver | INCIDENT REPORT","CONFIDENTIAL - INTERNAL",$"Exported: {DateTimeOffset.UtcNow:O}",$"Case: {incident.Id}",$"Revision: {incident.Version}",$"Title: {incident.Title}",$"Severity: {incident.Severity}",$"Status: {incident.Status}",$"Created: {incident.CreatedUtc:O}",$"Updated: {incident.UpdatedUtc:O}","","LINKED EVIDENCE","Event sequence references are retained; an event alone is not proof of ransomware."};
            lines.Insert(9,"Assigned actor ID: "+(incident.AssignedTo??"Unassigned"));
            lines.AddRange(detail.EventSequences.Select(x=>x<0?"Service event "+x.ToString(System.Globalization.CultureInfo.InvariantCulture)[1..]:"Event "+x.ToString(System.Globalization.CultureInfo.InvariantCulture)));lines.Add("");lines.Add("ACTIVITY NOTES (latest 100, newest first)");
            foreach(var note in detail.Notes){lines.Add($"{note.TimeUtc:O} | Actor ID: {note.Actor}");lines.Add(note.Note);lines.Add("");}
            lines.Add("This report includes operator-entered content and internal identifiers. Handle under your organization's incident-data policy.");
            var text=string.Join('\n',lines);var bytes=body.Format=="txt"?Encoding.UTF8.GetBytes(text):PaginatedReport.Pdf("Incident report",lines);
            store.CallbackAudit("Incident report exported: "+body.Format,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!,id);
            return Results.File(bytes,body.Format=="txt"?"text/plain; charset=utf-8":"application/pdf",$"ransom-free-incident-{id}.{body.Format}");
        }).RequireAuthorization(p=>p.RequireRole("Administrator","Operator","Reader"));
    }
}

internal static class PaginatedReport
{
    public static byte[] Pdf(string title,IEnumerable<string> paragraphs)
    {
        lock(ReportRenderer.Gate)
        {
            GlobalFontSettings.FontResolver??=new ReportFonts();using var document=new PdfDocument();document.Info.Title="seQuester - "+title;
            var font=new XFont("Report",10);var heading=new XFont("Report",17,XFontStyleEx.Bold);var footer=new XFont("Report",8);
            PdfPage? page=null;XGraphics? graphics=null;double y=0,width=0;
            void NewPage(){graphics?.Dispose();page=document.AddPage();page.Size=PdfSharp.PageSize.A4;graphics=XGraphics.FromPdfPage(page);width=page.Width.Point-88;graphics.DrawString(title,heading,XBrushes.DarkSlateGray,new XPoint(44,52));y=78;}
            void Draw(string line){if(page==null || y>page.Height.Point-72)NewPage();graphics!.DrawString(line,font,XBrushes.Black,new XPoint(44,y));y+=15;}
            try
            {
                NewPage();
                foreach(var paragraph in paragraphs)
                foreach(var raw in paragraph.Replace("\r","").Split('\n'))
                {
                    var text=new string(raw.Select(c=>char.IsControl(c)?' ':c).ToArray());if(text.Length==0){Draw("");continue;}
                    var line="";
                    foreach(var character in text)
                    {
                        if(graphics!.MeasureString(line+character,font).Width>width)
                        {
                            var split=line.LastIndexOf(' ');
                            if(split>0){Draw(line[..split]);line=line[(split+1)..];}
                            else{Draw(line);line="";} // Long identifiers still wrap within the page.
                        }
                        line+=character;
                    }
                    if(line.Length>0)Draw(line);
                }
            }
            finally{graphics?.Dispose();}
            for(var i=0;i<document.PageCount;i++)
            {
                using var g=XGraphics.FromPdfPage(document.Pages[i],XGraphicsPdfPageOptions.Append);var p=document.Pages[i];
                g.DrawLine(XPens.LightGray,44,p.Height.Point-50,p.Width.Point-44,p.Height.Point-50);
                g.DrawString("CONFIDENTIAL - INTERNAL | Development report",footer,XBrushes.Gray,new XPoint(44,p.Height.Point-34));
                g.DrawString($"{i+1} / {document.PageCount}",footer,XBrushes.Gray,new XPoint(p.Width.Point-80,p.Height.Point-34));
            }
            using var output=new MemoryStream();document.Save(output,false);return output.ToArray();
        }
    }
}
