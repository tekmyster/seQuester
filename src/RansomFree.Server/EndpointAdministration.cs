using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;

namespace RansomFree.Server;

public sealed record CancelEnrollmentBody(string Code);
public sealed record ManagementAuditEntry(long Sequence,DateTimeOffset TimeUtc,string Action,string Subject);

public static class EndpointAdministration
{
    public static void MapEndpointAdministration(this WebApplication app)
    {
        var routes=app.MapGroup("/api/v1/console").RequireAuthorization(p=>p.RequireRole("Administrator"));
        routes.MapGet("/management-audit",(Store store)=>Results.Ok(store.ManagementAudit()));
        routes.MapPost("/endpoints/{id}/revoke",async(HttpContext c,IAntiforgery csrf,string id,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(!Guid.TryParseExact(id,"N",out _))return Results.BadRequest();
            return store.Revoke(id,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!)?Results.NoContent():Results.NotFound();
        });
        routes.MapPost("/enrollment-codes/cancel",async(HttpContext c,IAntiforgery csrf,CancelEnrollmentBody body,Store store)=>
        {
            try{await csrf.ValidateRequestAsync(c);}catch(AntiforgeryValidationException){return Results.BadRequest();}
            if(body.Code is null || body.Code.Length!=64 || !body.Code.All(Uri.IsHexDigit))return Results.BadRequest();
            store.CancelEnrollmentCode(body.Code,c.User.FindFirstValue(ClaimTypes.NameIdentifier)!);
            return Results.NoContent();
        });
    }
}
